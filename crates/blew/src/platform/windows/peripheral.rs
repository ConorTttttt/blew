//! Windows peripheral role: Stage 4a — register GATT services and advertise them.
//!
//! Deliberately limited to empty services or static, read-only characteristics.
//! Dynamic GATT requests, notify/indicate, secondary services and custom local
//! names need separate implementations; we reject them rather than silently
//! publishing incorrect semantics. Not ready for Iroh traffic yet.

use crate::error::{BlewError, BlewResult};
use crate::gatt::props::{AttributePermissions, CharacteristicProperties};
use crate::gatt::service::GattService;
use crate::l2cap::{L2capChannel, types::Psm};
use crate::peripheral::backend::{self, PeripheralBackend};
use crate::peripheral::types::{
    AdvertisingConfig, Delivery, LocalName, PeripheralConfig, PeripheralRequest,
    PeripheralStateEvent,
};
use crate::platform::windows::{get_adapter, peripheral_error, radio_powered};
use crate::types::DeviceId;
use crate::util::BroadcastEventStream;
use parking_lot::Mutex;
use std::collections::HashSet;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristicParameters, GattProtectionLevel,
    GattServiceProvider, GattServiceProviderAdvertisingParameters,
};
use windows::Devices::Bluetooth::{BluetoothAdapter, BluetoothError};
use windows::Storage::Streams::DataWriter;
use windows::core::GUID;

/// Advertisements are owned by their providers; retaining them is required to
/// keep services available to other devices.
struct Published {
    providers: Vec<GattServiceProvider>,
}

impl Published {
    fn stop(&mut self) {
        for provider in &self.providers {
            let _ = provider.StopAdvertising();
        }
        self.providers.clear();
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default)]
struct ServerState {
    pending: Vec<GattService>,
    published: Option<Published>,
}

pub struct WindowsPeripheral {
    adapter: BluetoothAdapter,
    events: broadcast::Sender<PeripheralStateEvent>,
    _request_tx: mpsc::UnboundedSender<PeripheralRequest>,
    requests: Mutex<Option<mpsc::UnboundedReceiver<PeripheralRequest>>>,
    // Keep the lock across WinRT service creation: two concurrent calls to
    // start_advertising cannot both publish the same services.
    state: tokio::sync::Mutex<ServerState>,
}

impl WindowsPeripheral {
    pub async fn with_config(_config: PeripheralConfig) -> BlewResult<Self> {
        <Self as PeripheralBackend>::new().await
    }
}

fn unsupported(message: impl Into<String>) -> BlewError {
    BlewError::Internal(format!("Windows GATT server Stage 4a: {}", message.into()))
}

/// Stage 4a refuses unsupported semantics rather than advertising something
/// that cannot honor read/write/notify requests.
fn validate_service(service: &GattService) -> BlewResult<()> {
    if !service.primary {
        return Err(BlewError::NotSupported);
    }
    let mut seen = HashSet::new();
    for characteristic in &service.characteristics {
        if !seen.insert(characteristic.uuid) {
            return Err(unsupported(format!(
                "duplicate characteristic UUID {} in service {}",
                characteristic.uuid, service.uuid
            )));
        }
        if !characteristic.descriptors.is_empty() {
            return Err(BlewError::NotSupported);
        }
        // Only static read-only characteristics work at this stage. Reject all
        // features that would otherwise need a GATT callback or subscriber map.
        if !characteristic.properties.is_empty()
            && characteristic.properties != CharacteristicProperties::READ
        {
            return Err(BlewError::NotSupported);
        }
        if characteristic.permissions.intersects(
            AttributePermissions::WRITE
                | AttributePermissions::WRITE_ENCRYPTED
                | AttributePermissions::WRITE_AUTHENTICATED,
        ) {
            return Err(BlewError::NotSupported);
        }
    }
    Ok(())
}

fn read_protection(perms: AttributePermissions) -> GattProtectionLevel {
    if perms.contains(AttributePermissions::READ_AUTHENTICATED) {
        GattProtectionLevel::EncryptionAndAuthenticationRequired
    } else if perms.contains(AttributePermissions::READ_ENCRYPTED) {
        GattProtectionLevel::EncryptionRequired
    } else {
        GattProtectionLevel::Plain
    }
}

async fn build_provider(service: &GattService) -> BlewResult<GattServiceProvider> {
    let result = GattServiceProvider::CreateAsync(GUID::from_u128(service.uuid.as_u128()))
        .map_err(peripheral_error)?
        .await
        .map_err(peripheral_error)?;
    let error = result.Error().map_err(peripheral_error)?;
    if error != BluetoothError::Success {
        return Err(unsupported(format!(
            "creating GATT service {} failed: {error:?}",
            service.uuid
        )));
    }
    let provider = result.ServiceProvider().map_err(peripheral_error)?;
    let local_service = provider.Service().map_err(peripheral_error)?;

    for characteristic in &service.characteristics {
        let params = GattLocalCharacteristicParameters::new().map_err(peripheral_error)?;
        params
            .SetCharacteristicProperties(GattCharacteristicProperties(
                characteristic.properties.bits() as u32,
            ))
            .map_err(peripheral_error)?;
        params
            .SetReadProtectionLevel(read_protection(characteristic.permissions))
            .map_err(peripheral_error)?;
        if characteristic
            .properties
            .contains(CharacteristicProperties::READ)
        {
            let writer = DataWriter::new().map_err(peripheral_error)?;
            writer
                .WriteBytes(&characteristic.value)
                .map_err(peripheral_error)?;
            let buffer = writer.DetachBuffer().map_err(peripheral_error)?;
            params.SetStaticValue(&buffer).map_err(peripheral_error)?;
        }
        // Make sure WinRT-only objects used for static values do not remain
        // alive across `.await` (the async trait requires Send futures).
        let operation = local_service
            .CreateCharacteristicAsync(GUID::from_u128(characteristic.uuid.as_u128()), &params)
            .map_err(peripheral_error)?;
        let result = operation.await.map_err(peripheral_error)?;
        let error = result.Error().map_err(peripheral_error)?;
        if error != BluetoothError::Success {
            return Err(unsupported(format!(
                "creating characteristic {} failed: {error:?}",
                characteristic.uuid
            )));
        }
        let _local_characteristic = result.Characteristic().map_err(peripheral_error)?;
    }
    Ok(provider)
}

impl backend::private::Sealed for WindowsPeripheral {}

impl PeripheralBackend for WindowsPeripheral {
    type StateEvents = BroadcastEventStream<PeripheralStateEvent>;
    type Requests = UnboundedReceiverStream<PeripheralRequest>;

    async fn new() -> BlewResult<Self> {
        let adapter = get_adapter().await?;
        if !adapter
            .IsPeripheralRoleSupported()
            .map_err(peripheral_error)?
        {
            return Err(BlewError::NotSupported);
        }
        let (events, _) = broadcast::channel(128);
        let (tx, rx) = mpsc::unbounded_channel();
        Ok(Self {
            adapter,
            events,
            _request_tx: tx,
            requests: Mutex::new(Some(rx)),
            state: tokio::sync::Mutex::new(ServerState::default()),
        })
    }

    async fn is_powered(&self) -> BlewResult<bool> {
        radio_powered(&self.adapter).await
    }

    async fn add_service(&self, service: &GattService) -> BlewResult<()> {
        validate_service(service)?;
        let mut state = self.state.lock().await;
        if state.published.is_some() {
            return Err(unsupported(
                "stop advertising before adding another service",
            ));
        }
        if state
            .pending
            .iter()
            .any(|existing| existing.uuid == service.uuid)
        {
            return Err(unsupported(format!(
                "service {} is already registered",
                service.uuid
            )));
        }
        state.pending.push(service.clone());
        Ok(())
    }

    async fn start_advertising(&self, config: &AdvertisingConfig) -> BlewResult<()> {
        if !self.is_powered().await? {
            return Err(BlewError::NotPowered);
        }
        // Windows GattServiceProvider cannot set a per-advertisement local name.
        if config.local_name != LocalName::None {
            return Err(BlewError::LocalNameUnsupported {
                reason: "Windows GattServiceProvider uses the system Bluetooth device name",
            });
        }
        let mut state = self.state.lock().await;
        if state.published.is_some() {
            return Err(BlewError::AlreadyAdvertising);
        }
        if state.pending.is_empty() {
            return Err(unsupported("add_service must be called before advertising"));
        }
        // GattServiceProvider only advertises UUIDs for services actually
        // registered. Reject extra requested UUIDs rather than dropping them.
        if config
            .service_uuids
            .iter()
            .any(|uuid| !state.pending.iter().any(|service| service.uuid == *uuid))
        {
            return Err(BlewError::NotSupported);
        }
        let mut published = Published {
            providers: Vec::new(),
        };
        for service in &state.pending {
            published.providers.push(build_provider(service).await?);
        }
        // Start only after all service providers and characteristics exist.
        for provider in &published.providers {
            let parameters =
                GattServiceProviderAdvertisingParameters::new().map_err(peripheral_error)?;
            parameters
                .SetIsConnectable(true)
                .map_err(peripheral_error)?;
            parameters
                .SetIsDiscoverable(true)
                .map_err(peripheral_error)?;
            provider
                .StartAdvertisingWithParameters(&parameters)
                .map_err(peripheral_error)?;
        }
        // StartAdvertisingWithParameters queues a request to Windows. It does
        // not prove the advertisement is on air; hardware testing and status
        // monitoring are still required.
        state.published = Some(published);
        Ok(())
    }

    async fn stop_advertising(&self) -> BlewResult<()> {
        if let Some(mut published) = self.state.lock().await.published.take() {
            published.stop();
        }
        Ok(())
    }

    async fn notify_characteristic(
        &self,
        _device_id: &DeviceId,
        _char_uuid: Uuid,
        _value: Vec<u8>,
    ) -> BlewResult<Delivery> {
        Err(BlewError::NotSupported)
    }

    async fn l2cap_listener(
        &self,
    ) -> BlewResult<(
        Psm,
        tokio_stream::Empty<BlewResult<(DeviceId, L2capChannel)>>,
    )> {
        Err(BlewError::NotSupported)
    }

    fn state_events(&self) -> Self::StateEvents {
        BroadcastEventStream::new(self.events.subscribe())
    }

    fn take_requests(&self) -> Option<Self::Requests> {
        self.requests
            .lock()
            .take()
            .map(UnboundedReceiverStream::new)
    }
}
