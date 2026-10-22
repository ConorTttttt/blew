//! Windows peripheral role: Stage 4b — WinRT GATT server read and write callbacks.
//!
//! Static characteristics remain supported; empty readable values are handled
//! dynamically via PeripheralRequest::Read. Writes flow through the existing
//! responder-based PeripheralRequest::Write API, with a bounded ATT response.
//! Secondary services, notifications/indications, descriptors, and custom local
//! advertisement names are not yet supported. Not ready for Iroh traffic yet.

use crate::error::{BlewError, BlewResult};
use crate::gatt::props::{AttributePermissions, CharacteristicProperties};
use crate::gatt::service::GattService;
use crate::l2cap::{L2capChannel, types::Psm};
use crate::peripheral::backend::{self, PeripheralBackend};
use crate::peripheral::types::{
    AdvertisingConfig, Delivery, LocalName, PeripheralConfig, PeripheralRequest,
    PeripheralStateEvent, ReadResponder, WriteResponder,
};
use crate::platform::windows::{get_adapter, peripheral_error, radio_powered};
use crate::types::DeviceId;
use crate::util::BroadcastEventStream;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattReadRequest, GattReadRequestedEventArgs, GattServiceProvider,
    GattServiceProviderAdvertisingParameters, GattWriteOption, GattWriteRequest,
    GattWriteRequestedEventArgs,
};
use windows::Devices::Bluetooth::{BluetoothAdapter, BluetoothError};
use windows::Foundation::{Deferral, TypedEventHandler};
use windows::Storage::Streams::{DataReader, DataWriter};
use windows::core::{GUID, Interface};
use windows_future::IAsyncOperation;

/// Windows expects the request deferral to remain alive until the ATT
/// response has been sent, even if a task is cancelled during shutdown.
struct CompleteDeferral(Deferral);

impl Drop for CompleteDeferral {
    fn drop(&mut self) {
        let _ = self.0.Complete();
    }
}

/// Retain the WinRT event source and revoke its handlers on teardown.
struct LocalBinding {
    characteristic: GattLocalCharacteristic,
    read_token: Option<i64>,
    write_token: Option<i64>,
}

impl Drop for LocalBinding {
    fn drop(&mut self) {
        if let Some(token) = self.read_token.take() {
            let _ = self.characteristic.RemoveReadRequested(token);
        }
        if let Some(token) = self.write_token.take() {
            let _ = self.characteristic.RemoveWriteRequested(token);
        }
    }
}

/// Retaining both providers and local characteristic handles keeps the server
/// alive while it is advertising. Dropping the bindings revokes all handlers.
struct Published {
    providers: Vec<GattServiceProvider>,
    bindings: Vec<LocalBinding>,
}

impl Published {
    fn stop(&mut self) {
        for provider in &self.providers {
            let _ = provider.StopAdvertising();
        }
        self.bindings.clear();
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
    request_tx: mpsc::UnboundedSender<PeripheralRequest>,
    runtime: Handle,
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
    BlewError::Internal(format!("Windows GATT server Stage 4b: {}", message.into()))
}

/// Only expose GATT properties that Stage 4b can actually honor.
/// Notification and indication bits are refused until subscribers and sending
/// are implemented; declaring them now would break Iroh silently.
fn validate_service(service: &GattService) -> BlewResult<()> {
    if !service.primary {
        return Err(BlewError::NotSupported);
    }
    let allowed = CharacteristicProperties::READ
        | CharacteristicProperties::WRITE
        | CharacteristicProperties::WRITE_WITHOUT_RESPONSE;
    let mut seen = HashSet::new();
    for characteristic in &service.characteristics {
        if !seen.insert(characteristic.uuid) {
            return Err(unsupported(format!(
                "duplicate characteristic UUID {} in service {}",
                characteristic.uuid, service.uuid
            )));
        }
        if !characteristic.descriptors.is_empty() || !allowed.contains(characteristic.properties) {
            return Err(BlewError::NotSupported);
        }
        let writable = characteristic.properties.intersects(
            CharacteristicProperties::WRITE | CharacteristicProperties::WRITE_WITHOUT_RESPONSE,
        );
        if writable && !characteristic.value.is_empty() {
            return Err(unsupported(
                "writable characteristics must use an empty static value",
            ));
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

fn write_protection(perms: AttributePermissions) -> GattProtectionLevel {
    if perms.contains(AttributePermissions::WRITE_AUTHENTICATED) {
        GattProtectionLevel::EncryptionAndAuthenticationRequired
    } else if perms.contains(AttributePermissions::WRITE_ENCRYPTED) {
        GattProtectionLevel::EncryptionRequired
    } else {
        GattProtectionLevel::Plain
    }
}

// ATT 0x07 = Invalid Offset; 0x80 = Application Error.
const ATT_INVALID_OFFSET: u8 = 0x07;
const ATT_APP_ERROR: u8 = 0x80;
// Keep below the typical BLE ATT procedure timeout; a stalled app must not
// hold WinRT's deferral indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn client_id_for_session(
    session: &windows::Devices::Bluetooth::GenericAttributeProfile::GattSession,
) -> windows::core::Result<DeviceId> {
    // Windows supplies a Bluetooth device ID, not necessarily a public MAC.
    // The same OS ID is used for read/write and (eventually) subscriptions.
    let id = session.DeviceId()?.Id()?.to_string();
    Ok(DeviceId::from(id))
}

async fn process_read(
    operation: IAsyncOperation<GattReadRequest>,
    client_id: DeviceId,
    service_uuid: Uuid,
    char_uuid: Uuid,
    tx: mpsc::UnboundedSender<PeripheralRequest>,
) -> windows::core::Result<()> {
    let request = operation.await?;
    if request.as_raw().is_null() {
        return Ok(());
    }
    let offset = match u16::try_from(request.Offset()?) {
        Ok(offset) => offset,
        Err(_) => return request.RespondWithProtocolError(ATT_INVALID_OFFSET),
    };
    let (answer_tx, answer_rx) = oneshot::channel();
    let event = PeripheralRequest::Read {
        client_id,
        service_uuid,
        char_uuid,
        offset,
        responder: ReadResponder::new(answer_tx),
    };
    if tx.send(event).is_err() {
        return request.RespondWithProtocolError(ATT_APP_ERROR);
    }
    match tokio::time::timeout(REQUEST_TIMEOUT, answer_rx).await {
        Ok(Ok(Ok(value))) => {
            // No IBuffer/DataWriter may survive across an .await: the
            // handler task runs on a multithreaded Tokio executor.
            let writer = DataWriter::new()?;
            writer.WriteBytes(&value)?;
            let buffer = writer.DetachBuffer()?;
            request.RespondWithValue(&buffer)
        }
        _ => request.RespondWithProtocolError(ATT_APP_ERROR),
    }
}

async fn process_write(
    operation: IAsyncOperation<GattWriteRequest>,
    client_id: DeviceId,
    service_uuid: Uuid,
    char_uuid: Uuid,
    tx: mpsc::UnboundedSender<PeripheralRequest>,
) -> windows::core::Result<()> {
    let request = operation.await?;
    if request.as_raw().is_null() {
        return Ok(());
    }
    let with_response = request.Option()? == GattWriteOption::WriteWithResponse;
    let offset = match u16::try_from(request.Offset()?) {
        Ok(offset) => offset,
        Err(_) => {
            if with_response {
                request.RespondWithProtocolError(ATT_INVALID_OFFSET)?;
            }
            return Ok(());
        }
    };
    let bytes = {
        let buffer = request.Value()?;
        let mut bytes = vec![0u8; buffer.Length()? as usize];
        DataReader::FromBuffer(&buffer)?.ReadBytes(&mut bytes)?;
        bytes
    };
    // Drop IBuffer/DataReader before awaiting the application response.
    if with_response {
        let (answer_tx, answer_rx) = oneshot::channel();
        let event = PeripheralRequest::Write {
            client_id,
            service_uuid,
            char_uuid,
            offset,
            value: bytes,
            responder: Some(WriteResponder::new(answer_tx)),
        };
        if tx.send(event).is_err() {
            return request.RespondWithProtocolError(ATT_APP_ERROR);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, answer_rx).await {
            Ok(Ok(true)) => request.Respond(),
            _ => request.RespondWithProtocolError(ATT_APP_ERROR),
        }
    } else {
        // ATT Write Command has no ATT response. The receiver owns the data
        // and is responsible for dispatching it without a handshake.
        let _ = tx.send(PeripheralRequest::Write {
            client_id,
            service_uuid,
            char_uuid,
            offset,
            value: bytes,
            responder: None,
        });
        Ok(())
    }
}

fn install_read_handler(
    characteristic: &GattLocalCharacteristic,
    service_uuid: Uuid,
    char_uuid: Uuid,
    tx: mpsc::UnboundedSender<PeripheralRequest>,
    runtime: Handle,
) -> BlewResult<i64> {
    characteristic
        .ReadRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattReadRequestedEventArgs,
        >::new(move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let deferral = args.GetDeferral()?;
            let operation = match args.GetRequestAsync() {
                Ok(op) => op,
                Err(e) => {
                    let _ = deferral.Complete();
                    return Err(e);
                }
            };
            let client_id = match args.Session().and_then(|s| client_id_for_session(&s)) {
                Ok(id) => id,
                Err(e) => {
                    let _ = deferral.Complete();
                    return Err(e);
                }
            };
            let tx = tx.clone();
            runtime.spawn(async move {
                let _deferral = CompleteDeferral(deferral);
                if let Err(err) =
                    process_read(operation, client_id, service_uuid, char_uuid, tx).await
                {
                    tracing::warn!(?err, %service_uuid, %char_uuid, "Windows GATT read failed");
                }
            });
            Ok(())
        }))
        .map_err(peripheral_error)
}

fn install_write_handler(
    characteristic: &GattLocalCharacteristic,
    service_uuid: Uuid,
    char_uuid: Uuid,
    tx: mpsc::UnboundedSender<PeripheralRequest>,
    runtime: Handle,
) -> BlewResult<i64> {
    characteristic
        .WriteRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattWriteRequestedEventArgs,
        >::new(move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let deferral = args.GetDeferral()?;
            let operation = match args.GetRequestAsync() {
                Ok(op) => op,
                Err(e) => {
                    let _ = deferral.Complete();
                    return Err(e);
                }
            };
            let client_id = match args.Session().and_then(|s| client_id_for_session(&s)) {
                Ok(id) => id,
                Err(e) => {
                    let _ = deferral.Complete();
                    return Err(e);
                }
            };
            let tx = tx.clone();
            runtime.spawn(async move {
                let _deferral = CompleteDeferral(deferral);
                if let Err(err) =
                    process_write(operation, client_id, service_uuid, char_uuid, tx).await
                {
                    tracing::warn!(?err, %service_uuid, %char_uuid, "Windows GATT write failed");
                }
            });
            Ok(())
        }))
        .map_err(peripheral_error)
}

async fn build_provider(
    service: &GattService,
    tx: &mpsc::UnboundedSender<PeripheralRequest>,
    runtime: &Handle,
) -> BlewResult<(GattServiceProvider, Vec<LocalBinding>)> {
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
    let mut bindings = Vec::new();

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
        params
            .SetWriteProtectionLevel(write_protection(characteristic.permissions))
            .map_err(peripheral_error)?;
        // Empty static value means the application owns the read response.
        // A nonempty value is a static WinRT read with no callback.
        if characteristic
            .properties
            .contains(CharacteristicProperties::READ)
            && !characteristic.value.is_empty()
        {
            let writer = DataWriter::new().map_err(peripheral_error)?;
            writer
                .WriteBytes(&characteristic.value)
                .map_err(peripheral_error)?;
            let buffer = writer.DetachBuffer().map_err(peripheral_error)?;
            params.SetStaticValue(&buffer).map_err(peripheral_error)?;
        }
        // Construct operation while params and its IBuffer remain in scope;
        // only the WinRT IAsyncOperation is carried across the await.
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
        let local = result.Characteristic().map_err(peripheral_error)?;
        let mut binding = LocalBinding {
            characteristic: local,
            read_token: None,
            write_token: None,
        };
        if characteristic
            .properties
            .contains(CharacteristicProperties::READ)
            && characteristic.value.is_empty()
        {
            binding.read_token = Some(install_read_handler(
                &binding.characteristic,
                service.uuid,
                characteristic.uuid,
                tx.clone(),
                runtime.clone(),
            )?);
        }
        if characteristic.properties.intersects(
            CharacteristicProperties::WRITE | CharacteristicProperties::WRITE_WITHOUT_RESPONSE,
        ) {
            binding.write_token = Some(install_write_handler(
                &binding.characteristic,
                service.uuid,
                characteristic.uuid,
                tx.clone(),
                runtime.clone(),
            )?);
        }
        bindings.push(binding);
    }
    Ok((provider, bindings))
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
            request_tx: tx,
            runtime: Handle::try_current()
                .map_err(|e| unsupported(format!("Tokio runtime unavailable: {e}")))?,
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
            bindings: Vec::new(),
        };
        for service in &state.pending {
            let (provider, mut bindings) =
                build_provider(service, &self.request_tx, &self.runtime).await?;
            published.providers.push(provider);
            published.bindings.append(&mut bindings);
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
