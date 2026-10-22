//! Windows central: advertisement scanning and basic WinRT GATT client.
//! Stage 3: WinRT GATT notifications and disconnection event handling.
//! Hardware validation and concurrent-operation hardening are still required.

use crate::central::backend::{self, CentralBackend};
use crate::central::types::{
    CentralConfig, CentralEvent, DisconnectCause, ScanFilter, ScanMode, WriteType,
};
use crate::error::{BlewError, BlewResult};
use crate::gatt::props::{AttributePermissions, CharacteristicProperties};
use crate::gatt::service::{GattCharacteristic, GattService};
use crate::l2cap::{L2capChannel, types::Psm};
use crate::platform::windows::{central_error, get_adapter, radio_powered};
use crate::types::{BleDevice, DeviceId};
use crate::util::BroadcastEventStream;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::broadcast;
use uuid::Uuid;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic as WinGattCharacteristic,
    GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
    GattDeviceService, GattValueChangedEventArgs, GattWriteOption,
};
use windows::Devices::Bluetooth::{
    BluetoothAdapter, BluetoothCacheMode, BluetoothConnectionStatus, BluetoothLEDevice,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};
use windows::core::{IInspectable, Interface};

struct ScanHandle {
    watcher: BluetoothLEAdvertisementWatcher,
    received_token: i64,
}

struct WindowsSubscription {
    characteristic: WinGattCharacteristic,
    token: i64,
    active: Arc<AtomicBool>,
}

struct WindowsConnection {
    // Hold the COM device alive for the entire logical connection.
    device: BluetoothLEDevice,
    // Hold service handles; releasing all of them also releases the GATT session.
    services: Vec<GattDeviceService>,
    characteristics: HashMap<Uuid, WinGattCharacteristic>,
    subscriptions: HashMap<Uuid, WindowsSubscription>,
    status_token: i64,
    generation: u64,
}

struct Inner {
    adapter: BluetoothAdapter,
    discovered: Mutex<HashMap<DeviceId, BleDevice>>,
    connections: Mutex<HashMap<DeviceId, WindowsConnection>>,
    generation: AtomicU64,
    scan: Mutex<Option<ScanHandle>>,
    events: broadcast::Sender<CentralEvent>,
}

impl Inner {
    fn on_received(
        &self,
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        filter: &ScanFilter,
    ) -> windows::core::Result<()> {
        let adv = args.Advertisement()?;
        let uuids = adv.ServiceUuids()?;
        let count = uuids.Size()?;
        let mut services = Vec::with_capacity(count as usize);
        for i in 0..count {
            services.push(Uuid::from_u128(uuids.GetAt(i)?.to_u128()));
        }
        // An empty filter accepts all, otherwise the received packet MUST match.
        if !filter.services.is_empty()
            && !services.iter().any(|uuid| filter.services.contains(uuid))
        {
            return Ok(());
        }
        // Stable within a scan session; may rotate if the remote uses random addresses.
        // Keep uppercase hex without punctuation so the next connection stage can parse u64.
        let device_id = DeviceId::from(format!("{:012X}", args.BluetoothAddress()?));
        let name = adv.LocalName()?.to_string();
        let snapshot = BleDevice {
            id: device_id.clone(),
            name: (!name.is_empty()).then_some(name),
            rssi: Some(args.RawSignalStrengthInDBm()?),
            services,
            manufacturer_data: HashMap::new(), // stage 2: decode manufacturer data
            service_data: HashMap::new(),      // stage 2: decode service data
        };
        self.discovered.lock().insert(device_id, snapshot.clone());
        let _ = self.events.send(CentralEvent::DeviceDiscovered(snapshot));
        Ok(())
    }

    fn device_lost(&self, device_id: &DeviceId, generation: u64) {
        let removed = {
            let mut connections = self.connections.lock();
            // Ignore callbacks from a previous connection to the same address.
            if connections.get(device_id).map(|c| c.generation) != Some(generation) {
                return;
            }
            connections.remove(device_id)
        };
        if let Some(connection) = removed {
            close_connection(connection);
            let _ = self.events.send(CentralEvent::DeviceDisconnected {
                device_id: device_id.clone(),
                cause: DisconnectCause::LinkLoss,
            });
        }
    }
}

fn close_connection(connection: WindowsConnection) {
    for subscription in connection.subscriptions.into_values() {
        subscription.active.store(false, Ordering::Release);
        let _ = subscription
            .characteristic
            .RemoveValueChanged(subscription.token);
    }
    let _ = connection
        .device
        .RemoveConnectionStatusChanged(connection.status_token);
    for service in &connection.services {
        let _ = service.Close();
    }
    let _ = connection.device.Close();
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(scan) = self.scan.get_mut().take() {
            let _ = scan.watcher.Stop();
            let _ = scan.watcher.RemoveReceived(scan.received_token);
        }
        for connection in self.connections.get_mut().drain().map(|(_, c)| c) {
            close_connection(connection);
        }
    }
}

pub struct WindowsCentral(Arc<Inner>);

impl WindowsCentral {
    pub async fn with_config(_config: CentralConfig) -> BlewResult<Self> {
        <Self as CentralBackend>::new().await
    }
}

impl backend::private::Sealed for WindowsCentral {}

impl CentralBackend for WindowsCentral {
    type EventStream = BroadcastEventStream<CentralEvent>;

    async fn new() -> BlewResult<Self> {
        let adapter = get_adapter().await?;
        if !adapter.IsCentralRoleSupported().map_err(central_error)? {
            return Err(BlewError::NotSupported);
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self(Arc::new(Inner {
            adapter,
            discovered: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            scan: Mutex::new(None),
            events,
        })))
    }

    async fn is_powered(&self) -> BlewResult<bool> {
        radio_powered(&self.0.adapter).await
    }

    async fn start_scan(&self, filter: ScanFilter) -> BlewResult<()> {
        if !self.is_powered().await? {
            return Err(BlewError::NotPowered);
        }
        let mut slot = self.0.scan.lock();
        if slot.is_some() {
            // Start is idempotent. Call stop_scan first to change the filter.
            return Ok(());
        }
        let watcher = BluetoothLEAdvertisementWatcher::new().map_err(central_error)?;
        let mode = match filter.mode {
            ScanMode::LowLatency => BluetoothLEScanningMode::Active,
            ScanMode::LowPower => BluetoothLEScanningMode::Passive,
        };
        watcher.SetScanningMode(mode).map_err(central_error)?;
        let inner = Arc::downgrade(&self.0);
        let token = watcher
            .Received(&TypedEventHandler::<
                BluetoothLEAdvertisementWatcher,
                BluetoothLEAdvertisementReceivedEventArgs,
            >::new(move |_, args| {
                if let (Some(args), Some(inner)) = (args.as_ref(), inner.upgrade()) {
                    if let Err(err) = inner.on_received(args, &filter) {
                        tracing::debug!(error = %err, "Windows advertisement decoding failed");
                    }
                }
                Ok(())
            }))
            .map_err(central_error)?;
        self.0.discovered.lock().clear();
        if let Err(err) = watcher.Start() {
            let _ = watcher.RemoveReceived(token);
            return Err(central_error(err));
        }
        *slot = Some(ScanHandle {
            watcher,
            received_token: token,
        });
        Ok(())
    }

    async fn stop_scan(&self) -> BlewResult<()> {
        if let Some(scan) = self.0.scan.lock().take() {
            let stop_result = scan.watcher.Stop();
            let remove_result = scan.watcher.RemoveReceived(scan.received_token);
            stop_result.map_err(central_error)?;
            remove_result.map_err(central_error)?;
        }
        Ok(())
    }

    async fn discovered_devices(&self) -> BlewResult<Vec<BleDevice>> {
        Ok(self.0.discovered.lock().values().cloned().collect())
    }

    async fn connect(&self, device_id: &DeviceId) -> BlewResult<()> {
        if !self.is_powered().await? {
            return Err(BlewError::NotPowered);
        }
        if self.0.connections.lock().contains_key(device_id) {
            return Ok(());
        }
        let address = u64::from_str_radix(device_id.as_str(), 16)
            .map_err(|_| BlewError::DeviceNotFound(device_id.clone()))?;
        // Windows needs the device in its cache, typically populated by start_scan.
        let device = BluetoothLEDevice::FromBluetoothAddressAsync(address)
            .map_err(central_error)?
            .await
            .map_err(central_error)?;
        if device.as_raw().is_null() {
            return Err(BlewError::DeviceNotFound(device_id.clone()));
        }
        // An uncached GATT discovery is what initiates the physical BLE link.
        // Merely constructing BluetoothLEDevice does not establish a connection.
        let result = device
            .GetGattServicesWithCacheModeAsync(BluetoothCacheMode::Uncached)
            .map_err(central_error)?
            .await
            .map_err(central_error)?;
        let status = result.Status().map_err(central_error)?;
        if status != GattCommunicationStatus::Success {
            let _ = device.Close();
            return Err(BlewError::DiscoveryFailed {
                device_id: device_id.clone(),
                reason: format!("Windows GATT discovery status: {status:?}"),
            });
        }
        let win_services = result.Services().map_err(central_error)?;
        let mut services = Vec::new();
        for i in 0..win_services.Size().map_err(central_error)? {
            services.push(win_services.GetAt(i).map_err(central_error)?);
        }
        let generation = self.0.generation.fetch_add(1, Ordering::Relaxed);
        let weak = Arc::downgrade(&self.0);
        let id_for_callback = device_id.clone();
        let status_token = device
            .ConnectionStatusChanged(&TypedEventHandler::<BluetoothLEDevice, IInspectable>::new(
                move |sender, _| {
                    if let (Some(device), Some(inner)) = (sender.as_ref(), weak.upgrade()) {
                        if device.ConnectionStatus()? == BluetoothConnectionStatus::Disconnected {
                            inner.device_lost(&id_for_callback, generation);
                        }
                    }
                    Ok(())
                },
            ))
            .map_err(central_error)?;
        self.0.connections.lock().insert(
            device_id.clone(),
            WindowsConnection {
                device,
                services,
                characteristics: HashMap::new(),
                subscriptions: HashMap::new(),
                status_token,
                generation,
            },
        );
        // The event may have fired between handler registration and insertion.
        let disconnected = self
            .0
            .connections
            .lock()
            .get(device_id)
            .and_then(|c| c.device.ConnectionStatus().ok())
            == Some(BluetoothConnectionStatus::Disconnected);
        if disconnected {
            self.0.device_lost(device_id, generation);
            return Err(BlewError::NotConnected(device_id.clone()));
        }
        let _ = self.0.events.send(CentralEvent::DeviceConnected {
            device_id: device_id.clone(),
        });
        Ok(())
    }

    async fn disconnect(&self, device_id: &DeviceId) -> BlewResult<()> {
        let connection = self
            .0
            .connections
            .lock()
            .remove(device_id)
            .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?;
        // Release subscriptions, event handlers, and WinRT handles.
        // Windows may retain the radio link if another process uses it.
        close_connection(connection);
        let _ = self.0.events.send(CentralEvent::DeviceDisconnected {
            device_id: device_id.clone(),
            cause: DisconnectCause::LocalClose,
        });
        Ok(())
    }

    async fn discover_services(&self, device_id: &DeviceId) -> BlewResult<Vec<GattService>> {
        // Copy the COM handles, never carry a parking_lot guard across await.
        let services = self
            .0
            .connections
            .lock()
            .get(device_id)
            .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?
            .services
            .clone();
        let mut output = Vec::new();
        let mut chars = HashMap::new();
        for service in services {
            let id = Uuid::from_u128(service.Uuid().map_err(central_error)?.to_u128());
            let result = service
                .GetCharacteristicsWithCacheModeAsync(BluetoothCacheMode::Uncached)
                .map_err(central_error)?
                .await
                .map_err(central_error)?;
            let status = result.Status().map_err(central_error)?;
            if status != GattCommunicationStatus::Success {
                return Err(BlewError::DiscoveryFailed {
                    device_id: device_id.clone(),
                    reason: format!("Characteristic discovery for {id}: {status:?}"),
                });
            }
            let win_chars = result.Characteristics().map_err(central_error)?;
            let mut characteristics = Vec::new();
            for i in 0..win_chars.Size().map_err(central_error)? {
                let win_char = win_chars.GetAt(i).map_err(central_error)?;
                let uuid = Uuid::from_u128(win_char.Uuid().map_err(central_error)?.to_u128());
                let flags = win_char.CharacteristicProperties().map_err(central_error)?;
                characteristics.push(GattCharacteristic {
                    uuid,
                    properties: CharacteristicProperties::from_bits_truncate(flags.0 as u16),
                    // Client-side discovery cannot infer server access requirements.
                    permissions: AttributePermissions::empty(),
                    value: Vec::new(),
                    descriptors: Vec::new(),
                });
                // The blew API identifies a characteristic by UUID, not by handle;
                // if UUIDs repeat, only the first is addressable.
                chars.entry(uuid).or_insert(win_char);
            }
            output.push(GattService {
                uuid: id,
                // WinRT does not expose the primary/secondary bit here.
                primary: true,
                characteristics,
            });
        }
        let mut connections = self.0.connections.lock();
        let connection = connections
            .get_mut(device_id)
            .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?;
        connection.characteristics = chars;
        Ok(output)
    }

    async fn read_characteristic(
        &self,
        device_id: &DeviceId,
        char_uuid: Uuid,
    ) -> BlewResult<Vec<u8>> {
        let characteristic = self
            .0
            .connections
            .lock()
            .get(device_id)
            .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?
            .characteristics
            .get(&char_uuid)
            .cloned()
            .ok_or_else(|| BlewError::CharacteristicNotFound {
                device_id: device_id.clone(),
                char_uuid,
            })?;
        let result = characteristic
            .ReadValueAsync()
            .map_err(central_error)?
            .await
            .map_err(central_error)?;
        let status = result.Status().map_err(central_error)?;
        if status != GattCommunicationStatus::Success {
            return Err(BlewError::Gatt {
                device_id: device_id.clone(),
                source: std::io::Error::other(format!("Windows GATT read status: {status:?}"))
                    .into(),
            });
        }
        let buffer = result.Value().map_err(central_error)?;
        let mut bytes = vec![0u8; buffer.Length().map_err(central_error)? as usize];
        DataReader::FromBuffer(&buffer)
            .map_err(central_error)?
            .ReadBytes(&mut bytes)
            .map_err(central_error)?;
        Ok(bytes)
    }

    async fn write_characteristic(
        &self,
        device_id: &DeviceId,
        char_uuid: Uuid,
        value: Vec<u8>,
        write_type: WriteType,
    ) -> BlewResult<()> {
        let characteristic = self
            .0
            .connections
            .lock()
            .get(device_id)
            .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?
            .characteristics
            .get(&char_uuid)
            .cloned()
            .ok_or_else(|| BlewError::CharacteristicNotFound {
                device_id: device_id.clone(),
                char_uuid,
            })?;
        let operation = {
            let writer = DataWriter::new().map_err(central_error)?;
            writer.WriteBytes(&value).map_err(central_error)?;

            let buffer = writer.DetachBuffer().map_err(central_error)?;

            let option = match write_type {
                WriteType::WithResponse => GattWriteOption::WriteWithResponse,
                WriteType::WithoutResponse => GattWriteOption::WriteWithoutResponse,
            };

            characteristic
                .WriteValueWithResultAndOptionAsync(&buffer, option)
                .map_err(central_error)?
        };

        let result = operation.await.map_err(central_error)?;
        let status = result.Status().map_err(central_error)?;
        if status != GattCommunicationStatus::Success {
            return Err(BlewError::Gatt {
                device_id: device_id.clone(),
                source: std::io::Error::other(format!("Windows GATT write status: {status:?}"))
                    .into(),
            });
        }
        Ok(())
    }
    async fn subscribe_characteristic(
        &self,
        device_id: &DeviceId,
        char_uuid: Uuid,
    ) -> BlewResult<()> {
        let characteristic = {
            let connections = self.0.connections.lock();
            let connection = connections
                .get(device_id)
                .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?;
            if connection.subscriptions.contains_key(&char_uuid) {
                return Err(BlewError::AlreadySubscribed {
                    device_id: device_id.clone(),
                    char_uuid,
                });
            }
            connection
                .characteristics
                .get(&char_uuid)
                .cloned()
                .ok_or_else(|| BlewError::CharacteristicNotFound {
                    device_id: device_id.clone(),
                    char_uuid,
                })?
        };
        let props = CharacteristicProperties::from_bits_truncate(
            characteristic
                .CharacteristicProperties()
                .map_err(central_error)?
                .0 as u16,
        );
        let mode = if props.contains(CharacteristicProperties::NOTIFY) {
            GattClientCharacteristicConfigurationDescriptorValue::Notify
        } else if props.contains(CharacteristicProperties::INDICATE) {
            GattClientCharacteristicConfigurationDescriptorValue::Indicate
        } else {
            return Err(BlewError::NotSupported);
        };

        let active = Arc::new(AtomicBool::new(true));
        let enabled = Arc::clone(&active);
        let events = self.0.events.clone();
        let id = device_id.clone();
        let token = characteristic
            .ValueChanged(&TypedEventHandler::<
                WinGattCharacteristic,
                GattValueChangedEventArgs,
            >::new(move |_, args| {
                if !enabled.load(Ordering::Acquire) {
                    return Ok(());
                }
                if let Some(args) = args.as_ref() {
                    // COM buffers stay entirely inside this synchronous callback.
                    let decode = (|| -> windows::core::Result<Vec<u8>> {
                        let buffer = args.CharacteristicValue()?;
                        let reader = DataReader::FromBuffer(&buffer)?;
                        let mut value = vec![0u8; buffer.Length()? as usize];
                        reader.ReadBytes(&mut value)?;
                        Ok(value)
                    })();
                    match decode {
                        Ok(value) => {
                            if enabled.load(Ordering::Acquire) {
                                let _ = events.send(CentralEvent::CharacteristicNotification {
                                    device_id: id.clone(),
                                    char_uuid,
                                    value: bytes::Bytes::from(value),
                                });
                            }
                        }
                        Err(err) => {
                            tracing::debug!(error = %err, "GATT notification decode failed")
                        }
                    }
                }
                Ok(())
            }))
            .map_err(central_error)?;

        // Register the callback *before* enabling the CCCD, so the first
        // notification cannot be lost between descriptor write and registration.
        let operation =
            match characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(mode) {
                Ok(op) => op,
                Err(err) => {
                    active.store(false, Ordering::Release);
                    let _ = characteristic.RemoveValueChanged(token);
                    return Err(central_error(err));
                }
            };
        let status = operation.await;
        if !matches!(&status, Ok(v) if *v == GattCommunicationStatus::Success) {
            active.store(false, Ordering::Release);
            let _ = characteristic.RemoveValueChanged(token);
            let reason = match status {
                Ok(code) => format!("Windows CCCD write status: {code:?}"),
                Err(err) => format!("Windows CCCD write failed: {err}"),
            };
            return Err(BlewError::Gatt {
                device_id: device_id.clone(),
                source: std::io::Error::other(reason).into(),
            });
        }
        let mut connections = self.0.connections.lock();
        let Some(connection) = connections.get_mut(device_id) else {
            active.store(false, Ordering::Release);
            let _ = characteristic.RemoveValueChanged(token);
            return Err(BlewError::NotConnected(device_id.clone()));
        };
        if connection.subscriptions.contains_key(&char_uuid) {
            active.store(false, Ordering::Release);
            let _ = characteristic.RemoveValueChanged(token);
            return Err(BlewError::AlreadySubscribed {
                device_id: device_id.clone(),
                char_uuid,
            });
        }
        connection.subscriptions.insert(
            char_uuid,
            WindowsSubscription {
                characteristic,
                token,
                active,
            },
        );
        Ok(())
    }

    async fn unsubscribe_characteristic(
        &self,
        device_id: &DeviceId,
        char_uuid: Uuid,
    ) -> BlewResult<()> {
        let subscription = {
            let mut connections = self.0.connections.lock();
            connections
                .get_mut(device_id)
                .ok_or_else(|| BlewError::NotConnected(device_id.clone()))?
                .subscriptions
                .remove(&char_uuid)
                .ok_or_else(|| BlewError::CharacteristicNotFound {
                    device_id: device_id.clone(),
                    char_uuid,
                })?
        };
        subscription.active.store(false, Ordering::Release);
        let _ = subscription
            .characteristic
            .RemoveValueChanged(subscription.token);
        let operation = subscription
            .characteristic
            .WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::None,
            )
            .map_err(central_error)?;
        let status = operation.await.map_err(central_error)?;
        if status != GattCommunicationStatus::Success {
            return Err(BlewError::Gatt {
                device_id: device_id.clone(),
                source: std::io::Error::other(format!("Windows CCCD disable status: {status:?}",))
                    .into(),
            });
        }
        Ok(())
    }
    async fn mtu(&self, _device_id: &DeviceId) -> u16 {
        23
    }
    async fn open_l2cap_channel(
        &self,
        _device_id: &DeviceId,
        _psm: Psm,
    ) -> BlewResult<L2capChannel> {
        Err(BlewError::NotSupported)
    }
    fn events(&self) -> Self::EventStream {
        BroadcastEventStream::new(self.0.events.subscribe())
    }
}
