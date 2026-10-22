//! Windows BLE backend: stage 1 (advertisement scanning).
//!
//! GATT connections and GATT server support are deliberately NOT implemented yet.
//! The backend returns `BlewError::NotSupported` for those operations rather than
//! falsely reporting success. Do not use this stage for Iroh traffic.

pub mod central;
pub mod peripheral;

pub use central::WindowsCentral;
pub use peripheral::WindowsPeripheral;

use crate::error::{BlewError, BlewResult};
use windows::Devices::Bluetooth::BluetoothAdapter;
use windows::Devices::Radios::RadioState;

pub(super) fn central_error(e: windows::core::Error) -> BlewError {
    BlewError::Central {
        source: Box::new(e),
    }
}

pub(super) fn peripheral_error(e: windows::core::Error) -> BlewError {
    BlewError::Peripheral {
        source: Box::new(e),
    }
}

pub(super) async fn get_adapter() -> BlewResult<BluetoothAdapter> {
    // WinRT .await waits synchronously. Future iteration should make this
    // properly asynchronous; called infrequently in the first milestone.
    let adapter = BluetoothAdapter::GetDefaultAsync()
        .map_err(central_error)?
        .await
        .map_err(central_error)?;
    if !adapter.IsLowEnergySupported().map_err(central_error)? {
        return Err(BlewError::AdapterNotFound);
    }
    Ok(adapter)
}

pub(super) async fn radio_powered(adapter: &BluetoothAdapter) -> BlewResult<bool> {
    let radio = adapter
        .GetRadioAsync()
        .map_err(central_error)?
        .await
        .map_err(central_error)?;
    Ok(radio.State().map_err(central_error)? == RadioState::On)
}
