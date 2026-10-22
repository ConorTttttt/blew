//! Native Windows BLE backend (WinRT).
//!
//! Central: scanning, GATT client operations and incoming notifications.
//! Peripheral Stage 4a: GATT service providers and advertising for static
//! read-only characteristics. Dynamic GATT requests/notifications, secondary
//! services and custom local names are not supported yet.
//! This stage is not ready for end-to-end Iroh BLE traffic.

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
