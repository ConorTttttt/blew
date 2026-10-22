//! Windows-only BLE discovery smoke test.
//! `cargo run -p blew --example windows_scan` on Windows.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("Run this example on Windows 10/11.");
}

#[cfg(target_os = "windows")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use blew::central::{Central, ScanFilter};
    use std::time::Duration;
    use tokio_stream::StreamExt as _;

    let central: Central = Central::new().await?;
    println!("Adapter powered: {}", central.is_powered().await?);
    let mut stream = central.events();
    central.start_scan(ScanFilter::default()).await?;
    println!("Scanning for 15 seconds ...");
    let until = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, stream.next()).await {
            Ok(Some(blew::central::CentralEvent::DeviceDiscovered(device))) => {
                println!(
                    "{} RSSI={:?} name={:?} services={:?}",
                    device.id, device.rssi, device.name, device.services
                );
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    central.stop_scan().await?;
    println!(
        "Discovered {} devices",
        central.discovered_devices().await?.len()
    );
    Ok(())
}
