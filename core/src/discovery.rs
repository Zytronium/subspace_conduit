use std::collections::HashMap;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tracing::info;

const SERVICE_TYPE: &str = "_subspace._tcp.local.";

// -------- server-side advertising --------
// The returned ServiceDaemon must be kept alive for as long as the service
// should stay advertised, dropping it unregisters the service.
pub fn advertise(port: u16, device_name: &str) -> anyhow::Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new()?;

    let host_ip = local_ip_address::local_ip()?.to_string();
    let hostname = format!("{device_name}.local.");

    let mut properties = HashMap::new();
    properties.insert("device".to_string(), device_name.to_string());

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        device_name,
        &hostname,
        host_ip.as_str(),
        port,
        Some(properties),
    )?;

    daemon.register(service_info)?;
    info!("advertising subspace_conduit service as '{device_name}' on port {port}");

    Ok(daemon)
}

// -------- client-side discovery --------
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredServer {
    pub name: String,
    pub addr: String,
    pub port: u16,
}

pub fn discover(timeout: Duration) -> anyhow::Result<Vec<DiscoveredServer>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;

    let mut found = Vec::new();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(addr) = info.get_addresses().iter().next() {
                    found.push(DiscoveredServer {
                        name: info.get_fullname().to_string(),
                        addr: addr.to_string(),
                        port: info.get_port(),
                    });
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // -------- clean shutdown --------
    // shutdown() returns a receiver that reports when the daemon thread has
    // actually finished. Waiting on it (instead of dropping it immediately)
    // avoids the daemon trying to send its status into an already-closed
    // channel, which is what caused the earlier error.
    let _ = daemon.stop_browse(SERVICE_TYPE);
    if let Ok(shutdown_receiver) = daemon.shutdown() {
        let _ = shutdown_receiver.recv_timeout(Duration::from_millis(500));
    }

    Ok(found)
}

// -------- resolve a single server by name --------
// Like discover(), but stops as soon as a service whose instance name
// matches is found, rather than collecting everything until the timeout.
pub fn resolve_by_name(name: &str, timeout: Duration) -> anyhow::Result<Option<DiscoveredServer>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;

    let deadline = Instant::now() + timeout;
    let mut found = None;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let instance_name = info
                    .get_fullname()
                    .split('.')
                    .next()
                    .unwrap_or_default();

                if instance_name == name {
                    if let Some(addr) = info.get_addresses().iter().next() {
                        found = Some(DiscoveredServer {
                            name: info.get_fullname().to_string(),
                            addr: addr.to_string(),
                            port: info.get_port(),
                        });
                    }
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let _ = daemon.stop_browse(SERVICE_TYPE);
    if let Ok(shutdown_receiver) = daemon.shutdown() {
        let _ = shutdown_receiver.recv_timeout(Duration::from_millis(500));
    }

    Ok(found)
}
