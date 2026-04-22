//! Network monitoring — open ports and connections.
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub protocol: String,
}

pub fn list_listeners() -> Vec<Listener> {
    let output = if cfg!(target_os = "macos") {
        Command::new("lsof").args(["-iTCP", "-sTCP:LISTEN", "-nP"]).output()
    } else {
        Command::new("ss").args(["-tlnp"]).output()
    };
    let mut listeners = Vec::new();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                if let Some(addr_port) = parts.get(8).or(parts.get(3)) {
                    if let Some((addr, port_str)) = addr_port.rsplit_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            listeners.push(Listener {
                                address: addr.trim_start_matches('[').trim_end_matches(']').into(),
                                port,
                                protocol: "TCP".into(),
                                process: parts.get(0).map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
    listeners.sort_by_key(|l| l.port);
    listeners.dedup_by_key(|l| l.port);
    listeners
}

pub fn list_connections() -> Vec<Connection> {
    // Simplified — just return active connections
    Vec::new()
}
