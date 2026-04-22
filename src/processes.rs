//! Process inventory.
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub user: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
}

pub fn list_processes(sys: &System) -> Vec<ProcessInfo> {
    sys.processes().values().map(|p| {
        ProcessInfo {
            pid: p.pid().as_u32(),
            name: p.name().to_string_lossy().into(),
            path: p.exe().map(|e| e.to_string_lossy().into()).unwrap_or_default(),
            user: p.user_id().map(|u| u.to_string()).unwrap_or_default(),
            cpu_percent: p.cpu_usage(),
            memory_mb: p.memory() / 1024 / 1024,
        }
    }).collect()
}
