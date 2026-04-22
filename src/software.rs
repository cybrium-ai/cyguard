//! Software inventory — installed packages.
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: String,
}

pub fn list_packages() -> Vec<Package> {
    let mut pkgs = Vec::new();
    if cfg!(target_os = "macos") {
        if let Ok(out) = Command::new("brew").args(["list", "--versions"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.splitn(2, ' ');
                if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
                    pkgs.push(Package { name: name.into(), version: ver.trim().into(), source: "homebrew".into() });
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        if let Ok(out) = Command::new("dpkg-query").args(["-W", "-f", "${Package} ${Version}\n"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.splitn(2, ' ');
                if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
                    pkgs.push(Package { name: name.into(), version: ver.into(), source: "dpkg".into() });
                }
            }
        }
    }
    pkgs
}
