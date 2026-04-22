//! cyguard — Lightweight endpoint security agent by Cybrium AI.

mod processes;
mod network;
mod software;
mod output;

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cyguard", version, about = "Endpoint security agent — Cybrium AI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// One-shot endpoint security scan
    Scan {
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Run as continuous monitoring agent
    Agent {
        #[arg(long, default_value = "60")]
        interval: u64,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Self-update
    Update,
    /// Show version
    Version,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReport {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub uptime_secs: u64,
    pub cpu_count: usize,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub processes: Vec<processes::ProcessInfo>,
    pub listeners: Vec<network::Listener>,
    pub connections: Vec<network::Connection>,
    pub software: Vec<software::Package>,
    pub findings: Vec<Finding>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub evidence: String,
}

fn print_banner() {
    eprintln!("\x1b[35m");
    eprintln!(r#"   ___  _   _  ___  _   _    _    ___  ___  "#);
    eprintln!(r#"  / __|| | | |/ __|| | | |  /_\  | _ \|   \ "#);
    eprintln!(r#" | (__ | |_| || (_ || |_| | / _ \ |   /| |) |"#);
    eprintln!(r#"  \___| \__, | \___| \___/ /_/ \_\|_|_\|___/ "#);
    eprintln!(r#"        |___/                                "#);
    eprintln!("\x1b[0m");
    eprintln!("  \x1b[35m\x1b[1mcyguard\x1b[0m v{} — \x1b[2mCybrium AI Endpoint Agent\x1b[0m", env!("CARGO_PKG_VERSION"));
    eprintln!();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cyguard=info".parse().unwrap()))
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { format, output: out } => {
            print_banner();
            let report = collect_report();
            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&report).unwrap();
                    if let Some(p) = &out {
                        std::fs::write(p, &json).unwrap();
                        eprintln!("{} {}", "Report saved to".green(), p);
                    } else {
                        println!("{json}");
                    }
                }
                _ => {
                    output::print_report(&report);
                    if let Some(p) = &out {
                        let json = serde_json::to_string_pretty(&report).unwrap();
                        std::fs::write(p, &json).unwrap();
                        eprintln!("{} {}", "Report saved to".green(), p);
                    }
                }
            }
        }
        Commands::Agent { interval, platform, token } => {
            print_banner();
            eprintln!("  {} {}s", "Interval:".white().bold(), interval);
            if platform.is_some() { eprintln!("  {} streaming", "Platform:".white().bold()); }
            eprintln!("\n{}", "Running as agent... (Ctrl+C to stop)".green());
            loop {
                let report = collect_report();
                eprintln!("  [{}] {} processes, {} listeners, {} findings",
                    chrono::Local::now().format("%H:%M:%S"),
                    report.processes.len(), report.listeners.len(), report.findings.len());
                // TODO: stream to platform API
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }
        Commands::Update => {
            println!("Check https://github.com/cybrium-ai/cyguard/releases for updates");
        }
        Commands::Version => {
            println!("cyguard {} — Cybrium AI Endpoint Agent", env!("CARGO_PKG_VERSION"));
        }
    }
}

fn collect_report() -> EndpointReport {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let procs = processes::list_processes(&sys);
    let listeners = network::list_listeners();
    let connections = network::list_connections();
    let pkgs = software::list_packages();
    let mut findings = Vec::new();

    // Check for suspicious processes
    for p in &procs {
        let name_lower = p.name.to_lowercase();
        if name_lower.contains("miner") || name_lower.contains("xmrig") || name_lower.contains("cryptonight") {
            findings.push(Finding {
                id: format!("CYGUARD-PROC-{}", p.pid),
                title: format!("Suspicious process: {}", p.name),
                severity: "critical".into(),
                category: "Malware".into(),
                description: format!("Process '{}' (PID {}) matches crypto miner pattern", p.name, p.pid),
                evidence: format!("PID {} CMD {}", p.pid, p.path),
            });
        }
        if name_lower.contains("nc ") || name_lower.contains("ncat") || name_lower.contains("netcat") {
            findings.push(Finding {
                id: format!("CYGUARD-PROC-{}", p.pid),
                title: format!("Reverse shell indicator: {}", p.name),
                severity: "high".into(),
                category: "Backdoor".into(),
                description: format!("Netcat variant '{}' running — possible reverse shell", p.name),
                evidence: format!("PID {} CMD {}", p.pid, p.path),
            });
        }
    }

    // Check for OT protocol listeners
    for l in &listeners {
        let ot_port = match l.port {
            502 => Some("Modbus"),
            47808 => Some("BACnet"),
            44818 => Some("EtherNet/IP"),
            102 => Some("S7comm"),
            2404 => Some("IEC 104"),
            _ => None,
        };
        if let Some(proto) = ot_port {
            findings.push(Finding {
                id: format!("CYGUARD-OT-{}", l.port),
                title: format!("OT protocol listener: {} on port {}", proto, l.port),
                severity: "info".into(),
                category: "OT Discovery".into(),
                description: format!("{} service listening on port {}", proto, l.port),
                evidence: format!("{}:{} ({})", l.address, l.port, l.process.as_deref().unwrap_or("unknown")),
            });
        }
    }

    EndpointReport {
        hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
        os: System::name().unwrap_or_else(|| "unknown".into()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".into()),
        arch: std::env::consts::ARCH.into(),
        uptime_secs: System::uptime(),
        cpu_count: sys.cpus().len(),
        memory_total_mb: sys.total_memory() / 1024 / 1024,
        memory_used_mb: sys.used_memory() / 1024 / 1024,
        processes: procs,
        listeners,
        connections,
        software: pkgs,
        findings,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    }
}
