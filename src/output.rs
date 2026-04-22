//! Output formatting.
use crate::EndpointReport;
use colored::Colorize;

pub fn print_report(r: &EndpointReport) {
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());
    eprintln!("  {} {} ({})", "HOST".green().bold(), r.hostname.white(), r.os);
    eprintln!("  OS: {} {} | Arch: {} | CPUs: {} | RAM: {}/{}MB",
        r.os, r.os_version, r.arch, r.cpu_count, r.memory_used_mb, r.memory_total_mb);
    eprintln!("  Uptime: {}h", r.uptime_secs / 3600);
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());

    eprintln!("\n  {} {}", "Processes:".white().bold(), r.processes.len());
    let top: Vec<_> = {
        let mut sorted = r.processes.clone();
        sorted.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(10).collect()
    };
    for p in &top {
        eprintln!("    {:>6} {:<20} CPU:{:>5.1}% MEM:{:>4}MB", p.pid, p.name, p.cpu_percent, p.memory_mb);
    }

    eprintln!("\n  {} {}", "Listeners:".white().bold(), r.listeners.len());
    for l in &r.listeners {
        eprintln!("    {}:{} ({}) {}", l.address, l.port.to_string().yellow(), l.protocol, l.process.as_deref().unwrap_or(""));
    }

    eprintln!("\n  {} {}", "Software:".white().bold(), r.software.len());

    if !r.findings.is_empty() {
        eprintln!("\n  {} {}", "Findings:".red().bold(), r.findings.len());
        for f in &r.findings {
            let sev = match f.severity.as_str() {
                "critical" => "CRIT".red().bold().to_string(),
                "high" => "HIGH".yellow().bold().to_string(),
                _ => "INFO".dimmed().to_string(),
            };
            eprintln!("    [{}] {} — {}", sev, f.title, f.evidence.dimmed());
        }
    }
}
