mod config;
mod firewall;
mod ipspace;
mod matcher;
mod tracker;
mod tui;
mod watcher;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process;
use std::time::Instant;

use config::{ ip_to_subnet_cidr, parse_duration_secs, Cidr, Config };
use firewall::Firewall;
use matcher::IpKey;
use tracker::{ BanDecision, IpTracker };

fn print_usage() {
    eprintln!(
        "kiban v0.1.0 — Ultra-lightweight Fail2Ban alternative (Rust + nftables + ip.space.ua)\n\
         \n\
         USAGE:\n\
           kiban [tui] [-c <kiban.conf>]                   Launch interactive fzf TUI console\n\
           kiban run [-c <kiban.conf>] [--dry-run]         Start the event-driven protection daemon\n\
           kiban status [-c <kiban.conf>]                  Show active jails, nftables bans & counters\n\
           kiban lookup <IP> [reason] [action]             Query ip.space.ua threat verdict for an IP\n\
           kiban preview <IP> [-c <kiban.conf>]            Display full IP dossier & log evidence\n\
           kiban ban <IP> [duration] [-c <kiban.conf>]     Ban an IPv4/IPv6 address (or update timeout)\n\
           kiban unban <IP> [-c <kiban.conf>]              Unban an IPv4 or IPv6 (/64) address\n\
           kiban whitelist <add|remove|list> [IP/CIDR]     Manage whitelist entries & reload daemon\n\
           kiban flush [-c <kiban.conf>]                   Flush all active bans from nftables sets\n\
           kiban test [-c <kiban.conf>] <logfile>          Dry-run log parser & tracker on a log file\n\
           kiban benchmark [num_lines]                     Run zero-alloc speed & RAM footprint benchmark\n\
           kiban print-nft [-c <kiban.conf>]               Print generated nftables ruleset\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        if let Err(e) = dispatch("tui", &[]) {
            eprintln!("[kiban] error: {e}");
            process::exit(1);
        }
        return;
    }

    let subcmd = args[0].as_str();
    if subcmd == "-h" || subcmd == "--help" || subcmd == "help" {
        print_usage();
        return;
    }

    if let Err(e) = dispatch(subcmd, &args[1..]) {
        eprintln!("[kiban] error: {e}");
        process::exit(1);
    }
}

fn dispatch(subcmd: &str, rest: &[String]) -> Result<(), String> {
    let (config_path, dry_run_flag, positional) = parse_common_flags(rest)?;

    let resolved_path: Option<String> = match config_path {
        Some(p) => Some(p),
        None => {
            if std::path::Path::new("/etc/kiban/kiban.conf").exists() {
                Some("/etc/kiban/kiban.conf".to_string())
            } else if std::path::Path::new("kiban.conf").exists() {
                Some("kiban.conf".to_string())
            } else {
                None
            }
        }
    };

    let mut cfg = match resolved_path {
        Some(ref p) => Config::load_from_file(p)?,
        None => Config::default(),
    };
    if dry_run_flag {
        cfg.dry_run = true;
    }

    let conf_file_str = resolved_path.as_deref().unwrap_or("/etc/kiban/kiban.conf");

    match subcmd {
        "tui" | "ui" => tui::run_tui(&mut cfg, conf_file_str),
        "preview" => {
            let target = positional.first().map(|s| s.as_str()).unwrap_or("");
            tui::run_preview(&cfg, target)
        }
        "whitelist" | "wl" => {
            let op = positional
                .first()
                .map(|s| s.as_str())
                .unwrap_or("list");
            match op {
                "list" | "ls" => {
                    for cidr in &cfg.whitelist {
                        println!("{}", cidr.to_string_repr());
                    }
                    Ok(())
                }
                "add" => {
                    let raw = positional
                        .get(1)
                        .ok_or_else(|| "usage: kiban whitelist add <IP_OR_CIDR> [--subnet]".to_string())?;
                    let as_subnet = positional.iter().any(|a| a == "--subnet" || a == "-s");
                    let cidr_str = if as_subnet {
                        ip_to_subnet_cidr(raw)?
                    } else {
                        config::normalize_cidr_str(raw)?
                    };
                    let fw = Firewall::new(&cfg);
                    if let Ok(cidr) = Cidr::parse(&cidr_str) {
                        let _ = fw.unban_matching_cidr(cidr);
                    }
                    if let Ok(ip_key) = parse_cli_ip(raw) {
                        let _ = fw.unban_single(ip_key);
                    }
                    let (canonical, added) = Config::add_whitelist_to_file(conf_file_str, &cidr_str)?;
                    tui::reload_daemon_sighup();
                    if added {
                        println!("Added {} to whitelist in {} and reloaded kiban.", canonical, conf_file_str);
                    } else {
                        println!("{} is already in whitelist ({}).", canonical, conf_file_str);
                    }
                    Ok(())
                }
                "remove" | "del" | "rm" => {
                    let raw = positional
                        .get(1)
                        .ok_or_else(|| "usage: kiban whitelist remove <IP_OR_CIDR>".to_string())?;
                    let (canonical, removed) = Config::remove_whitelist_from_file(conf_file_str, raw)?;
                    tui::reload_daemon_sighup();
                    if removed {
                        println!("Removed {} from whitelist in {} and reloaded kiban.", canonical, conf_file_str);
                    } else {
                        println!("{} was not found in whitelist ({}).", canonical, conf_file_str);
                    }
                    Ok(())
                }
                other => Err(format!("unknown whitelist action '{other}' (expected add, remove, or list)")),
            }
        }
        "run" | "daemon" => watcher::run_daemon(&mut cfg, resolved_path.as_deref()),
        "lookup" | "check" => {
            let ip_str = positional
                .first()
                .ok_or_else(|| "usage: kiban lookup <IP> [reason] [action]".to_string())?;
            let reason = positional.get(1).map(|s| s.as_str()).unwrap_or("SSH");
            let action = positional.get(2).map(|s| s.as_str()).unwrap_or("check");
            let ip = parse_cli_ip(ip_str)?;
            let verdict = ipspace::query_ip(&cfg.ipspace, ip, reason, action, cfg.dry_run)?;
            println!(
                "IP: {} | action={} | recommendedAction={} | recommendedTtl={}s | riskScore={} | country={} | lists={} | whitelisted={} | instant_ban={}",
                ipspace::format_ip_for_api(ip),
                verdict.action,
                verdict.recommended_action,
                verdict.recommended_ttl,
                verdict.risk_score,
                verdict.country_code,
                verdict.num_lists_found,
                verdict.is_whitelisted,
                verdict.should_ban_immediately(cfg.ipspace.risk_threshold)
            );
            Ok(())
        }
        "test" | "test-log" => {
            let log_path = positional
                .first()
                .ok_or_else(|| "missing <logfile> argument for 'kiban test'".to_string())?;
            run_test_log(&cfg, log_path)
        }
        "benchmark" | "bench" => {
            let num_lines: usize = positional
                .first()
                .map(|s| s.parse().unwrap_or(1_000_000))
                .unwrap_or(1_000_000);
            run_benchmark(&cfg, num_lines)
        }
        "status" => {
            println!("=== kiban Jails & Configuration ===");
            println!(
                "ip.space.ua API : {} (endpoint={}, source={}, risk_threshold={})",
                if cfg.ipspace.enabled { "ENABLED" } else { "disabled" },
                cfg.ipspace.endpoint,
                cfg.ipspace.source,
                cfg.ipspace.risk_threshold
            );
            println!("Whitelist CIDRs : {}", cfg.whitelist.len());
            for j in &cfg.jails {
                let state = if j.enabled { "ACTIVE" } else { "disabled" };
                let srcs: Vec<String> = j
                    .sources
                    .iter()
                    .map(|s| match s {
                        config::LogSource::File(p) => format!("file:{p}"),
                        config::LogSource::Journal(u) => format!("journal:{u}"),
                    })
                    .collect();
                println!(
                    "  - [{}] {:<12} reason={:<6} maxretry={} findtime={}s bantime={}s sources=[{}]",
                    state,
                    j.name,
                    j.reason,
                    j.maxretry,
                    j.findtime_secs,
                    j.bantime_secs,
                    srcs.join(", ")
                );
            }
            println!("\n=== Active Kernel Bans & Drop Counters (nftables) ===");
            let fw = Firewall::new(&cfg);
            let out = fw.status()?;
            print!("{out}");
            Ok(())
        }
        "ban" => {
            let ip_str = positional
                .first()
                .ok_or_else(|| "usage: kiban ban <IP> [duration]".to_string())?;
            let duration_secs = match positional.get(1) {
                Some(d) => parse_duration_secs(d)?,
                None => 3600,
            };
            let ip = parse_cli_ip(ip_str)?;
            let mut fw = Firewall::new(&cfg);
            fw.ban_single(ip, duration_secs)?;
            println!("Banned {} for {}s", ip.format_nft(), duration_secs);
            Ok(())
        }
        "unban" => {
            let ip_str = positional
                .first()
                .ok_or_else(|| "usage: kiban unban <IP>".to_string())?;
            let ip = parse_cli_ip(ip_str)?;
            let fw = Firewall::new(&cfg);
            fw.unban_single(ip)?;
            println!("Unbanned {}", ip.format_nft());
            Ok(())
        }
        "flush" => {
            let fw = Firewall::new(&cfg);
            fw.flush_sets()?;
            println!("Flushed all active bans in table {} {}", cfg.nft_family, cfg.nft_table);
            Ok(())
        }
        "print-nft" => {
            let fw = Firewall::new(&cfg);
            print!("{}", fw.build_init_script());
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'. Run 'kiban --help' for usage.")),
    }
}

fn parse_common_flags(args: &[String]) -> Result<(Option<String>, bool, Vec<String>), String> {
    let mut config_path = None;
    let mut dry_run = false;
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing path after -c/--config".to_string());
                }
                config_path = Some(args[i].clone());
            }
            "--dry-run" | "-n" => {
                dry_run = true;
            }
            arg => positional.push(arg.to_string()),
        }
        i += 1;
    }

    Ok((config_path, dry_run, positional))
}

fn parse_cli_ip(s: &str) -> Result<IpKey, String> {
    let clean = s.trim().strip_suffix("/64").unwrap_or(s.trim());
    let addr: IpAddr = clean
        .parse()
        .map_err(|_| format!("invalid IP address '{s}'"))?;
    Ok(IpKey::from_ip_addr(addr))
}

fn run_test_log(cfg: &Config, log_path: &str) -> Result<(), String> {
    let file = File::open(log_path)
        .map_err(|e| format!("failed to open log file '{log_path}': {e}"))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut tracker = IpTracker::new(cfg.max_tracked_ips);

    let matched_jails: Vec<usize> = (0..cfg.jails.len())
        .filter(|&i| {
            cfg.jails[i].enabled
                && cfg.jails[i].sources.iter().any(|s| match s {
                    config::LogSource::File(p) => p == log_path,
                    _ => false,
                })
        })
        .collect();

    let all_jails: Vec<usize> = if !matched_jails.is_empty() {
        matched_jails
    } else {
        (0..cfg.jails.len())
            .filter(|&i| cfg.jails[i].enabled)
            .collect()
    };

    let mut line_buf = Vec::with_capacity(1024);
    let mut total_lines: u64 = 0;
    let mut pending_bans: Vec<BanDecision> = Vec::new();
    let start = Instant::now();

    loop {
        line_buf.clear();
        let n = reader
            .read_until(b'\n', &mut line_buf)
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        total_lines += 1;
        let mut slice = &line_buf[..];
        if slice.ends_with(b"\n") {
            slice = &slice[..slice.len() - 1];
        }
        if slice.ends_with(b"\r") {
            slice = &slice[..slice.len() - 1];
        }
        watcher::evaluate_line_offline(cfg, &mut tracker, &all_jails, slice, 100, &mut pending_bans);
    }

    let elapsed = start.elapsed();
    for ban in &pending_bans {
        let jail_name = &cfg.jails[ban.jail_id as usize].name;
        println!(
            "[BAN] ip={} jail={} bantime={}s failures={} strike={}",
            ban.ip.format_nft(),
            jail_name,
            ban.bantime_secs,
            ban.failures,
            ban.strikes
        );
    }

    let secs = elapsed.as_secs_f64().max(1e-9);
    let lines_per_sec = (total_lines as f64) / secs;
    println!(
        "---\nProcessed {} lines in {:.3} ms ({:.0} lines/sec) | offenses={} | bans={} | RSS={} KB",
        total_lines,
        secs * 1000.0,
        lines_per_sec,
        tracker.total_events,
        tracker.total_bans,
        watcher::read_current_rss_kb().unwrap_or(0)
    );
    Ok(())
}

fn run_benchmark(cfg: &Config, num_lines: usize) -> Result<(), String> {
    let mut tracker = IpTracker::new(cfg.max_tracked_ips);
    let all_jails: Vec<usize> = (0..cfg.jails.len())
        .filter(|&i| cfg.jails[i].enabled)
        .collect();

    const SAMPLE_LINES: &[&[u8]] = &[
        b"Oct 20 14:22:01 srv sshd[1200]: Accepted publickey for deploy from 10.0.0.5 port 51200 ssh2",
        b"198.51.100.1 - - [20/Oct/2026:14:30:01 +0300] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"",
        b"198.51.100.2 - - [20/Oct/2026:14:30:01 +0300] \"GET /assets/app.css HTTP/1.1\" 200 4096 \"-\" \"Mozilla/5.0\"",
        b"Oct 20 14:22:03 srv sshd[1234]: Failed password for root from 203.0.113.42 port 51234 ssh2",
        b"Oct 20 14:22:04 srv sshd[1235]: Invalid user admin from 2001:db8:abcd:1234::99 port 49000 ssh2",
        b"198.51.100.55 - - [20/Oct/2026:14:30:05 +0300] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.0\"",
        b"203.0.113.99 - - [20/Oct/2026:14:30:06 +0300] \"POST /api/login HTTP/2.0\" 401 42 \"-\" \"Mozilla/5.0\"",
        b"198.51.100.3 - - [20/Oct/2026:14:30:07 +0300] \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"kube-probe\"",
    ];

    let mut pending_bans = Vec::with_capacity(64);
    let start = Instant::now();

    for i in 0..num_lines {
        let line = SAMPLE_LINES[i & (SAMPLE_LINES.len() - 1)];
        let now_secs = 100 + ((i >> 10) as u32);
        watcher::evaluate_line_offline(cfg, &mut tracker, &all_jails, line, now_secs, &mut pending_bans);
        if pending_bans.len() >= 32 {
            pending_bans.clear();
        }
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-9);
    let throughput = (num_lines as f64) / secs;
    let ns_per_line = (elapsed.as_nanos() as f64) / (num_lines as f64);
    let rss_kb = watcher::read_current_rss_kb().unwrap_or(0);

    println!("=== kiban Benchmark Results ===");
    println!("Lines processed   : {}", num_lines);
    println!("Elapsed time      : {:.2} ms", secs * 1000.0);
    println!("Throughput        : {:.0} lines/sec", throughput);
    println!("Latency per line  : {:.1} ns/line", ns_per_line);
    println!("Offenses matched  : {}", tracker.total_events);
    println!("Bans triggered    : {}", tracker.total_bans);
    println!(
        "Tracker table RAM : {} KB ({} slots x 24 B, {} occupied)",
        tracker.memory_bytes() / 1024,
        tracker.capacity(),
        tracker.occupied_count()
    );
    println!(
        "Process VmRSS     : {} KB ({:.2} MB)",
        rss_kb,
        (rss_kb as f64) / 1024.0
    );

    Ok(())
}
