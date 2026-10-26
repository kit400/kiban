use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::config::{
    ip_to_subnet_cidr, normalize_cidr_str, parse_duration_secs, Cidr, Config, LogSource,
};
use crate::firewall::Firewall;
use crate::ipspace;
use crate::matcher::IpKey;

#[derive(Debug, Clone)]
struct JournalBanMeta {
    jail: String,
    bantime: String,
    failures: String,
    strike: String,
    via: String,
    timestamp: String,
}

/// Runs the interactive `fzf`-powered TUI console.
pub fn run_tui(cfg: &mut Config, config_path: &str) -> Result<(), String> {
    let self_exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/kiban".to_string());

    let mut status_banner = String::from(
        "Ready. Use Up/Down to browse, Tab to multi-select, Enter for Action Menu, or Ctrl-* hotkeys.",
    );

    loop {
        // Reload config on each refresh so whitelist changes are reflected immediately
        if let Ok(fresh) = Config::load_from_file(config_path) {
            *cfg = fresh;
        }

        let rows = build_fzf_rows(cfg);
        let preview_cmd = format!("{} preview {{2}} -c '{}'", self_exe, config_path);
        let header = format!(
            "{}\n\
             [Enter] Action Menu  [Tab] Multi  [Ctrl-U] Unban  [Ctrl-W] White IP  [Ctrl-N] White /24  [Ctrl-E] Ban Time  [Ctrl-B] New Ban  [Ctrl-R] Refresh  [Esc] Quit\n\
             {:<9} {:<18} {:<11} {:<7} {:<12} {}",
            status_banner, "STATE", "IP / CIDR", "JAIL", "TIMEOUT", "EXPIRES", "DETAILS"
        );

        let Some((key, selected_lines)) = run_fzf_selector(
            &rows,
            "kiban> ",
            &header,
            Some(&preview_cmd),
            true,
            Some("enter,ctrl-u,ctrl-w,ctrl-n,ctrl-e,ctrl-b,ctrl-r"),
        )?
        else {
            // User pressed Esc or Ctrl-C
            break;
        };

        if key == "ctrl-r" {
            status_banner = "Refreshed active bans and whitelist.".to_string();
            continue;
        }

        if key == "ctrl-b" {
            status_banner = prompt_and_ban_new_ip(cfg)?;
            continue;
        }

        let targets = extract_targets_from_lines(&selected_lines);
        if targets.is_empty() {
            continue;
        }

        if targets.iter().any(|(_, ip)| ip == "+ban-or-whitelist") && key == "enter" {
            status_banner = handle_plus_new_menu(cfg, config_path)?;
            continue;
        }

        match key.as_str() {
            "ctrl-u" => {
                status_banner = action_unban_targets(cfg, &targets);
            }
            "ctrl-w" => {
                status_banner = action_whitelist_ips(cfg, config_path, &targets, false);
            }
            "ctrl-n" => {
                status_banner = action_whitelist_ips(cfg, config_path, &targets, true);
            }
            "ctrl-e" => {
                if let Some(dur_secs) = select_duration_fzf()? {
                    status_banner = action_set_ban_duration(cfg, &targets, dur_secs);
                }
            }
            _ => {
                // Default (`enter`): open context-aware action menu for selected target(s)
                if let Some(msg) = open_action_menu(cfg, config_path, &targets)? {
                    status_banner = msg;
                }
            }
        }
    }

    Ok(())
}

/// Generates the right-side preview output (`kiban preview <IP_OR_CIDR>`) for `fzf`.
pub fn run_preview(cfg: &Config, raw_target: &str) -> Result<(), String> {
    let target = strip_ansi(raw_target).trim().to_string();
    if target.is_empty() || target == "+ban-or-whitelist" {
        println!("\x1b[1;36m=== Manual Entry Actions ===\x1b[0m");
        println!("Press \x1b[1;32mEnter\x1b[0m on this row (or press \x1b[1;33mCtrl-B\x1b[0m anywhere) to:");
        println!("  • Manually ban a new IPv4 / IPv6 address with a custom timeout");
        println!("  • Manually add a new IP or CIDR subnet to /etc/kiban/kiban.conf whitelist");
        return Ok(());
    }

    let fw = Firewall::new(cfg);
    let active_bans = fw.list_active_bans().unwrap_or_default();
    let base_ip_str = target.split('/').next().unwrap_or(&target);

    println!("\x1b[1;36m=== Target: {} ===\x1b[0m", target);

    // 1. Check active kernel nftables status & whitelist coverage
    if let Some(active) = active_bans
        .iter()
        .find(|b| b.ip_str == target || b.ip_str == base_ip_str)
    {
        println!(
            "  Kernel Status      : \x1b[1;31mBANNED in nftables\x1b[0m (timeout={}, expires={})",
            active.timeout, active.expires
        );
    } else {
        println!("  Kernel Status      : \x1b[32mNot currently in nftables blacklist\x1b[0m");
    }

    if let Ok(subnet) = ip_to_subnet_cidr(&target) {
        println!("  Subnet (/24 | /64) : {}", subnet);
    }

    if let Ok(addr) = base_ip_str.parse::<IpAddr>() {
        let key = IpKey::from_ip_addr(addr);
        let wl = match key {
            IpKey::V4(v4) => cfg.is_whitelisted_v4(v4),
            IpKey::V6Prefix64(p64) => cfg.is_whitelisted_v6_prefix64(p64),
        };
        if wl {
            println!("  Whitelist Status   : \x1b[1;32mWHITELISTED in kiban.conf\x1b[0m");
        } else {
            println!("  Whitelist Status   : Not whitelisted");
        }

        // 2. Threat Intelligence Dossier from ip.space.ua (for public IPs)
        if !addr.is_loopback() && !is_private_ip(addr) && !cfg.ipspace.token.is_empty() {
            println!("\n\x1b[1;35m=== ip.space.ua Threat Intelligence ===\x1b[0m");
            match ipspace::fetch_dossier_summary(&cfg.ipspace, key) {
                Ok(dossier) => println!("{dossier}"),
                Err(e) => println!("  Lookup note: {e}"),
            }
        }
    }

    // 3. kiban Daemon Journal History for this IP
    println!("\n\x1b[1;33m=== kiban Ban History (journalctl) ===\x1b[0m");
    let journal_matches = grep_journal_for_ip(base_ip_str, 8);
    if journal_matches.is_empty() {
        println!("  (no recorded ban events in journald)");
    } else {
        for line in journal_matches {
            println!("  {line}");
        }
    }

    // 4. Recent Log Evidence across configured jail log files
    println!("\n\x1b[1;34m=== Recent Log Evidence ===\x1b[0m");
    let log_matches = grep_jail_logs_for_ip(cfg, base_ip_str, 10);
    if log_matches.is_empty() {
        println!("  (no recent matching lines in watched log files)");
    } else {
        for line in log_matches {
            println!("  {line}");
        }
    }

    Ok(())
}

fn build_fzf_rows(cfg: &Config) -> Vec<String> {
    let fw = Firewall::new(cfg);
    let active_bans = fw.list_active_bans().unwrap_or_default();
    let journal_map = collect_journal_ban_history();

    let mut rows = Vec::new();
    let mut seen_ips = Vec::new();

    // 1. Active bans from nftables
    for b in &active_bans {
        seen_ips.push(b.ip_str.clone());
        let (jail, details) = if let Some(meta) = journal_map.get(&b.ip_str) {
            (
                meta.jail.as_str(),
                format!(
                    "via={} failures={} strike={} ({})",
                    meta.via, meta.failures, meta.strike, meta.timestamp
                ),
            )
        } else {
            ("manual/nft", "active kernel set element".to_string())
        };

        let clean_expires = trim_expires_ms(&b.expires);
        rows.push(format!(
            "\x1b[1;31m{:<9}\x1b[0m {:<18} {:<11} {:<7} {:<12} {}",
            "[BANNED]", b.ip_str, jail, b.timeout, clean_expires, details
        ));
    }

    // 2. Historical bans from journald that are not currently active in nftables
    for (ip_str, meta) in &journal_map {
        if seen_ips.contains(ip_str) {
            continue;
        }
        rows.push(format!(
            "\x1b[33m{:<9}\x1b[0m {:<18} {:<11} {:<7} {:<12} via={} failures={} strike={} ({})",
            "[HIST]",
            ip_str,
            meta.jail,
            meta.bantime,
            "expired",
            meta.via,
            meta.failures,
            meta.strike,
            meta.timestamp
        ));
    }

    // 3. Whitelisted CIDRs from kiban.conf
    for cidr in &cfg.whitelist {
        let repr = cidr.to_string_repr();
        rows.push(format!(
            "\x1b[1;32m{:<9}\x1b[0m {:<18} {:<11} {:<7} {:<12} trusted whitelist CIDR in kiban.conf",
            "[WHITE]", repr, "whitelist", "-", "permanent"
        ));
    }

    // 4. Manual entry helper row
    rows.push(format!(
        "\x1b[1;36m{:<9}\x1b[0m {:<18} {:<11} {:<7} {:<12} Ban a new IP or add a new CIDR to whitelist",
        "[+NEW]", "+ban-or-whitelist", "-", "-", "-"
    ));

    rows
}

fn open_action_menu(
    cfg: &mut Config,
    config_path: &str,
    targets: &[(String, String)],
) -> Result<Option<String>, String> {
    let label = if targets.len() == 1 {
        targets[0].1.clone()
    } else {
        format!("{} selected targets", targets.len())
    };

    let sample_ip = &targets[0].1;
    let subnet_hint = ip_to_subnet_cidr(sample_ip).unwrap_or_else(|_| "/24 or /64".to_string());

    let menu_items = vec![
        format!("1. unban       | Unban {} from nftables", label),
        format!(
            "2. white-ip    | Unban + Add IP ({}) to Whitelist in kiban.conf",
            label
        ),
        format!(
            "3. white-net   | Unban + Add Network Subnet ({}) to Whitelist",
            subnet_hint
        ),
        format!(
            "4. extend      | Change / Extend Ban Duration for {} (15m..365d)",
            label
        ),
        format!(
            "5. reban       | Ban {} + Report action=ban to ip.space.ua",
            label
        ),
        format!(
            "6. del-white   | Remove {} from Whitelist in kiban.conf",
            label
        ),
        "7. new-ban     | Manually Ban a New IP Address".to_string(),
        "8. back        | Return to Main List".to_string(),
    ];

    let header = format!("Select action for {}:", label);
    let Some((_, chosen)) = run_fzf_selector(&menu_items, "action> ", &header, None, false, None)?
    else {
        return Ok(None);
    };

    let Some(first) = chosen.first() else {
        return Ok(None);
    };

    if first.starts_with("1.") {
        Ok(Some(action_unban_targets(cfg, targets)))
    } else if first.starts_with("2.") {
        Ok(Some(action_whitelist_ips(cfg, config_path, targets, false)))
    } else if first.starts_with("3.") {
        Ok(Some(action_whitelist_ips(cfg, config_path, targets, true)))
    } else if first.starts_with("4.") {
        if let Some(dur) = select_duration_fzf()? {
            Ok(Some(action_set_ban_duration(cfg, targets, dur)))
        } else {
            Ok(None)
        }
    } else if first.starts_with("5.") {
        if let Some(dur) = select_duration_fzf()? {
            let msg = action_set_ban_duration(cfg, targets, dur);
            for (_, ip_str) in targets {
                if let Some(key) = parse_target_ip_key(ip_str) {
                    ipspace::report_ban_async(&cfg.ipspace, key, "MANUAL", cfg.dry_run);
                }
            }
            Ok(Some(format!("{msg} (reported action=ban to ip.space.ua)")))
        } else {
            Ok(None)
        }
    } else if first.starts_with("6.") {
        Ok(Some(action_remove_whitelist(config_path, targets)))
    } else if first.starts_with("7.") {
        Ok(Some(prompt_and_ban_new_ip(cfg)?))
    } else {
        Ok(None)
    }
}

fn handle_plus_new_menu(cfg: &mut Config, config_path: &str) -> Result<String, String> {
    let items = vec![
        "1. Ban a new IPv4 / IPv6 address".to_string(),
        "2. Add a new IP or CIDR subnet to Whitelist".to_string(),
        "3. Cancel".to_string(),
    ];
    let Some((_, chosen)) =
        run_fzf_selector(&items, "new> ", "Choose operation:", None, false, None)?
    else {
        return Ok("Cancelled.".to_string());
    };
    let Some(first) = chosen.first() else {
        return Ok("Cancelled.".to_string());
    };
    if first.starts_with("1.") {
        prompt_and_ban_new_ip(cfg)
    } else if first.starts_with("2.") {
        print!("Enter IP or CIDR to whitelist (e.g. 203.0.113.50 or 203.0.113.0/24): ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok("Cancelled (empty input).".to_string());
        }
        let targets = vec![("[WHITE]".to_string(), trimmed.to_string())];
        Ok(action_whitelist_ips(cfg, config_path, &targets, false))
    } else {
        Ok("Cancelled.".to_string())
    }
}

fn select_duration_fzf() -> Result<Option<u32>, String> {
    let presets = vec![
        "15m   | 900 seconds (15 minutes)".to_string(),
        "1h    | 3600 seconds (1 hour)".to_string(),
        "6h    | 21600 seconds (6 hours)".to_string(),
        "24h   | 86400 seconds (1 day)".to_string(),
        "3d    | 259200 seconds (3 days)".to_string(),
        "7d    | 604800 seconds (1 week)".to_string(),
        "30d   | 2592000 seconds (1 month)".to_string(),
        "90d   | 7776000 seconds (3 months)".to_string(),
        "365d  | 31536000 seconds (1 year)".to_string(),
        "custom| Enter custom duration (e.g. 45m, 12h, 14d)".to_string(),
    ];

    let Some((_, chosen)) = run_fzf_selector(
        &presets,
        "duration> ",
        "Select new ban duration:",
        None,
        false,
        None,
    )?
    else {
        return Ok(None);
    };

    let Some(first) = chosen.first() else {
        return Ok(None);
    };
    let token = first.split('|').next().unwrap_or("").trim();
    if token == "custom" {
        print!("Enter custom ban duration (e.g. 30m, 12h, 14d): ");
        let _ = io::stdout().flush();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        let d = parse_duration_secs(buf.trim())?;
        Ok(Some(d))
    } else {
        Ok(Some(parse_duration_secs(token)?))
    }
}

fn prompt_and_ban_new_ip(cfg: &Config) -> Result<String, String> {
    print!("Enter IPv4 or IPv6 address to ban: ");
    let _ = io::stdout().flush();
    let mut ip_input = String::new();
    io::stdin()
        .read_line(&mut ip_input)
        .map_err(|e| e.to_string())?;
    let ip_trimmed = ip_input.trim();
    if ip_trimmed.is_empty() {
        return Ok("Cancelled (empty IP).".to_string());
    }
    let key = parse_target_ip_key(ip_trimmed)
        .ok_or_else(|| format!("invalid IP address '{ip_trimmed}'"))?;

    let Some(dur_secs) = select_duration_fzf()? else {
        return Ok("Cancelled duration selection.".to_string());
    };

    let mut fw = Firewall::new(cfg);
    fw.ban_single(key, dur_secs)?;
    ipspace::report_ban_async(&cfg.ipspace, key, "MANUAL", cfg.dry_run);
    Ok(format!(
        "Banned {} for {}s and reported to ip.space.ua.",
        key.format_nft(),
        dur_secs
    ))
}

fn action_unban_targets(cfg: &Config, targets: &[(String, String)]) -> String {
    let fw = Firewall::new(cfg);
    let mut ok_count = 0;
    let mut last_err = None;

    for (_, ip_str) in targets {
        if let Some(key) = parse_target_ip_key(ip_str) {
            match fw.unban_single(key) {
                Ok(()) => ok_count += 1,
                Err(e) => last_err = Some(e),
            }
        }
    }

    if ok_count > 0 {
        format!("Unbanned {ok_count} IP(s) from nftables.")
    } else if let Some(e) = last_err {
        format!("Unban note: {e}")
    } else {
        "No active ban elements matched.".to_string()
    }
}

fn action_set_ban_duration(
    cfg: &Config,
    targets: &[(String, String)],
    dur_secs: u32,
) -> String {
    let mut fw = Firewall::new(cfg);
    let mut updated = 0;
    let mut last_err = None;

    for (_, ip_str) in targets {
        if let Some(key) = parse_target_ip_key(ip_str) {
            match fw.ban_single(key, dur_secs) {
                Ok(()) => updated += 1,
                Err(e) => last_err = Some(e),
            }
        }
    }

    if updated > 0 {
        format!("Updated ban duration to {dur_secs}s for {updated} IP(s).")
    } else if let Some(e) = last_err {
        format!("Failed to update ban duration: {e}")
    } else {
        "No valid IP targets selected.".to_string()
    }
}

fn action_whitelist_ips(
    cfg: &Config,
    config_path: &str,
    targets: &[(String, String)],
    as_subnet: bool,
) -> String {
    let fw = Firewall::new(cfg);
    let mut added_list = Vec::new();
    let mut unbanned_count = 0;

    for (_, ip_str) in targets {
        let cidr_res = if as_subnet {
            ip_to_subnet_cidr(ip_str)
        } else {
            normalize_cidr_str(ip_str)
        };

        let Ok(cidr_str) = cidr_res else {
            continue;
        };

        if let Ok(cidr) = Cidr::parse(&cidr_str) {
            if let Ok(n) = fw.unban_matching_cidr(cidr) {
                unbanned_count += n;
            }
        }
        if let Some(key) = parse_target_ip_key(ip_str) {
            if fw.unban_single(key).is_ok() {
                unbanned_count += 1;
            }
        }

        if let Ok((canonical, _)) = Config::add_whitelist_to_file(config_path, &cidr_str) {
            added_list.push(canonical);
        }
    }

    reload_daemon_sighup();

    if added_list.is_empty() {
        "No valid IP/CIDR targets to whitelist.".to_string()
    } else {
        format!(
            "Whitelisted [{}] in {} (unbanned {} active element(s), sent SIGHUP to kiban).",
            added_list.join(", "),
            config_path,
            unbanned_count
        )
    }
}

fn action_remove_whitelist(config_path: &str, targets: &[(String, String)]) -> String {
    let mut removed = Vec::new();
    for (_, ip_str) in targets {
        if let Ok((canonical, true)) = Config::remove_whitelist_from_file(config_path, ip_str) {
            removed.push(canonical);
        }
    }
    reload_daemon_sighup();
    if removed.is_empty() {
        "Entry was not in whitelist.".to_string()
    } else {
        format!(
            "Removed [{}] from whitelist in {} (sent SIGHUP to kiban).",
            removed.join(", "),
            config_path
        )
    }
}

/// Sends `SIGHUP` strictly to the running `kiban.service` daemon so it reloads `kiban.conf` in-place
/// without signaling the current CLI/TUI process.
pub fn reload_daemon_sighup() {
    let _ = Command::new("systemctl")
        .args(["kill", "-s", "HUP", "--kill-who=main", "kiban.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn run_fzf_selector(
    rows: &[String],
    prompt: &str,
    header: &str,
    preview_cmd: Option<&str>,
    multi: bool,
    expect_keys: Option<&str>,
) -> Result<Option<(String, Vec<String>)>, String> {
    let mut cmd = Command::new("fzf");
    cmd.args([
        "--ansi",
        "--exact",
        "--no-hscroll",
        "--layout=reverse",
        "--height=95%",
        "--border=rounded",
        "--info=inline",
        "--prompt",
        prompt,
        "--header",
        header,
    ]);

    if multi {
        cmd.arg("--multi");
    }
    if let Some(exp) = expect_keys {
        cmd.arg("--expect").arg(exp);
    }
    if let Some(prev) = preview_cmd {
        cmd.arg("--nth=1,2,3");
        cmd.arg("--preview").arg(prev);
        cmd.arg("--preview-window=right:52%:wrap");
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to launch 'fzf' (is /usr/bin/fzf installed?): {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = rows.join("\n");
        let _ = stdin.write_all(payload.as_bytes());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on fzf: {e}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();

    let key = if expect_keys.is_some() {
        lines.next().unwrap_or("enter").trim().to_string()
    } else {
        "enter".to_string()
    };

    let selected: Vec<String> = lines
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if selected.is_empty() && key != "ctrl-r" && key != "ctrl-b" {
        return Ok(None);
    }

    Ok(Some((key, selected)))
}

fn extract_targets_from_lines(lines: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in lines {
        let clean = strip_ansi(line);
        let cols: Vec<&str> = clean.split_whitespace().collect();
        if cols.len() >= 2 {
            out.push((cols[0].to_string(), cols[1].to_string()));
        }
    }
    out
}

fn parse_target_ip_key(s: &str) -> Option<IpKey> {
    let clean = s.trim().strip_suffix("/64").or_else(|| s.trim().strip_suffix("/32")).or_else(|| s.trim().strip_suffix("/128")).unwrap_or(s.trim());
    let addr: IpAddr = clean.parse().ok()?;
    Some(IpKey::from_ip_addr(addr))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                while let Some(nc) = chars.next() {
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn trim_expires_ms(s: &str) -> String {
    if let Some(s_idx) = s.find('s') {
        if s[s_idx + 1..].ends_with("ms") {
            return s[..=s_idx].to_string();
        }
    }
    s.to_string()
}

fn collect_journal_ban_history() -> HashMap<String, JournalBanMeta> {
    let mut map = HashMap::new();
    let Ok(output) = Command::new("journalctl")
        .args(["-u", "kiban", "-n", "5000", "--no-pager"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return map;
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let Some(ban_idx) = line.find("[kiban] BAN ") else {
            continue;
        };
        let ts = line.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
        let tail = &line[ban_idx + "[kiban] BAN ".len()..];

        let mut ip = String::new();
        let mut jail = String::from("-");
        let mut bantime = String::from("-");
        let mut failures = String::from("1");
        let mut strike = String::from("1");
        let mut via = String::from("local");

        for kv in tail.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "ip" => ip = v.to_string(),
                    "jail" => jail = v.to_string(),
                    "bantime" => bantime = v.to_string(),
                    "failures" => failures = v.to_string(),
                    "strike" => strike = v.to_string(),
                    "via" => via = v.to_string(),
                    _ => {}
                }
            }
        }

        if !ip.is_empty() {
            map.insert(
                ip,
                JournalBanMeta {
                    jail,
                    bantime,
                    failures,
                    strike,
                    via,
                    timestamp: ts,
                },
            );
        }
    }

    map
}

fn grep_journal_for_ip(ip_needle: &str, max_lines: usize) -> Vec<String> {
    let Ok(output) = Command::new("journalctl")
        .args(["-u", "kiban", "-n", "500", "--no-pager"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut matches: Vec<String> = text
        .lines()
        .filter(|l| l.contains(ip_needle))
        .map(|l| l.to_string())
        .collect();
    if matches.len() > max_lines {
        matches = matches.split_off(matches.len() - max_lines);
    }
    matches
}

fn grep_jail_logs_for_ip(cfg: &Config, ip_needle: &str, max_lines: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut searched_files = Vec::new();

    for jail in &cfg.jails {
        for src in &jail.sources {
            if let LogSource::File(path_pattern) = src {
                let paths = crate::config::resolve_file_sources(path_pattern);
                for path in paths {
                    let path_str = path.display().to_string();
                    if searched_files.contains(&path_str) {
                        continue;
                    }
                    searched_files.push(path_str);
                    if let Ok(file) = File::open(&path) {
                        let reader = BufReader::new(file);
                        let mut file_hits = Vec::new();
                        for line in reader.lines().map_while(Result::ok) {
                            if line.contains(ip_needle)
                                && !line.contains("COMMAND=")
                                && !line.contains("\"GET /api?")
                                && !line.contains("\"GET /api/")
                            {
                                file_hits.push(format!("[{}] {}", jail.name, line));
                            }
                        }
                        if file_hits.len() > max_lines {
                            file_hits = file_hits.split_off(file_hits.len() - max_lines);
                        }
                        results.extend(file_hits);
                    }
                }
            }
        }
    }

    if results.len() > max_lines {
        results = results.split_off(results.len() - max_lines);
    }
    results
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}
