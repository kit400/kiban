use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Compact representation of an IPv4 or IPv6 CIDR network for O(1) whitelist checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip_str, prefix_opt) = match s.split_once('/') {
            Some((ip, pref)) => (ip.trim(), Some(pref.trim())),
            None => (s, None),
        };

        let addr: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("invalid IP address in CIDR: '{s}'"))?;

        match addr {
            IpAddr::V4(v4) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p
                        .parse()
                        .map_err(|_| format!("invalid IPv4 prefix length in '{s}'"))?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(format!("IPv4 prefix length out of range (0..=32): '{s}'"));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let network = u32::from(v4) & mask;
                Ok(Cidr::V4 { network, mask })
            }
            IpAddr::V6(v6) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p
                        .parse()
                        .map_err(|_| format!("invalid IPv6 prefix length in '{s}'"))?,
                    None => 128,
                };
                if prefix > 128 {
                    return Err(format!("IPv6 prefix length out of range (0..=128): '{s}'"));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                let network = u128::from(v6) & mask;
                Ok(Cidr::V6 { network, mask })
            }
        }
    }

    #[inline]
    pub fn contains_v4(&self, ip: u32) -> bool {
        match *self {
            Cidr::V4 { network, mask } => (ip & mask) == network,
            Cidr::V6 { .. } => false,
        }
    }

    #[inline]
    pub fn contains_v6(&self, ip: u128) -> bool {
        match *self {
            Cidr::V6 { network, mask } => (ip & mask) == network,
            Cidr::V4 { .. } => false,
        }
    }

    #[inline]
    pub fn contains_v6_prefix64(&self, prefix64: u64) -> bool {
        let full = (prefix64 as u128) << 64;
        self.contains_v6(full)
    }

    pub fn to_string_repr(&self) -> String {
        match *self {
            Cidr::V4 { network, mask } => {
                let prefix = mask.count_ones();
                format!("{}/{}", Ipv4Addr::from(network), prefix)
            }
            Cidr::V6 { network, mask } => {
                let prefix = mask.count_ones();
                format!("{}/{}", Ipv6Addr::from(network), prefix)
            }
        }
    }
}

/// Normalizes an IP or CIDR string into canonical `<network>/<prefix>` format (e.g. `1.2.3.4/32`).
pub fn normalize_cidr_str(s: &str) -> Result<String, String> {
    let cidr = Cidr::parse(s)?;
    Ok(cidr.to_string_repr())
}

/// Converts an IP or CIDR string into its standard subnet CIDR (`/24` for IPv4, `/64` for IPv6).
pub fn ip_to_subnet_cidr(s: &str) -> Result<String, String> {
    let base_ip = s.trim().split('/').next().unwrap_or(s.trim());
    let addr: IpAddr = base_ip
        .parse()
        .map_err(|_| format!("invalid IP address '{s}'"))?;
    match addr {
        IpAddr::V4(v4) => {
            let net = u32::from(v4) & 0xFFFF_FF00;
            Ok(format!("{}/24", Ipv4Addr::from(net)))
        }
        IpAddr::V6(v6) => {
            let net = u128::from(v6) & (!0u128 << 64);
            Ok(format!("{}/64", Ipv6Addr::from(net)))
        }
    }
}

/// Log source definition for a jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    /// Tail a file on disk using Linux `inotify` (handles log rotation automatically).
    File(String),
    /// Follow a `systemd-journald` unit stream (e.g. `sshd.service`).
    Journal(String),
}

impl LogSource {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("file:") {
            let path = rest.trim();
            if path.is_empty() {
                return Err("empty file path in source".to_string());
            }
            Ok(LogSource::File(path.to_string()))
        } else if let Some(rest) = s.strip_prefix("journal:") {
            let unit = rest.trim();
            if unit.is_empty() {
                return Err("empty journal unit in source".to_string());
            }
            Ok(LogSource::Journal(unit.to_string()))
        } else if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
            Ok(LogSource::File(s.to_string()))
        } else {
            Err(format!(
                "invalid source '{s}': expected 'file:/path/to/log' or 'journal:unit.service'"
            ))
        }
    }
}

pub fn glob_matches(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == "*.error.log" {
        return name.ends_with(".error.log");
    }
    if pattern == "*.log" {
        return name.ends_with(".log") && !name.ends_with(".error.log");
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len();
    }
    name == pattern
}

pub fn resolve_file_sources(pattern_path: &str) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let pb = PathBuf::from(pattern_path);
    if pattern_path.contains('*') || pattern_path.contains('?') {
        let parent = pb.parent().unwrap_or_else(|| Path::new("."));
        let pattern = pb.file_name().and_then(|f| f.to_str()).unwrap_or("*");
        let mut list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                        if glob_matches(file_name, pattern) {
                            list.push(path);
                        }
                    }
                }
            }
        }
        list.sort();
        list
    } else {
        vec![pb]
    }
}

/// Built-in or custom log parser profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParserKind {
    /// Built-in zero-allocation OpenSSH (`sshd`) parser.
    Sshd,
    /// Built-in zero-allocation Nginx / Caddy / Apache access log parser (401/403/444 + scanners).
    HttpAccess {
        /// Weight multiplier for known exploit/scanner paths (e.g. `/.env`, `/wp-login.php`).
        scanner_weight: u16,
    },
    /// Built-in zero-allocation Nginx / Apache error log parser.
    HttpError,
    /// Custom substring anchor + token extraction rule (no heavy regex engine required).
    Custom {
        /// Required substring patterns (at least one must match).
        match_any: Vec< Vec<u8> >,
        /// Optional substring patterns that cause the line to be ignored if present.
        ignore_any: Vec< Vec<u8> >,
        /// Optional marker immediately preceding the IP address (e.g. `b"from "` or `b"client: "`).
        /// If empty, the matcher scans the line for the first valid IPv4/IPv6 token.
        ip_after: Vec< Vec<u8> >,
    },
}

/// Configuration for the `ip.space.ua` Threat Intelligence API integration.
#[derive(Debug, Clone)]
pub struct IpSpaceConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub token: String,
    pub source: String,
    pub timeout_secs: u32,
    pub risk_threshold: u8,
    pub report_ban: bool,
}

impl Default for IpSpaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://ip.space.ua/api".to_string(),
            token: String::new(),
            source: "IPrepDB".to_string(),
            timeout_secs: 3,
            risk_threshold: 75,
            report_ban: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JailConfig {
    pub id: u8,
    pub name: String,
    pub reason: String,
    pub enabled: bool,
    pub sources: Vec<LogSource>,
    pub parser: ParserKind,
    pub maxretry: u16,
    pub findtime_secs: u32,
    pub bantime_secs: u32,
    pub bantime_multiplier: u16,
    pub max_bantime_secs: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub nft_table: String,
    pub nft_family: String,
    pub nft_set_v4: String,
    pub nft_set_v6: String,
    pub max_tracked_ips: usize,
    pub dry_run: bool,
    pub whitelist: Vec<Cidr>,
    pub ipspace: IpSpaceConfig,
    pub jails: Vec<JailConfig>,
}

impl Default for Config {
    fn default() -> Self {
        let whitelist = vec![
            Cidr::parse("127.0.0.0/8").unwrap(),
            Cidr::parse("::1/128").unwrap(),
            Cidr::parse("fe80::/10").unwrap(),
        ];

        let jails = vec![
            JailConfig {
                id: 0,
                name: "sshd".to_string(),
                reason: "SSH".to_string(),
                enabled: true,
                sources: vec![LogSource::File("/var/log/auth.log".to_string())],
                parser: ParserKind::Sshd,
                maxretry: 5,
                findtime_secs: 300,
                bantime_secs: 3600,
                bantime_multiplier: 2,
                max_bantime_secs: 86400 * 7,
            },
            JailConfig {
                id: 1,
                name: "http-access".to_string(),
                reason: "WEB".to_string(),
                enabled: true,
                sources: vec![LogSource::File("/var/log/nginx/access.log".to_string())],
                parser: ParserKind::HttpAccess { scanner_weight: 5 },
                maxretry: 5,
                findtime_secs: 120,
                bantime_secs: 3600,
                bantime_multiplier: 4,
                max_bantime_secs: 86400 * 7,
            },
        ];

        Self {
            nft_table: "kiban".to_string(),
            nft_family: "inet".to_string(),
            nft_set_v4: "blacklist_v4".to_string(),
            nft_set_v6: "blacklist_v6".to_string(),
            max_tracked_ips: 8192,
            dry_run: false,
            whitelist,
            ipspace: IpSpaceConfig::default(),
            jails,
        }
    }
}

/// Parses human-friendly durations like `"300"`, `"60s"`, `"10m"`, `"2h"`, `"7d"`.
pub fn parse_duration_secs(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration value".to_string());
    }
    let last = s.as_bytes()[s.len() - 1];
    let (num_str, mult) = match last {
        b's' | b'S' => (&s[..s.len() - 1], 1u32),
        b'm' | b'M' => (&s[..s.len() - 1], 60u32),
        b'h' | b'H' => (&s[..s.len() - 1], 3600u32),
        b'd' | b'D' => (&s[..s.len() - 1], 86400u32),
        b'0'..=b'9' => (s, 1u32),
        _ => return Err(format!("invalid duration suffix in '{s}'")),
    };
    let val: u32 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number in duration '{s}'"))?;
    val.checked_mul(mult)
        .ok_or_else(|| format!("duration overflow in '{s}'"))
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("failed to read config '{}': {e}", path.as_ref().display()))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(input: &str) -> Result<Self, String> {
        let mut cfg = Config {
            jails: Vec::new(),
            ..Config::default()
        };

        let mut current_section = String::from("global");
        let mut current_jail: Option<JailBuilder> = None;
        let mut next_jail_id: u8 = 0;

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line_num = line_idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                if let Some(jb) = current_jail.take() {
                    cfg.jails.push(jb.build(next_jail_id)?);
                    next_jail_id = next_jail_id.saturating_add(1);
                }

                let sec = line[1..line.len() - 1].trim();
                current_section = sec.to_string();
                if let Some(jail_name) = sec.strip_prefix("jail.") {
                    current_jail = Some(JailBuilder::new(jail_name.trim()));
                } else if sec != "global" && sec != "ipspace" {
                    return Err(format!(
                        "line {line_num}: unknown section '[{sec}]' (expected '[global]', '[ipspace]', or '[jail.<name>]')"
                    ));
                }
                continue;
            }

            let (key, val) = line
                .split_once('=')
                .ok_or_else(|| format!("line {line_num}: expected 'key = value', got '{line}'"))?;
            let key = key.trim();
            let val = unquote(val.trim());

            if current_section == "global" {
                match key {
                    "nft_table" => cfg.nft_table = val.to_string(),
                    "nft_family" => cfg.nft_family = val.to_string(),
                    "nft_set_v4" => cfg.nft_set_v4 = val.to_string(),
                    "nft_set_v6" => cfg.nft_set_v6 = val.to_string(),
                    "max_tracked_ips" => {
                        let n: usize = val.parse().map_err(|_| {
                            format!("line {line_num}: invalid max_tracked_ips '{val}'")
                        })?;
                        if n < 64 {
                            return Err(format!("line {line_num}: max_tracked_ips must be >= 64"));
                        }
                        cfg.max_tracked_ips = n.next_power_of_two();
                    }
                    "dry_run" => {
                        cfg.dry_run = parse_bool(val, line_num)?;
                    }
                    "whitelist" => {
                        cfg.whitelist.clear();
                        for item in val.split(',') {
                            let item = item.trim();
                            if !item.is_empty() {
                                cfg.whitelist.push(
                                    Cidr::parse(item)
                                        .map_err(|e| format!("line {line_num}: {e}"))?,
                                );
                            }
                        }
                    }
                    _ => {
                        return Err(format!(
                            "line {line_num}: unknown global key '{key}'"
                        ));
                    }
                }
            } else if current_section == "ipspace" {
                match key {
                    "enabled" => cfg.ipspace.enabled = parse_bool(val, line_num)?,
                    "endpoint" | "url" => cfg.ipspace.endpoint = val.to_string(),
                    "token" | "t" | "key" => cfg.ipspace.token = val.to_string(),
                    "source" | "s" => cfg.ipspace.source = val.to_string(),
                    "timeout" | "timeout_secs" => {
                        cfg.ipspace.timeout_secs = parse_duration_secs(val)
                            .map_err(|e| format!("line {line_num}: {e}"))?;
                    }
                    "risk_threshold" => {
                        cfg.ipspace.risk_threshold = val.parse().map_err(|_| {
                            format!("line {line_num}: invalid risk_threshold '{val}'")
                        })?;
                    }
                    "report_ban" => cfg.ipspace.report_ban = parse_bool(val, line_num)?,
                    _ => {
                        return Err(format!(
                            "line {line_num}: unknown [ipspace] key '{key}'"
                        ));
                    }
                }
            } else if let Some(ref mut jb) = current_jail {
                jb.set(key, val, line_num)?;
            }
        }

        if let Some(jb) = current_jail.take() {
            cfg.jails.push(jb.build(next_jail_id)?);
        }

        Ok(cfg)
    }

    #[inline]
    pub fn is_whitelisted_v4(&self, ip: u32) -> bool {
        for cidr in &self.whitelist {
            if cidr.contains_v4(ip) {
                return true;
            }
        }
        false
    }

    #[inline]
    pub fn is_whitelisted_v6_prefix64(&self, prefix64: u64) -> bool {
        for cidr in &self.whitelist {
            if cidr.contains_v6_prefix64(prefix64) {
                return true;
            }
        }
        false
    }
}

struct JailBuilder {
    name: String,
    reason: Option<String>,
    enabled: bool,
    sources: Vec<LogSource>,
    parser_name: String,
    scanner_weight: u16,
    match_any: Vec<Vec<u8>>,
    ignore_any: Vec<Vec<u8>>,
    ip_after: Vec<Vec<u8>>,
    maxretry: u16,
    findtime_secs: u32,
    bantime_secs: u32,
    bantime_multiplier: u16,
    max_bantime_secs: u32,
}

impl JailBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            reason: None,
            enabled: true,
            sources: Vec::new(),
            parser_name: "sshd".to_string(),
            scanner_weight: 5,
            match_any: Vec::new(),
            ignore_any: Vec::new(),
            ip_after: Vec::new(),
            maxretry: 5,
            findtime_secs: 300,
            bantime_secs: 3600,
            bantime_multiplier: 2,
            max_bantime_secs: 86400 * 7,
        }
    }

    fn set(&mut self, key: &str, val: &str, line_num: usize) -> Result<(), String> {
        match key {
            "enabled" => self.enabled = parse_bool(val, line_num)?,
            "reason" | "r" => self.reason = Some(val.to_string()),
            "source" => {
                for part in val.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        self.sources.push(
                            LogSource::parse(part)
                                .map_err(|e| format!("line {line_num}: {e}"))?,
                        );
                    }
                }
            }
            "parser" => self.parser_name = val.to_string(),
            "scanner_weight" => {
                self.scanner_weight = val
                    .parse()
                    .map_err(|_| format!("line {line_num}: invalid scanner_weight '{val}'"))?;
            }
            "match" => {
                for item in val.split('|') {
                    let item = item.trim();
                    if !item.is_empty() {
                        self.match_any.push(item.as_bytes().to_vec());
                    }
                }
            }
            "ignore" => {
                for item in val.split('|') {
                    let item = item.trim();
                    if !item.is_empty() {
                        self.ignore_any.push(item.as_bytes().to_vec());
                    }
                }
            }
            "ip_after" => {
                for item in val.split('|') {
                    if !item.is_empty() {
                        self.ip_after.push(item.as_bytes().to_vec());
                    }
                }
            }
            "maxretry" => {
                self.maxretry = val
                    .parse()
                    .map_err(|_| format!("line {line_num}: invalid maxretry '{val}'"))?;
                if self.maxretry == 0 {
                    return Err(format!("line {line_num}: maxretry must be >= 1"));
                }
            }
            "findtime" => {
                self.findtime_secs =
                    parse_duration_secs(val).map_err(|e| format!("line {line_num}: {e}"))?;
            }
            "bantime" => {
                self.bantime_secs =
                    parse_duration_secs(val).map_err(|e| format!("line {line_num}: {e}"))?;
            }
            "bantime_multiplier" => {
                self.bantime_multiplier = val.parse().map_err(|_| {
                    format!("line {line_num}: invalid bantime_multiplier '{val}'")
                })?;
                if self.bantime_multiplier == 0 {
                    self.bantime_multiplier = 1;
                }
            }
            "max_bantime" => {
                self.max_bantime_secs =
                    parse_duration_secs(val).map_err(|e| format!("line {line_num}: {e}"))?;
            }
            _ => {
                return Err(format!(
                    "line {line_num}: unknown key '{key}' in [jail.{}]",
                    self.name
                ));
            }
        }
        Ok(())
    }

    fn build(self, id: u8) -> Result<JailConfig, String> {
        if self.enabled && self.sources.is_empty() {
            return Err(format!(
                "jail '{}' is enabled but has no 'source' configured",
                self.name
            ));
        }

        let parser = match self.parser_name.as_str() {
            "sshd" | "ssh" => ParserKind::Sshd,
            "http-access" | "nginx-access" | "caddy-access" | "apache-access" => {
                ParserKind::HttpAccess {
                    scanner_weight: self.scanner_weight.max(1),
                }
            }
            "http-error" | "nginx-error" | "apache-error" => ParserKind::HttpError,
            "custom" => {
                if self.match_any.is_empty() {
                    return Err(format!(
                        "jail '{}' uses parser = custom, but no 'match' pattern was specified",
                        self.name
                    ));
                }
                ParserKind::Custom {
                    match_any: self.match_any,
                    ignore_any: self.ignore_any,
                    ip_after: self.ip_after,
                }
            }
            other => {
                return Err(format!(
                    "jail '{}': unknown parser '{other}' (expected sshd, http-access, http-error, or custom)",
                    self.name
                ));
            }
        };

        let default_reason = match &parser {
            ParserKind::Sshd => "SSH".to_string(),
            ParserKind::HttpAccess { .. } | ParserKind::HttpError => "WEB".to_string(),
            ParserKind::Custom { .. } => self.name.to_ascii_uppercase(),
        };

        Ok(JailConfig {
            id,
            name: self.name,
            reason: self.reason.unwrap_or(default_reason),
            enabled: self.enabled,
            sources: self.sources,
            parser,
            maxretry: self.maxretry,
            findtime_secs: self.findtime_secs,
            bantime_secs: self.bantime_secs,
            bantime_multiplier: self.bantime_multiplier,
            max_bantime_secs: self.max_bantime_secs.max(self.bantime_secs),
        })
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (idx, b) in line.bytes().enumerate() {
        if b == b'"' {
            in_quotes = !in_quotes;
        } else if b == b'#' && !in_quotes {
            return &line[..idx];
        }
    }
    line
}

fn unquote(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_bool(s: &str, line_num: usize) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(format!("line {line_num}: invalid boolean '{s}'")),
    }
}

/// Formats a compact IP key into standard `nftables` string representation.
pub fn format_ipv4(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

pub fn format_ipv6_prefix64(prefix64: u64) -> String {
    let full = (prefix64 as u128) << 64;
    format!("{}/64", Ipv6Addr::from(full))
}

impl Config {
    /// Appends a canonical CIDR entry to the `whitelist = "..."` line in `config_path`.
    /// Returns `Ok((canonical_cidr, true))` if added, or `Ok((canonical_cidr, false))` if already present.
    pub fn add_whitelist_to_file<P: AsRef<Path>>(
        config_path: P,
        raw_entry: &str,
    ) -> Result<(String, bool), String> {
        let canonical = normalize_cidr_str(raw_entry)?;
        let target_cidr = Cidr::parse(&canonical)?;

        let content = fs::read_to_string(config_path.as_ref()).map_err(|e| {
            format!(
                "failed to read config '{}': {e}",
                config_path.as_ref().display()
            )
        })?;

        let updated_opt = Self::modify_whitelist_in_str(&content, |list| {
            if list.iter().any(|existing| Cidr::parse(existing).ok() == Some(target_cidr)) {
                return false;
            }
            list.push(canonical.clone());
            true
        })?;

        if let Some(new_content) = updated_opt {
            fs::write(config_path.as_ref(), new_content).map_err(|e| {
                format!(
                    "failed to write config '{}': {e}",
                    config_path.as_ref().display()
                )
            })?;
            Ok((canonical, true))
        } else {
            Ok((canonical, false))
        }
    }

    /// Removes a CIDR entry from the `whitelist = "..."` line in `config_path`.
    pub fn remove_whitelist_from_file<P: AsRef<Path>>(
        config_path: P,
        raw_entry: &str,
    ) -> Result<(String, bool), String> {
        let canonical = normalize_cidr_str(raw_entry)?;
        let target_cidr = Cidr::parse(&canonical)?;

        let content = fs::read_to_string(config_path.as_ref()).map_err(|e| {
            format!(
                "failed to read config '{}': {e}",
                config_path.as_ref().display()
            )
        })?;

        let updated_opt = Self::modify_whitelist_in_str(&content, |list| {
            let before = list.len();
            list.retain(|existing| Cidr::parse(existing).ok() != Some(target_cidr));
            list.len() != before
        })?;

        if let Some(new_content) = updated_opt {
            fs::write(config_path.as_ref(), new_content).map_err(|e| {
                format!(
                    "failed to write config '{}': {e}",
                    config_path.as_ref().display()
                )
            })?;
            Ok((canonical, true))
        } else {
            Ok((canonical, false))
        }
    }

    pub fn modify_whitelist_in_str<F>(content: &str, mut f: F) -> Result<Option<String>, String>
    where
        F: FnMut(&mut Vec<String>) -> bool,
    {
        let mut out_lines: Vec<String> = Vec::new();
        let mut in_global = true;
        let mut modified = false;
        let mut found_whitelist_key = false;

        for raw_line in content.lines() {
            let trimmed = strip_comment(raw_line).trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let sec = trimmed[1..trimmed.len() - 1].trim();
                in_global = sec == "global";
                out_lines.push(raw_line.to_string());
                continue;
            }

            if in_global {
                if let Some((k, v)) = trimmed.split_once('=') {
                    if k.trim() == "whitelist" {
                        found_whitelist_key = true;
                        let raw_val = unquote(v.trim());
                        let mut items: Vec<String> = raw_val
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if f(&mut items) {
                            modified = true;
                            out_lines.push(format!("whitelist = \"{}\"", items.join(", ")));
                        } else {
                            out_lines.push(raw_line.to_string());
                        }
                        continue;
                    }
                }
            }
            out_lines.push(raw_line.to_string());
        }

        if !found_whitelist_key {
            let mut items = vec![
                "127.0.0.0/8".to_string(),
                "::1/128".to_string(),
                "fe80::/10".to_string(),
            ];
            if f(&mut items) {
                modified = true;
                out_lines.insert(0, format!("whitelist = \"{}\"", items.join(", ")));
            }
        }

        if modified {
            let mut joined = out_lines.join("\n");
            joined.push('\n');
            Ok(Some(joined))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matching() {
        assert!(glob_matches("example.com.log", "*.log"));
        assert!(!glob_matches("example.com.error.log", "*.log"));
        assert!(glob_matches("example.com.error.log", "*.error.log"));
        assert!(!glob_matches("example.com.bytes", "*.log"));
        assert!(!glob_matches("example.com.log.1", "*.log"));
        assert!(!glob_matches("example.com.log.2.gz", "*.log"));
        assert!(glob_matches("nginx.access.log", "nginx*"));
        assert!(glob_matches("test_foo_bar.txt", "test*bar.txt"));
    }

    #[test]
    fn test_cidr_matching() {
        let v4 = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(v4.contains_v4(u32::from(Ipv4Addr::new(192, 168, 1, 42))));
        assert!(!v4.contains_v4(u32::from(Ipv4Addr::new(192, 168, 2, 1))));

        let v6 = Cidr::parse("2001:db8:abcd::/48").unwrap();
        let ip_inside: Ipv6Addr = "2001:db8:abcd:1234::1".parse().unwrap();
        let prefix64 = (u128::from(ip_inside) >> 64) as u64;
        assert!(v6.contains_v6_prefix64(prefix64));
    }

    #[test]
    fn test_duration_parsing() {
        assert_eq!(parse_duration_secs("300").unwrap(), 300);
        assert_eq!(parse_duration_secs("45s").unwrap(), 45);
        assert_eq!(parse_duration_secs("10m").unwrap(), 600);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
        assert_eq!(parse_duration_secs("1d").unwrap(), 86400);
    }

    #[test]
    fn test_config_parsing() {
        let sample = r#"
        [global]
        nft_table = "kiban"
        max_tracked_ips = 4096
        whitelist = "127.0.0.0/8, ::1/128, 10.0.0.0/8"

        [jail.sshd]
        enabled = true
        source = "file:/var/log/auth.log, journal:sshd.service"
        parser = "sshd"
        maxretry = 4
        findtime = 5m
        bantime = 1h
        bantime_multiplier = 3

        [jail.custom-app]
        enabled = true
        source = "file:/var/log/app.log"
        parser = "custom"
        match = "AUTH_FAIL | INVALID_TOKEN"
        ip_after = "client_ip= | from "
        maxretry = 3
        findtime = 120s
        bantime = 30m
        "#;

        let cfg = Config::parse_str(sample).unwrap();
        assert_eq!(cfg.max_tracked_ips, 4096);
        assert_eq!(cfg.whitelist.len(), 3);
        assert_eq!(cfg.jails.len(), 2);
        assert_eq!(cfg.jails[0].name, "sshd");
        assert_eq!(cfg.jails[0].maxretry, 4);
        assert_eq!(cfg.jails[0].findtime_secs, 300);
        assert_eq!(cfg.jails[0].bantime_secs, 3600);
        assert_eq!(cfg.jails[1].name, "custom-app");
    }

    #[test]
    fn test_subnet_cidr_and_whitelist_editing() {
        assert_eq!(ip_to_subnet_cidr("203.0.113.42").unwrap(), "203.0.113.0/24");
        assert_eq!(
            ip_to_subnet_cidr("2001:db8:abcd:1234::99").unwrap(),
            "2001:db8:abcd:1234::/64"
        );

        let sample = "[global]\nwhitelist = \"127.0.0.0/8, ::1/128\"\n";
        let added = Config::modify_whitelist_in_str(sample, |list| {
            list.push("203.0.113.0/24".to_string());
            true
        })
        .unwrap()
        .unwrap();
        assert!(added.contains("203.0.113.0/24"));
    }
}
