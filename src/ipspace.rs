use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::config::IpSpaceConfig;
use crate::matcher::IpKey;

static PENDING_REPORTS: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// Reaps any completed background `curl` processes spawned by `report_ban_async`
/// so they never accumulate as `<defunct>` zombie processes.
/// Returns `true` if there are still in-flight `curl` processes running.
pub fn reap_finished_reports() -> bool {
    let Ok(mut list) = PENDING_REPORTS.lock() else {
        return false;
    };
    list.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
    !list.is_empty()
}

/// Parsed threat intelligence verdict returned by the `ip.space.ua` API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSpaceVerdict {
    pub action: String,
    pub recommended_action: String,
    pub recommended_ttl: u32,
    pub risk_score: u8,
    pub is_whitelisted: bool,
    pub country_code: String,
    pub num_lists_found: u32,
}

impl IpSpaceVerdict {
    /// Returns `true` if the IP is explicitly whitelisted or marked `"allow"` by IP Space.
    #[inline]
    pub fn is_allow(&self) -> bool {
        self.is_whitelisted || self.recommended_action.eq_ignore_ascii_case("allow")
    }

    /// Returns `true` if the verdict warrants an immediate ban on the very first log event.
    #[inline]
    pub fn should_ban_immediately(&self, risk_threshold: u8) -> bool {
        if self.is_allow() {
            return false;
        }
        self.action.eq_ignore_ascii_case("ban")
            || self.recommended_action.eq_ignore_ascii_case("ban")
            || self.recommended_action.eq_ignore_ascii_case("tarpit")
            || self.risk_score >= risk_threshold
    }

    /// Zero-dependency parser for the JSON payload returned by `https://ip.space.ua/api`.
    pub fn parse_json(json: &str) -> Option<Self> {
        // Reject API error responses (e.g. {"error": "Unauthorized", ...})
        if extract_json_str(json, "error").is_some() {
            return None;
        }

        let action = extract_json_str(json, "action")?.to_string();
        let recommended_action = extract_json_str(json, "recommendedAction")
            .unwrap_or("monitor")
            .to_string();
        let recommended_ttl = extract_json_u64(json, "recommendedTtl").unwrap_or(0) as u32;
        let risk_score = extract_json_u64(json, "riskScore")
            .unwrap_or(0)
            .min(100) as u8;

        let is_whitelisted = match extract_json_u64(json, "AIDBisWhitelisted") {
            Some(v) => v != 0,
            None => extract_json_bool(json, "AIDBisWhitelisted").unwrap_or(false),
        };

        let country_code = extract_json_str(json, "countryCode")
            .unwrap_or("NA")
            .to_string();
        let num_lists_found = extract_json_u64(json, "numListsFound").unwrap_or(0) as u32;

        Some(Self {
            action,
            recommended_action,
            recommended_ttl,
            risk_score,
            is_whitelisted,
            country_code,
            num_lists_found,
        })
    }
}

/// Formats a compact `IpKey` as a valid IP address parameter for `ip.space.ua/api`.
pub fn format_ip_for_api(ip: IpKey) -> String {
    match ip {
        IpKey::V4(v4) => Ipv4Addr::from(v4).to_string(),
        IpKey::V6Prefix64(p64) => {
            // Use host ::1 within the /64 prefix so PHP's FILTER_VALIDATE_IP accepts it without CIDR mask
            let full = ((p64 as u128) << 64) | 1;
            Ipv6Addr::from(full).to_string()
        }
    }
}

/// Builds the full query URL for `https://ip.space.ua/docs#endpoint-query`.
pub fn build_query_url(cfg: &IpSpaceConfig, ip: IpKey, reason: &str, action: &str) -> String {
    let ip_str = format_ip_for_api(ip);
    let sep = if cfg.endpoint.contains('?') { '&' } else { '?' };
    format!(
        "{}{}t={}&s={}&ip={}&r={}&a={}",
        cfg.endpoint, sep, cfg.token, cfg.source, ip_str, reason, action
    )
}

/// Queries `ip.space.ua` with `a=found` (or `a=check`) and returns the parsed `IpSpaceVerdict`.
pub fn query_ip(
    cfg: &IpSpaceConfig,
    ip: IpKey,
    reason: &str,
    action: &str,
    dry_run: bool,
) -> Result<IpSpaceVerdict, String> {
    let url = build_query_url(cfg, ip, reason, action);
    if dry_run && action != "check" {
        eprintln!(
            "[dry-run] ipspace GET {}?t=***&s={}&ip={}&r={}&a={}",
            cfg.endpoint,
            cfg.source,
            format_ip_for_api(ip),
            reason,
            action
        );
    }

    let timeout_str = cfg.timeout_secs.max(1).to_string();
    let output = Command::new("curl")
        .args([
            "-s",
            "-S",
            "-m",
            &timeout_str,
            "--connect-timeout",
            "2",
            "-H",
            "Accept: application/json",
            &url,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to execute curl for ipspace query: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", stderr.trim()));
    }

    let body = String::from_utf8_lossy(&output.stdout);
    IpSpaceVerdict::parse_json(&body)
        .ok_or_else(|| format!("failed to parse ip.space.ua response: {}", body.trim()))
}

/// Fetches a formatted human-readable threat intelligence dossier from `ip.space.ua` (`a=check`) for the TUI preview pane.
pub fn fetch_dossier_summary(cfg: &IpSpaceConfig, ip: IpKey) -> Result<String, String> {
    let url = build_query_url(cfg, ip, "CHECK", "check");
    let timeout_str = cfg.timeout_secs.max(1).to_string();
    let output = Command::new("curl")
        .args([
            "-s",
            "-S",
            "-m",
            &timeout_str,
            "--connect-timeout",
            "2",
            "-H",
            "Accept: application/json",
            &url,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("curl error: {e}"))?;

    if !output.status.success() {
        return Err("API request failed".to_string());
    }

    let json = String::from_utf8_lossy(&output.stdout);
    let Some(v) = IpSpaceVerdict::parse_json(&json) else {
        return Err("Unavailable / Invalid response".to_string());
    };

    let risk_level = extract_json_str(&json, "riskLevel").unwrap_or("unknown");
    let threat_cat = extract_json_str(&json, "threatCategory").unwrap_or("-");
    let country_name = extract_json_str(&json, "countryName").unwrap_or("-");
    let asn = extract_json_u64(&json, "asn")
        .map(|n| format!("AS{n}"))
        .unwrap_or_else(|| "-".to_string());
    let as_name = extract_json_str(&json, "asName").unwrap_or("-");
    let is_dc = extract_json_bool(&json, "isDataCenter").unwrap_or(false);
    let is_tor = extract_json_bool(&json, "isTor").unwrap_or(false);
    let attack_cnt = extract_json_u64(&json, "attackCount").unwrap_or(0);
    let aidb_score = extract_json_u64(&json, "AIDBConfidenceScore").unwrap_or(0);
    let first_seen = extract_json_str(&json, "firstSeen").unwrap_or("-");
    let last_seen = extract_json_str(&json, "lastSeen").unwrap_or("-");
    let matched_cidr = extract_json_str(&json, "matchedCidr").unwrap_or("-");

    Ok(format!(
        "  Risk Score         : {}/100 ({})\n\
         \x20 Recommended Action : {} (TTL: {}s)\n\
         \x20 Threat Category    : {}\n\
         \x20 AbuseIPDB Score    : {}% (Whitelisted: {})\n\
         \x20 Country            : {} ({})\n\
         \x20 Network / ISP      : {} — {}\n\
         \x20 Flags              : DataCenter={}, Tor={}\n\
         \x20 Blacklists Matched : {} (CIDR: {})\n\
         \x20 Mesh Attack Count  : {} (First: {}, Last: {})",
        v.risk_score,
        risk_level.to_ascii_uppercase(),
        v.recommended_action.to_ascii_uppercase(),
        v.recommended_ttl,
        threat_cat,
        aidb_score,
        v.is_whitelisted,
        country_name,
        v.country_code,
        asn,
        as_name,
        is_dc,
        is_tor,
        v.num_lists_found,
        matched_cidr,
        attack_cnt,
        first_seen,
        last_seen
    ))
}

/// Reports a local ban (`a=ban`) to `ip.space.ua` when an IP reaches local `maxretry`.
pub fn report_ban_async(cfg: &IpSpaceConfig, ip: IpKey, reason: &str, dry_run: bool) {
    if !cfg.enabled || !cfg.report_ban || cfg.token.is_empty() {
        return;
    }
    let url = build_query_url(cfg, ip, reason, "ban");
    if dry_run {
        eprintln!(
            "[dry-run] ipspace REPORT BAN {}?t=***&s={}&ip={}&r={}&a=ban",
            cfg.endpoint,
            cfg.source,
            format_ip_for_api(ip),
            reason
        );
        return;
    }

    let _ = reap_finished_reports();
    if let Ok(list) = PENDING_REPORTS.lock() {
        if list.len() >= 32 {
            return;
        }
    }

    let timeout_str = cfg.timeout_secs.max(1).to_string();
    if let Ok(child) = Command::new("curl")
        .args([
            "-s",
            "-m",
            &timeout_str,
            "--connect-timeout",
            "2",
            &url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Ok(mut list) = PENDING_REPORTS.lock() {
            list.push(child);
        }
    }
}

/// Extracts a string value for `"key": "value"` from a JSON object slice without allocations.
fn extract_json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let tail = find_json_key_value(json, key)?;
    if !tail.starts_with('"') {
        return None;
    }
    let after_quote = &tail[1..];
    let end_quote = after_quote.find('"')?;
    Some(&after_quote[..end_quote])
}

/// Extracts an unsigned integer value for `"key": 123` from a JSON object slice.
fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let tail = find_json_key_value(json, key)?;
    let digits_len = tail
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits_len == 0 {
        return None;
    }
    tail[..digits_len].parse().ok()
}

/// Extracts a boolean value for `"key": true|false` from a JSON object slice.
fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let tail = find_json_key_value(json, key)?;
    if tail.starts_with("true") {
        Some(true)
    } else if tail.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn find_json_key_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let mut search_from = 0;
    let bytes = json.as_bytes();
    let kbytes = key.as_bytes();

    while search_from + kbytes.len() + 2 < bytes.len() {
        let rel = json[search_from..].find(key)?;
        let pos = search_from + rel;
        if pos > 0 && bytes[pos - 1] == b'"' && bytes.get(pos + kbytes.len()) == Some(&b'"') {
            let after_key = &json[pos + kbytes.len() + 1..].trim_start();
            if let Some(after_colon) = after_key.strip_prefix(':') {
                return Some(after_colon.trim_start());
            }
        }
        search_from = pos + kbytes.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipspace_verdict_ban() {
        let sample_json = r#"{
            "ipAddress": "203.0.113.126",
            "action": "found",
            "reason": "SSH",
            "AIDBisWhitelisted": 0,
            "AIDBConfidenceScore": 100,
            "countryCode": "RO",
            "numListsFound": 5,
            "recommendedAction": "ban",
            "recommendedTtl": 604800,
            "riskScore": 100,
            "riskLevel": "critical",
            "threatCategory": "DDoS"
        }"#;

        let v = IpSpaceVerdict::parse_json(sample_json).unwrap();
        assert_eq!(v.action, "found");
        assert_eq!(v.recommended_action, "ban");
        assert_eq!(v.recommended_ttl, 604800);
        assert_eq!(v.risk_score, 100);
        assert!(!v.is_whitelisted);
        assert_eq!(v.country_code, "RO");
        assert_eq!(v.num_lists_found, 5);
        assert!(!v.is_allow());
        assert!(v.should_ban_immediately(75));
    }

    #[test]
    fn test_parse_ipspace_verdict_allow_and_monitor() {
        let allow_json = r#"{
            "ipAddress": "8.8.8.8",
            "action": "found",
            "AIDBisWhitelisted": 1,
            "recommendedAction": "allow",
            "recommendedTtl": 0,
            "riskScore": 0
        }"#;
        let v_allow = IpSpaceVerdict::parse_json(allow_json).unwrap();
        assert!(v_allow.is_allow());
        assert!(!v_allow.should_ban_immediately(75));

        let monitor_json = r#"{
            "ipAddress": "198.51.100.10",
            "action": "found",
            "AIDBisWhitelisted": 0,
            "recommendedAction": "monitor",
            "recommendedTtl": 3600,
            "riskScore": 20
        }"#;
        let v_mon = IpSpaceVerdict::parse_json(monitor_json).unwrap();
        assert!(!v_mon.is_allow());
        assert!(!v_mon.should_ban_immediately(75));
    }
}
