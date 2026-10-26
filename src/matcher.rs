use std::net::IpAddr;
use crate::config::ParserKind;

/// Compact, copyable IP key used throughout the hot path.
/// - IPv4 is stored as a 32-bit big-endian integer (`u32`).
/// - IPv6 is normalized to its `/64` network prefix (`u64`) to defeat IPv6 subnet rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpKey {
    V4(u32),
    V6Prefix64(u64),
}

impl IpKey {
    pub fn from_ip_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => IpKey::V4(u32::from(v4)),
            IpAddr::V6(v6) => {
                // Convert IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to native V4
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    IpKey::V4(u32::from(mapped_v4))
                } else {
                    let raw = u128::from(v6);
                    IpKey::V6Prefix64((raw >> 64) as u64)
                }
            }
        }
    }

    pub fn format_nft(&self) -> String {
        match *self {
            IpKey::V4(ip) => crate::config::format_ipv4(ip),
            IpKey::V6Prefix64(pref) => crate::config::format_ipv6_prefix64(pref),
        }
    }
}

/// Result of matching a single log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchResult {
    pub ip: IpKey,
    /// Offense weight (1 for normal auth failure, >=1 for exploit/scanner hits).
    pub weight: u16,
}

/// Fast byte-slice substring finder (`memmem` style with first/last byte pre-check).
#[inline]
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let nlen = needle.len();
    if nlen == 0 {
        return Some(0);
    }
    if haystack.len() < nlen {
        return None;
    }
    let first = needle[0];
    let last = needle[nlen - 1];
    let max_idx = haystack.len() - nlen;
    let mut i = 0;
    while i <= max_idx {
        if haystack[i] == first && haystack[i + nlen - 1] == last {
            if &haystack[i..i + nlen] == needle {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[inline]
pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

/// Zero-allocation IPv4 parser directly from `&[u8]`.
#[inline]
pub fn parse_ipv4_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 7 || bytes.len() > 15 {
        return None;
    }
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut current: u16 = 0;
    let mut digits_in_octet = 0;

    for &b in bytes {
        if b.is_ascii_digit() {
            if digits_in_octet > 0 && current == 0 {
                // Reject leading zeros like 01.02.03.04
                return None;
            }
            current = current * 10 + (b - b'0') as u16;
            if current > 255 {
                return None;
            }
            digits_in_octet += 1;
        } else if b == b'.' {
            if digits_in_octet == 0 || octet_idx >= 3 {
                return None;
            }
            octets[octet_idx] = current as u8;
            octet_idx += 1;
            current = 0;
            digits_in_octet = 0;
        } else {
            return None;
        }
    }

    if octet_idx != 3 || digits_in_octet == 0 {
        return None;
    }
    octets[3] = current as u8;
    Some(u32::from_be_bytes(octets))
}

#[inline]
fn is_ip_token_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b'.' || b == b':'
}

/// Parses an IPv4 or IPv6 token from the beginning of `slice`, stopping at delimiter characters.
pub fn extract_ip_at_start(slice: &[u8]) -> Option<IpKey> {
    let slice = trim_leading_delims(slice);
    if slice.is_empty() {
        return None;
    }

    // Handle bracketed IPv6 e.g. `[2001:db8::1]:443`
    if slice[0] == b'[' {
        if let Some(end_bracket) = slice.iter().position(|&b| b == b']') {
            return parse_clean_ip_token(&slice[1..end_bracket]);
        }
    }

    let mut len = 0;
    while len < slice.len() && is_ip_token_char(slice[len]) {
        len += 1;
    }
    if len < 3 {
        return None;
    }
    let token = &slice[..len];
    parse_clean_ip_token(token)
}

fn parse_clean_ip_token(token: &[u8]) -> Option<IpKey> {
    // Strip trailing '.' or ':' if punctuation was attached in log text
    let token = token.strip_suffix(b".").unwrap_or(token);

    // Fast path: IPv4 without port
    if let Some(v4) = parse_ipv4_bytes(token) {
        return Some(IpKey::V4(v4));
    }

    // Check IPv4:port (e.g. `192.0.2.15:54321`) — exactly one colon and contains dots
    let colon_count = token.iter().filter(|&&b| b == b':').count();
    if colon_count == 1 {
        if let Some(colon_pos) = token.iter().position(|&b| b == b':') {
            if let Some(v4) = parse_ipv4_bytes(&token[..colon_pos]) {
                return Some(IpKey::V4(v4));
            }
        }
    }

    // IPv6 path (must have >= 2 colons)
    if colon_count >= 2 && token.len() <= 45 {
        if let Ok(s) = std::str::from_utf8(token) {
            if let Ok(addr) = s.parse::<IpAddr>() {
                return Some(IpKey::from_ip_addr(addr));
            }
        }
    }

    None
}

#[inline]
fn trim_leading_delims(mut s: &[u8]) -> &[u8] {
    while let Some(&first) = s.first() {
        if first == b' ' || first == b'\t' || first == b'"' || first == b'\'' {
            s = &s[1..];
        } else {
            break;
        }
    }
    s
}

/// Evaluates a log line against a configured `ParserKind`.
#[inline]
pub fn match_line(parser: &ParserKind, line: &[u8]) -> Option<MatchResult> {
    if line.is_empty() {
        return None;
    }
    match parser {
        ParserKind::Sshd => match_sshd(line),
        ParserKind::HttpAccess { scanner_weight } => match_http_access(line, *scanner_weight),
        ParserKind::HttpError => match_http_error(line),
        ParserKind::Custom {
            match_any,
            ignore_any,
            ip_after,
        } => match_custom(line, match_any, ignore_any, ip_after),
    }
}

/// Ultra-fast zero-allocation matcher for OpenSSH (`sshd`) logs.
pub fn match_sshd(line: &[u8]) -> Option<MatchResult> {
    // Fast path 1: 90%+ of OpenSSH failure logs contain `" from "` right before the IP.
    // A single scan for `" from "` replaces 9 separate full-line scans.
    if let Some(from_pos) = find_subslice(line, b" from ") {
        let prefix = &line[..from_pos];
        const FROM_PREFIX_SIGS: &[&[u8]] = &[
            b"Failed password",
            b"Failed publickey",
            b"Failed keyboard-interactive",
            b"Invalid user ",
            b"invalid user ",
            b"maximum authentication attempts exceeded",
            b"Did not receive identification string",
            b"Bad protocol version identification",
            b"banner exchange: Connection",
        ];
        for sig in FROM_PREFIX_SIGS {
            if contains_subslice(prefix, sig) {
                if let Some(ip) = extract_ip_at_start(&line[from_pos + 6..]) {
                    return Some(MatchResult { ip, weight: 1 });
                }
                break;
            }
        }
    }

    // Fast path 2: Pre-auth disconnect / reset patterns all contain `" user "`
    // e.g. `Connection closed by authenticating user root 203.0.113.5 port 44322 [preauth]`
    if let Some(user_pos) = find_subslice(line, b" user ") {
        let prefix = &line[..user_pos + 6];
        const PREAUTH_PREFIXES: &[&[u8]] = &[
            b"Connection closed by authenticating user ",
            b"Connection closed by invalid user ",
            b"Disconnecting authenticating user ",
            b"Disconnecting invalid user ",
            b"Connection reset by authenticating user ",
            b"Connection reset by invalid user ",
        ];
        for pat in PREAUTH_PREFIXES {
            if contains_subslice(prefix, pat) {
                let after_user_kw = &line[user_pos + 6..];
                if let Some(space_pos) = after_user_kw.iter().position(|&b| b == b' ') {
                    if let Some(ip) = extract_ip_at_start(&after_user_kw[space_pos + 1..]) {
                        return Some(MatchResult { ip, weight: 1 });
                    }
                }
                break;
            }
        }
    }

    // Fast path 3: `"Unable to negotiate with <IP>"`
    if let Some(pos) = find_subslice(line, b"Unable to negotiate with ") {
        if let Some(ip) = extract_ip_at_start(&line[pos + 25..]) {
            return Some(MatchResult { ip, weight: 1 });
        }
    }

    // Fast path 4: PAM authentication failure (`rhost=<IP>`)
    if let Some(rhost_pos) = find_subslice(line, b"rhost=") {
        if contains_subslice(line, b"authentication failure") {
            if let Some(ip) = extract_ip_at_start(&line[rhost_pos + 6..]) {
                return Some(MatchResult { ip, weight: 1 });
            }
        }
    }

    None
}

/// High-confidence web scanner / exploit probe signatures.
const WEB_SCANNER_SIGNATURES: &[&[u8]] = &[
    b"/.env",
    b"/.git/",
    b"/.aws/",
    b"/wp-login.php",
    b"/xmlrpc.php",
    b"/wp-admin/setup-config.php",
    b"/phpmyadmin",
    b"/pma/",
    b"/myadmin/",
    b"/vendor/phpunit",
    b"/eval-stdin.php",
    b"/actuator/",
    b"/cgi-bin/",
    b"/etc/passwd",
    b"../",
    b"..%2f",
    b"..%2F",
    b"/boaform/",
    b"/HNAP1",
    b"/GponForm/",
    b"/autodiscover/autodiscover.json",
    b"/XDEBUG_SESSION_START",
];

/// Fast zero-allocation matcher for Nginx / Caddy / Apache access logs (Combined & JSON).
pub fn match_http_access(line: &[u8], scanner_weight: u16) -> Option<MatchResult> {
    // Quick rejection for non-HTTP lines (e.g. syslog lines when multiple jails share a stream)
    let http_pos = find_subslice(line, b" HTTP/");
    let is_json = if http_pos.is_none() {
        contains_subslice(line, b"\"status\":")
    } else {
        false
    };
    if http_pos.is_none() && !is_json {
        return None;
    }

    // Narrow down the URI search region to the request target if standard HTTP format
    let uri_region = if let Some(hp) = http_pos {
        let before_http = &line[..hp];
        // Find opening quote of `"GET /path`
        if let Some(q_pos) = before_http.iter().rposition(|&b| b == b'"') {
            &before_http[q_pos + 1..]
        } else {
            before_http
        }
    } else {
        line
    };

    // 1. Check if the request URI hits a known vulnerability scanner / exploit path
    let mut is_scanner = false;
    for sig in WEB_SCANNER_SIGNATURES {
        if contains_subslice(uri_region, sig) {
            is_scanner = true;
            break;
        }
    }

    // 2. Check if line has an offending HTTP status code (401, 403, 444)
    let is_auth_or_block_status = if !is_scanner {
        if let Some(hp) = http_pos {
            has_offending_http_status(&line[hp..])
        } else {
            has_offending_http_status(line)
        }
    } else {
        false
    };

    if !is_scanner && !is_auth_or_block_status {
        return None;
    }

    // Ignore benign browser requests for favicon.ico or robots.txt returning 403/401
    if !is_scanner
        && (contains_subslice(uri_region, b"/favicon.ico")
            || contains_subslice(uri_region, b"/robots.txt"))
    {
        return None;
    }

    let ip = extract_http_access_ip(line)?;
    let weight = if is_scanner {
        scanner_weight.max(1)
    } else {
        1
    };

    Some(MatchResult { ip, weight })
}

#[inline]
fn has_offending_http_status(line: &[u8]) -> bool {
    // Standard CLF / Combined log format: `HTTP/1.1" 401 ` or `HTTP/2.0" 403 ` or `HTTP/1.0" 444 `
    if let Some(pos) = find_subslice(line, b"\" 40") {
        let after = &line[pos + 4..];
        if after.starts_with(b"1 ") || after.starts_with(b"3 ") {
            return true;
        }
    }
    if contains_subslice(line, b"\" 444 ") {
        return true;
    }
    // JSON access log format (Caddy / Nginx JSON): `"status":401` or `"status": 403`
    if contains_subslice(line, b"\"status\":401")
        || contains_subslice(line, b"\"status\": 401")
        || contains_subslice(line, b"\"status\":403")
        || contains_subslice(line, b"\"status\": 403")
        || contains_subslice(line, b"\"status\":444")
    {
        return true;
    }
    false
}

#[inline]
fn extract_http_access_ip(line: &[u8]) -> Option<IpKey> {
    // 1. Standard Combined/CLF format: IP is at the very beginning of the line
    if let Some(ip) = extract_ip_at_start(line) {
        return Some(ip);
    }

    // 2. JSON format (`"remote_ip":"1.2.3.4"`, `"client_ip":"1.2.3.4"`, `"remote_addr":"1.2.3.4"`)
    const JSON_IP_KEYS: &[&[u8]] = &[
        b"\"remote_ip\":",
        b"\"client_ip\":",
        b"\"remote_addr\":",
    ];
    for key in JSON_IP_KEYS {
        if let Some(pos) = find_subslice(line, key) {
            if let Some(ip) = extract_ip_at_start(&line[pos + key.len()..]) {
                return Some(ip);
            }
        }
    }

    // 3. Vhost-prefixed log (`example.com:443 198.51.100.7 - - [...]`)
    if let Some(space_pos) = line.iter().position(|&b| b == b' ') {
        if let Some(ip) = extract_ip_at_start(&line[space_pos + 1..]) {
            return Some(ip);
        }
    }

    None
}

/// Fast zero-allocation matcher for Nginx / Apache error logs.
pub fn match_http_error(line: &[u8]) -> Option<MatchResult> {
    const ERROR_SIGS: &[&[u8]] = &[
        b"password mismatch",
        b"was not found in ",
        b"no user/password was provided",
        b"access forbidden by rule",
        b"ModSecurity: Access denied",
        b"Primary script unknown",
        b"limiting requests, excess:",
    ];

    let mut matched = false;
    for sig in ERROR_SIGS {
        if contains_subslice(line, sig) {
            matched = true;
            break;
        }
    }
    if !matched {
        return None;
    }

    // Nginx error log: `... client: 198.51.100.9, server: ...`
    if let Some(pos) = find_subslice(line, b"client: ") {
        if let Some(ip) = extract_ip_at_start(&line[pos + 8..]) {
            return Some(MatchResult { ip, weight: 1 });
        }
    }

    // Apache error log: `... [client 198.51.100.9:51234] ...`
    if let Some(pos) = find_subslice(line, b"[client ") {
        if let Some(ip) = extract_ip_at_start(&line[pos + 8..]) {
            return Some(MatchResult { ip, weight: 1 });
        }
    }

    None
}

/// Custom substring + marker matcher without regular expression overhead.
pub fn match_custom(
    line: &[u8],
    match_any: &[Vec<u8>],
    ignore_any: &[Vec<u8>],
    ip_after: &[Vec<u8>],
) -> Option<MatchResult> {
    for ign in ignore_any {
        if contains_subslice(line, ign) {
            return None;
        }
    }

    let mut matched = false;
    for pat in match_any {
        if contains_subslice(line, pat) {
            matched = true;
            break;
        }
    }
    if !matched {
        return None;
    }

    if !ip_after.is_empty() {
        for marker in ip_after {
            if let Some(pos) = find_subslice(line, marker) {
                if let Some(ip) = extract_ip_at_start(&line[pos + marker.len()..]) {
                    return Some(MatchResult { ip, weight: 1 });
                }
            }
        }
        return None;
    }

    // Fallback: scan whitespace-separated tokens in the line for the first valid IP
    let mut i = 0;
    while i < line.len() {
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t' || line[i] == b'[') {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        if let Some(ip) = extract_ip_at_start(&line[i..]) {
            return Some(MatchResult { ip, weight: 1 });
        }
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
            i += 1;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_sshd_ipv4_and_ipv6() {
        let l1 = b"Oct 20 14:22:01 srv sshd[1234]: Failed password for root from 203.0.113.42 port 51234 ssh2";
        let r1 = match_sshd(l1).unwrap();
        assert_eq!(r1.ip, IpKey::V4(u32::from(Ipv4Addr::new(203, 0, 113, 42))));

        let l2 = b"Oct 20 14:22:05 srv sshd[1235]: Invalid user admin from 2001:db8:abcd:1234::99 port 49000 ssh2";
        let r2 = match_sshd(l2).unwrap();
        let expected_v6 = (u128::from("2001:db8:abcd:1234::99".parse::<Ipv6Addr>().unwrap()) >> 64) as u64;
        assert_eq!(r2.ip, IpKey::V6Prefix64(expected_v6));

        let l3 = b"Oct 20 14:22:09 srv sshd[1236]: Connection closed by authenticating user ubuntu 198.51.100.7 port 39100 [preauth]";
        let r3 = match_sshd(l3).unwrap();
        assert_eq!(r3.ip, IpKey::V4(u32::from(Ipv4Addr::new(198, 51, 100, 7))));

        let benign = b"Oct 20 14:22:10 srv sshd[1237]: Accepted publickey for deploy from 192.168.1.10 port 52222 ssh2";
        assert!(match_sshd(benign).is_none());
    }

    #[test]
    fn test_http_access_scanners_and_bruteforce() {
        let scanner_line = b"198.51.100.55 - - [20/Oct/2026:14:30:00 +0300] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.0\"";
        let m1 = match_http_access(scanner_line, 5).unwrap();
        assert_eq!(m1.ip, IpKey::V4(u32::from(Ipv4Addr::new(198, 51, 100, 55))));
        assert_eq!(m1.weight, 5);

        let auth_line = b"203.0.113.9 - - [20/Oct/2026:14:30:01 +0300] \"POST /api/login HTTP/2.0\" 401 42 \"-\" \"Mozilla/5.0\"";
        let m2 = match_http_access(auth_line, 5).unwrap();
        assert_eq!(m2.ip, IpKey::V4(u32::from(Ipv4Addr::new(203, 0, 113, 9))));
        assert_eq!(m2.weight, 1);

        let json_line = br#"{"ts":1792500000,"remote_ip":"198.51.100.88","request":{"uri":"/wp-login.php"},"status":200}"#;
        let m3 = match_http_access(json_line, 5).unwrap();
        assert_eq!(m3.ip, IpKey::V4(u32::from(Ipv4Addr::new(198, 51, 100, 88))));
        assert_eq!(m3.weight, 5);

        let ok_line = b"198.51.100.1 - - [20/Oct/2026:14:30:01 +0300] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"";
        assert!(match_http_access(ok_line, 5).is_none());
    }

    #[test]
    fn test_http_error_logs() {
        let nginx_err = b"2026/10/20 14:35:00 [error] 102#102: *99 user \"admin\": password mismatch, client: 203.0.113.77, server: example.com";
        let m = match_http_error(nginx_err).unwrap();
        assert_eq!(m.ip, IpKey::V4(u32::from(Ipv4Addr::new(203, 0, 113, 77))));
    }
}
