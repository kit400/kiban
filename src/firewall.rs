use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::config::{Cidr, Config};
use crate::matcher::IpKey;
use crate::tracker::BanDecision;

/// Represents an active ban entry parsed from `nft list table inet kiban`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveBanElement {
    pub ip_str: String,
    pub timeout: String,
    pub expires: String,
}

pub struct Firewall {
    family: String,
    table: String,
    set_v4: String,
    set_v6: String,
    dry_run: bool,
    batch_buf: String,
}

impl Firewall {
    pub fn new(cfg: &Config) -> Self {
        Self {
            family: cfg.nft_family.clone(),
            table: cfg.nft_table.clone(),
            set_v4: cfg.nft_set_v4.clone(),
            set_v6: cfg.nft_set_v6.clone(),
            dry_run: cfg.dry_run,
            batch_buf: String::with_capacity(512),
        }
    }

    /// Generates the idempotent `nftables` initialization ruleset.
    /// Existing elements in `blacklist_v4` and `blacklist_v6` are preserved across daemon restarts,
    /// while `chain input` is flushed and recreated cleanly.
    pub fn build_init_script(&self) -> String {
        format!(
            "add table {fam} {tbl}\n\
             add set {fam} {tbl} {s4} {{ type ipv4_addr; flags interval, timeout; auto-merge; }}\n\
             add set {fam} {tbl} {s6} {{ type ipv6_addr; flags interval, timeout; auto-merge; }}\n\
             add chain {fam} {tbl} input {{ type filter hook input priority filter - 10; policy accept; }}\n\
             flush chain {fam} {tbl} input\n\
             add rule {fam} {tbl} input ip saddr @{s4} counter drop\n\
             add rule {fam} {tbl} input ip6 saddr @{s6} counter drop\n",
            fam = self.family,
            tbl = self.table,
            s4 = self.set_v4,
            s6 = self.set_v6,
        )
    }

    /// Initializes the `nftables` table, sets, and input drop chain.
    pub fn init(&self) -> Result<(), String> {
        let script = self.build_init_script();
        if self.dry_run {
            eprintln!("[dry-run] nftables init script:\n{}", script.trim_end());
            return Ok(());
        }
        Self::run_nft_script(&script)
    }

    /// Applies a batch of ban decisions in a single atomic `nft -f -` transaction.
    pub fn apply_bans(&mut self, bans: &[BanDecision]) -> Result<(), String> {
        if bans.is_empty() {
            return Ok(());
        }
        self.batch_buf.clear();
        for b in bans {
            self.append_ban_cmd(b.ip, b.bantime_secs);
        }

        if self.dry_run {
            for line in self.batch_buf.lines() {
                eprintln!("[dry-run] nft: {line}");
            }
            return Ok(());
        }

        Self::run_nft_script(&self.batch_buf)
    }

    /// Bans or updates the ban duration of a single IP or `/64` prefix.
    /// Deletes any existing element first so `nftables` interval sets update `expires` reliably.
    pub fn ban_single(&mut self, ip: IpKey, bantime_secs: u32) -> Result<(), String> {
        let _ = self.unban_single(ip);
        self.batch_buf.clear();
        self.append_ban_cmd(ip, bantime_secs);
        if self.dry_run {
            eprintln!("[dry-run] nft: {}", self.batch_buf.trim_end());
            return Ok(());
        }
        Self::run_nft_script(&self.batch_buf)
    }

    /// Unbans any active kernel elements that fall within `cidr`.
    pub fn unban_matching_cidr(&self, cidr: Cidr) -> Result<usize, String> {
        let active = self.list_active_bans().unwrap_or_default();
        let mut count = 0;
        for elem in active {
            let base = elem.ip_str.split('/').next().unwrap_or(&elem.ip_str);
            if let Ok(addr) = base.parse::<IpAddr>() {
                let key = IpKey::from_ip_addr(addr);
                let inside = match key {
                    IpKey::V4(v4) => cidr.contains_v4(v4),
                    IpKey::V6Prefix64(p64) => cidr.contains_v6_prefix64(p64),
                };
                if inside && self.unban_single(key).is_ok() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Returns all active ban elements parsed from `nft list table`.
    pub fn list_active_bans(&self) -> Result<Vec<ActiveBanElement>, String> {
        let out = self.status()?;
        Ok(parse_nft_active_bans(&out))
    }

    /// Unbans a single IP or `/64` prefix from the kernel set.
    pub fn unban_single(&self, ip: IpKey) -> Result<(), String> {
        let (set_name, elem) = match ip {
            IpKey::V4(v4) => (&self.set_v4, crate::config::format_ipv4(v4)),
            IpKey::V6Prefix64(p64) => (&self.set_v6, crate::config::format_ipv6_prefix64(p64)),
        };
        let cmd = format!(
            "delete element {} {} {} {{ {} }}\n",
            self.family, self.table, set_name, elem
        );
        if self.dry_run {
            eprintln!("[dry-run] nft: {}", cmd.trim_end());
            return Ok(());
        }
        Self::run_nft_script(&cmd)
    }

    /// Flushes all active bans in both IPv4 and IPv6 sets.
    pub fn flush_sets(&self) -> Result<(), String> {
        let script = format!(
            "flush set {fam} {tbl} {s4}\nflush set {fam} {tbl} {s6}\n",
            fam = self.family,
            tbl = self.table,
            s4 = self.set_v4,
            s6 = self.set_v6,
        );
        if self.dry_run {
            eprintln!("[dry-run] nft:\n{}", script.trim_end());
            return Ok(());
        }
        Self::run_nft_script(&script)
    }

    /// Queries the current `nftables` status for `table inet kiban`.
    pub fn status(&self) -> Result<String, String> {
        let output = Command::new("nft")
            .args(["list", "table", &self.family, &self.table])
            .output()
            .map_err(|e| format!("failed to execute 'nft': {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nft list table failed: {}", stderr.trim()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn append_ban_cmd(&mut self, ip: IpKey, bantime_secs: u32) {
        let timeout = bantime_secs.max(1);
        match ip {
            IpKey::V4(v4) => {
                let addr = std::net::Ipv4Addr::from(v4);
                // Resetting timeout in nftables: `add element` (or delete+add for interval sets on older kernels)
                let _ = writeln!(
                    self.batch_buf,
                    "add element {} {} {} {{ {} timeout {}s }}",
                    self.family, self.table, self.set_v4, addr, timeout
                );
            }
            IpKey::V6Prefix64(p64) => {
                let full = (p64 as u128) << 64;
                let addr = std::net::Ipv6Addr::from(full);
                let _ = writeln!(
                    self.batch_buf,
                    "add element {} {} {} {{ {}/64 timeout {}s }}",
                    self.family, self.table, self.set_v6, addr, timeout
                );
            }
        }
    }

    fn run_nft_script(script: &str) -> Result<(), String> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn 'nft -f -': {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("failed to write to nft stdin: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed waiting for 'nft': {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nft error: {}", stderr.trim()));
        }
        Ok(())
    }
}

/// Parses `elements = { ... }` blocks from `nft list table` output.
pub fn parse_nft_active_bans(nft_output: &str) -> Vec<ActiveBanElement> {
    let mut results = Vec::new();
    let mut search_pos = 0;

    while let Some(rel_idx) = nft_output[search_pos..].find("elements = {") {
        let block_start = search_pos + rel_idx + "elements = {".len();
        let Some(rel_end) = nft_output[block_start..].find('}') else {
            break;
        };
        let block = &nft_output[block_start..block_start + rel_end];
        search_pos = block_start + rel_end + 1;

        for raw_entry in block.split(',') {
            let entry = raw_entry.trim();
            if entry.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = entry.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }
            let ip_str = tokens[0].to_string();
            let mut timeout = String::from("-");
            let mut expires = String::from("permanent");

            let mut i = 1;
            while i + 1 < tokens.len() {
                match tokens[i] {
                    "timeout" => {
                        timeout = tokens[i + 1].to_string();
                        i += 2;
                    }
                    "expires" => {
                        expires = tokens[i + 1].to_string();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            if let Some((start_s, end_s)) = ip_str.split_once('-') {
                if let (Ok(start_ip), Ok(end_ip)) =
                    (start_s.trim().parse::< std::net::Ipv4Addr>(), end_s.trim().parse::<std::net::Ipv4Addr>())
                {
                    let s_u32 = u32::from(start_ip);
                    let e_u32 = u32::from(end_ip);
                    if e_u32 >= s_u32 && (e_u32 - s_u32) <= 256 {
                        for addr_u32 in s_u32..=e_u32 {
                            results.push(ActiveBanElement {
                                ip_str: std::net::Ipv4Addr::from(addr_u32).to_string(),
                                timeout: timeout.clone(),
                                expires: expires.clone(),
                            });
                        }
                        continue;
                    }
                }
            }

            results.push(ActiveBanElement {
                ip_str,
                timeout,
                expires,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_nft_active_bans() {
        let sample = r#"
table inet kiban {
	set blacklist_v4 {
		type ipv4_addr
		flags interval,timeout
		auto-merge
		elements = { 203.0.113.126 timeout 7d expires 6d23h56m2s508ms,
			     198.51.100.42 timeout 1h expires 45m12s }
	}
	set blacklist_v6 {
		type ipv6_addr
		flags interval,timeout
		auto-merge
		elements = { 2001:db8:dead:beef::/64 timeout 2h expires 1h59m }
	}
}
"#;
        let parsed = parse_nft_active_bans(sample);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].ip_str, "203.0.113.126");
        assert_eq!(parsed[0].timeout, "7d");
        assert_eq!(parsed[0].expires, "6d23h56m2s508ms");
        assert_eq!(parsed[2].ip_str, "2001:db8:dead:beef::/64");
    }

    #[test]
    fn test_init_script_and_batch_formatting() {
        let mut cfg = Config::default();
        cfg.dry_run = true;
        let mut fw = Firewall::new(&cfg);

        let init = fw.build_init_script();
        assert!(init.contains("add table inet kiban"));
        assert!(init.contains("flags interval, timeout; auto-merge;"));
        assert!(init.contains("ip saddr @blacklist_v4 counter drop"));
        assert!(init.contains("ip6 saddr @blacklist_v6 counter drop"));

        let bans = vec![
            BanDecision {
                ip: IpKey::V4(u32::from(Ipv4Addr::new(198, 51, 100, 12))),
                jail_id: 0,
                bantime_secs: 3600,
                failures: 5,
                strikes: 1,
                report_to_ipspace: true,
                via_ipspace: false,
            },
            BanDecision {
                ip: IpKey::V6Prefix64(0x2001_0db8_abcd_1234),
                jail_id: 0,
                bantime_secs: 7200,
                failures: 5,
                strikes: 2,
                report_to_ipspace: false,
                via_ipspace: true,
            },
        ];

        fw.apply_bans(&bans).unwrap();
        assert!(fw
            .batch_buf
            .contains("add element inet kiban blacklist_v4 { 198.51.100.12 timeout 3600s }"));
        assert!(fw
            .batch_buf
            .contains("add element inet kiban blacklist_v6 { 2001:db8:abcd:1234::/64 timeout 7200s }"));
    }
}
