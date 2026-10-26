use crate::config::{Config, JailConfig};
use crate::ipspace::{self, IpSpaceVerdict};
use crate::matcher::IpKey;

const FLAG_OCCUPIED: u8 = 0b0000_0001;
const FLAG_IPV6: u8 = 0b0000_0010;
const FLAG_API_CHECKED: u8 = 0b0000_0100;
const FLAG_API_ALLOW: u8 = 0b0000_1000;
const MAX_PROBE_LEN: usize = 16;

/// Fixed 24-byte slot in the pre-allocated open-addressing state table.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TrackerSlot {
    pub key_bits: u64,
    pub window_start: u32,
    pub banned_until: u32,
    pub last_seen: u32,
    pub failures: u16,
    pub strikes: u8,
    pub flags: u8,
}

impl TrackerSlot {
    #[inline]
    fn is_occupied(&self) -> bool {
        (self.flags & FLAG_OCCUPIED) != 0
    }

    #[inline]
    fn matches(&self, ip: IpKey, jail_id: u8) -> bool {
        if !self.is_occupied() {
            return false;
        }
        let slot_jail = self.flags >> 4;
        if slot_jail != (jail_id & 0x0F) {
            return false;
        }
        match ip {
            IpKey::V4(v4) => (self.flags & FLAG_IPV6) == 0 && self.key_bits == (v4 as u64),
            IpKey::V6Prefix64(p64) => (self.flags & FLAG_IPV6) != 0 && self.key_bits == p64,
        }
    }

    #[inline]
    fn encode_flags(ip: IpKey, jail_id: u8) -> (u64, u8) {
        let jail_bits = (jail_id & 0x0F) << 4;
        match ip {
            IpKey::V4(v4) => (v4 as u64, FLAG_OCCUPIED | jail_bits),
            IpKey::V6Prefix64(p64) => (p64, FLAG_OCCUPIED | FLAG_IPV6 | jail_bits),
        }
    }
}

/// Decision returned when an offending log line triggers a ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanDecision {
    pub ip: IpKey,
    pub jail_id: u8,
    pub bantime_secs: u32,
    pub failures: u16,
    pub strikes: u8,
    /// True if this ban was triggered by local `maxretry` and should be reported (`a=ban`) to `ip.space.ua`.
    pub report_to_ipspace: bool,
    /// True if this ban was triggered immediately on the first offense by an `ip.space.ua` `a=found` verdict.
    pub via_ipspace: bool,
}

/// Fixed-capacity, zero-runtime-allocation offense tracker.
pub struct IpTracker {
    slots: Box<[TrackerSlot]>,
    mask: usize,
    pub total_events: u64,
    pub total_bans: u64,
    pub ipspace_instant_bans: u64,
    pub whitelisted_hits: u64,
}

impl IpTracker {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(64).next_power_of_two();
        let slots = vec![TrackerSlot::default(); cap].into_boxed_slice();
        Self {
            slots,
            mask: cap - 1,
            total_events: 0,
            total_bans: 0,
            ipspace_instant_bans: 0,
            whitelisted_hits: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn memory_bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<TrackerSlot>()
    }

    pub fn occupied_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_occupied()).count()
    }

    /// Records an offense for `ip` in `jail` at monotonic timestamp `now_secs`,
    /// performing an `ip.space.ua` (`action=found`) lookup on the first offense if enabled.
    pub fn record_offense(
        &mut self,
        cfg: &Config,
        jail: &JailConfig,
        ip: IpKey,
        weight: u16,
        now_secs: u32,
    ) -> Option<BanDecision> {
        let ipspace_active = cfg.ipspace.enabled && !cfg.ipspace.token.is_empty();
        self.record_offense_with_hook(cfg, jail, ip, weight, now_secs, |q_ip, reason| {
            if !ipspace_active {
                return None;
            }
            match ipspace::query_ip(&cfg.ipspace, q_ip, reason, "found", cfg.dry_run) {
                Ok(verdict) => Some(verdict),
                Err(e) => {
                    eprintln!(
                        "[kiban] ipspace lookup warning for {}: {e}",
                        q_ip.format_nft()
                    );
                    None
                }
            }
        })
    }

    /// Records an offense without making network calls to `ip.space.ua` (used for offline log tests & benchmarks).
    pub fn record_offense_offline(
        &mut self,
        cfg: &Config,
        jail: &JailConfig,
        ip: IpKey,
        weight: u16,
        now_secs: u32,
    ) -> Option<BanDecision> {
        self.record_offense_with_hook(cfg, jail, ip, weight, now_secs, |_, _| None)
    }

    /// Core state machine with injectable threat-intelligence lookup hook.
    pub fn record_offense_with_hook<F>(
        &mut self,
        cfg: &Config,
        jail: &JailConfig,
        ip: IpKey,
        weight: u16,
        now_secs: u32,
        mut lookup_fn: F,
    ) -> Option<BanDecision>
    where
        F: FnMut(IpKey, &str) -> Option<IpSpaceVerdict>,
    {
        self.total_events += 1;

        // 1. Fast local CIDR whitelist check
        let is_whitelisted = match ip {
            IpKey::V4(v4) => cfg.is_whitelisted_v4(v4),
            IpKey::V6Prefix64(p64) => cfg.is_whitelisted_v6_prefix64(p64),
        };
        if is_whitelisted {
            self.whitelisted_hits += 1;
            return None;
        }

        let (key_bits, encoded_flags) = TrackerSlot::encode_flags(ip, jail.id);
        let start_idx = self.hash_index(key_bits, encoded_flags);

        let mut target_idx: Option<usize> = None;
        let mut oldest_idx = start_idx;
        let mut oldest_time = u32::MAX;

        for step in 0..MAX_PROBE_LEN {
            let idx = (start_idx + step) & self.mask;
            let slot = &self.slots[idx];

            if slot.matches(ip, jail.id) {
                target_idx = Some(idx);
                break;
            }
            if !slot.is_occupied() {
                target_idx = Some(idx);
                break;
            }
            if slot.last_seen < oldest_time {
                oldest_time = slot.last_seen;
                oldest_idx = idx;
            }
        }

        let idx = target_idx.unwrap_or(oldest_idx);
        let slot = &mut self.slots[idx];

        if !slot.matches(ip, jail.id) {
            *slot = TrackerSlot {
                key_bits,
                window_start: now_secs,
                banned_until: 0,
                last_seen: now_secs,
                failures: 0,
                strikes: 0,
                flags: encoded_flags,
            };
        }

        slot.last_seen = now_secs;

        // Suppress duplicate actions while an active ban is in effect
        if slot.banned_until > now_secs {
            return None;
        }

        // Reset sliding window and cached API flags if `findtime` has elapsed
        if now_secs.saturating_sub(slot.window_start) > jail.findtime_secs {
            slot.window_start = now_secs;
            slot.failures = 0;
            slot.flags &= !(FLAG_API_CHECKED | FLAG_API_ALLOW);
        }

        // Ignore if `ip.space.ua` already whitelisted this IP during the current window
        if (slot.flags & FLAG_API_ALLOW) != 0 {
            self.whitelisted_hits += 1;
            return None;
        }

        // On the very first suspicious event in the window, query `ip.space.ua` with `action=found`
        if (slot.flags & FLAG_API_CHECKED) == 0 {
            slot.flags |= FLAG_API_CHECKED;
            if let Some(verdict) = lookup_fn(ip, &jail.reason) {
                if verdict.is_allow() {
                    slot.flags |= FLAG_API_ALLOW;
                    self.whitelisted_hits += 1;
                    return None;
                }

                if verdict.should_ban_immediately(cfg.ipspace.risk_threshold) {
                    slot.strikes = slot.strikes.saturating_add(1);
                    let failures = slot.failures.saturating_add(weight.max(1));
                    let bantime_secs = if verdict.recommended_ttl > 0 {
                        verdict.recommended_ttl
                    } else {
                        compute_bantime(
                            jail.bantime_secs,
                            jail.bantime_multiplier,
                            jail.max_bantime_secs,
                            slot.strikes,
                        )
                    };
                    slot.banned_until = now_secs.saturating_add(bantime_secs);
                    let strikes = slot.strikes;
                    slot.failures = 0;
                    slot.window_start = now_secs;

                    self.total_bans += 1;
                    self.ipspace_instant_bans += 1;
                    return Some(BanDecision {
                        ip,
                        jail_id: jail.id,
                        bantime_secs,
                        failures,
                        strikes,
                        report_to_ipspace: true,
                        via_ipspace: true,
                    });
                }
            }
        }

        slot.failures = slot.failures.saturating_add(weight.max(1));

        if slot.failures >= jail.maxretry {
            slot.strikes = slot.strikes.saturating_add(1);
            let bantime_secs = compute_bantime(
                jail.bantime_secs,
                jail.bantime_multiplier,
                jail.max_bantime_secs,
                slot.strikes,
            );
            slot.banned_until = now_secs.saturating_add(bantime_secs);
            let failures = slot.failures;
            let strikes = slot.strikes;
            slot.failures = 0;
            slot.window_start = now_secs;

            self.total_bans += 1;
            return Some(BanDecision {
                ip,
                jail_id: jail.id,
                bantime_secs,
                failures,
                strikes,
                report_to_ipspace: true,
                via_ipspace: false,
            });
        }

        None
    }

    #[inline]
    fn hash_index(&self, key_bits: u64, flags: u8) -> usize {
        // Mask only address-type and jail_id bits (`0b1111_0011`) so API flags don't alter hash slot
        let identity_flags = flags & !(FLAG_API_CHECKED | FLAG_API_ALLOW);
        let mut h = key_bits ^ ((identity_flags as u64) << 56);
        h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        h ^= h >> 31;
        (h as usize) & self.mask
    }
}

#[inline]
fn compute_bantime(base: u32, multiplier: u16, max_bantime: u32, strikes: u8) -> u32 {
    if strikes <= 1 || multiplier <= 1 {
        return base.min(max_bantime);
    }
    let mut current = base as u64;
    let mult = multiplier as u64;
    let max_b = max_bantime as u64;
    for _ in 1..strikes {
        current = current.saturating_mul(mult);
        if current >= max_b {
            return max_bantime;
        }
    }
    (current as u32).min(max_bantime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_slot_size_is_24_bytes() {
        assert_eq!(std::mem::size_of::<TrackerSlot>(), 24);
    }

    #[test]
    fn test_sliding_window_and_exponential_backoff() {
        let cfg = Config::default();
        let jail = &cfg.jails[0];
        let mut tracker = IpTracker::new(1024);
        let attacker = IpKey::V4(u32::from(Ipv4Addr::new(203, 0, 113, 50)));

        for t in 100..104 {
            assert!(tracker.record_offense(&cfg, jail, attacker, 1, t).is_none());
        }
        let d1 = tracker.record_offense(&cfg, jail, attacker, 1, 105).unwrap();
        assert_eq!(d1.bantime_secs, 3600);
        assert_eq!(d1.strikes, 1);
        assert!(d1.report_to_ipspace);
        assert!(!d1.via_ipspace);

        assert!(tracker.record_offense(&cfg, jail, attacker, 5, 110).is_none());

        let d2 = tracker.record_offense(&cfg, jail, attacker, 5, 4000).unwrap();
        assert_eq!(d2.bantime_secs, 7200);
        assert_eq!(d2.strikes, 2);
    }

    #[test]
    fn test_ipspace_first_offense_instant_ban_and_allow() {
        let cfg = Config::default();
        let jail = &cfg.jails[0]; // maxretry = 5
        let mut tracker = IpTracker::new(256);

        // 1. Known malicious IP: banned immediately on 1st attempt with recommendedTtl = 604800s
        let bad_ip = IpKey::V4(u32::from(Ipv4Addr::new(80, 94, 92, 126)));
        let dec = tracker
            .record_offense_with_hook(&cfg, jail, bad_ip, 1, 100, |_, _| {
                Some(IpSpaceVerdict {
                    action: "found".to_string(),
                    recommended_action: "ban".to_string(),
                    recommended_ttl: 604800,
                    risk_score: 100,
                    is_whitelisted: false,
                    country_code: "RO".to_string(),
                    num_lists_found: 5,
                })
            })
            .unwrap();
        assert_eq!(dec.bantime_secs, 604800);
        assert_eq!(dec.failures, 1);
        assert!(dec.via_ipspace);
        assert!(dec.report_to_ipspace);

        // 2. Whitelisted IP via API: ignored across all attempts in the window, queried only once
        let good_ip = IpKey::V4(u32::from(Ipv4Addr::new(198, 51, 100, 77)));
        let mut api_calls = 0;
        for _ in 0..10 {
            let res = tracker.record_offense_with_hook(&cfg, jail, good_ip, 1, 200, |_, _| {
                api_calls += 1;
                Some(IpSpaceVerdict {
                    action: "found".to_string(),
                    recommended_action: "allow".to_string(),
                    recommended_ttl: 0,
                    risk_score: 0,
                    is_whitelisted: true,
                    country_code: "UA".to_string(),
                    num_lists_found: 0,
                })
            });
            assert!(res.is_none());
        }
        assert_eq!(api_calls, 1);

        // 3. Unknown IP (monitor verdict on 1st attempt): queried once, banned on 5th attempt with report_to_ipspace = true
        let new_ip = IpKey::V4(u32::from(Ipv4Addr::new(203, 0, 113, 88)));
        let mut monitor_calls = 0;
        for attempt in 1..=5 {
            let res = tracker.record_offense_with_hook(&cfg, jail, new_ip, 1, 300 + attempt, |_, _| {
                monitor_calls += 1;
                Some(IpSpaceVerdict {
                    action: "found".to_string(),
                    recommended_action: "monitor".to_string(),
                    recommended_ttl: 3600,
                    risk_score: 15,
                    is_whitelisted: false,
                    country_code: "US".to_string(),
                    num_lists_found: 0,
                })
            });
            if attempt < 5 {
                assert!(res.is_none());
            } else {
                let d = res.unwrap();
                assert!(!d.via_ipspace);
                assert!(d.report_to_ipspace);
                assert_eq!(d.failures, 5);
            }
        }
        assert_eq!(monitor_calls, 1);
    }

    #[test]
    fn test_whitelist_ignored() {
        let cfg = Config::default();
        let jail = &cfg.jails[0];
        let mut tracker = IpTracker::new(256);
        let localhost = IpKey::V4(u32::from(Ipv4Addr::new(127, 0, 0, 1)));

        for _ in 0..20 {
            assert!(tracker.record_offense(&cfg, jail, localhost, 5, 100).is_none());
        }
        assert_eq!(tracker.whitelisted_hits, 20);
        assert_eq!(tracker.total_bans, 0);
    }
}
