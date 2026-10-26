# kiban

**`kiban`** is an ultra-lightweight, zero-dependency intrusion prevention daemon and Fail2Ban alternative written in Rust for Linux (`epoll` + `inotify` + `systemd-journald` + `nftables`).

It is engineered from first principles to achieve **minimal CPU (~0.00% idle, <580 ns per log line)** and **minimal, strictly bounded RAM (~1.5–2.3 MB RSS)** even under heavy brute-force or DDoS attacks.

Repository: [https://github.com/kit400/kiban](https://github.com/kit400/kiban)

---

## Why `kiban` Instead of Fail2Ban?

Traditional `fail2ban` runs a multi-threaded Python runtime, evaluates dozens of backtracking regular expressions (PCRE) against every log line, persists state in SQLite, and maintains user-space timers to unban expired IPs. This typically consumes **35–120+ MB of RAM** and causes **CPU spikes** during brute-force waves or web vulnerability scans.

| Metric / Feature | Fail2Ban (Python) | `kiban` (Rust + nftables) |
| :--- | :--- | :--- |
| **Memory Footprint (RSS)** | 35 – 120+ MB | **~1.5 – 2.3 MB** (strictly bounded) |
| **Binary Size** | Python + libraries | **~418 KB** (0 external crates) |
| **Log Parsing Throughput** | ~10k – 30k lines/sec (Regex) | **~1,730,000+ lines/sec** (zero-alloc byte slices) |
| **Unban Mechanism** | User-space timer threads + subprocesses | **0% CPU in user-space** (native kernel `nftables` set `timeout`) |
| **IPv6 Subnet Protection** | Often bans single `/128` addresses | Automatically normalizes & bans IPv6 by **`/64` prefix** |
| **DDoS / OOM Resilience** | Unbounded heap growth | Fixed-size 24-byte slot open-addressing ring table |
| **Event Loop** | Polling / multi-threaded | Single-threaded Linux `epoll` + `inotify` (handles `logrotate`) |

---

## Architecture

1. **Zero-Polling Event Loop (`epoll` + `inotify` + `journald`)**:
   - Sleeps in the kernel via `epoll_wait` with **0.00% CPU usage** until new bytes are written to watched log files or `systemd-journald` streams.
   - Automatically handles log rotation (`logrotate` rename/create via parent directory watches and `inode` tracking, as well as in-place truncation `copytruncate`).
2. **Two-Stage Zero-Allocation Matcher**:
   - Reads log chunks into a fixed 8 KB buffer and slices lines as `&[u8]` without heap-allocating `String` objects.
   - Performs fast anchor pre-filtering before extracting IPv4 (`u32`) or IPv6 (`/64` prefix `u64`) directly from byte slices.
3. **Bounded 24-Byte Slot State Table**:
   - Pre-allocates a fixed power-of-two table at startup (default `8192` slots = **192 KB RAM**).
   - Tracks sliding window failure counts (`findtime`, `maxretry`) and repeat-offender strikes (`bantime_multiplier` exponential backoff).
4. **Kernel-Offloaded Ban Expiration (`nftables`)**:
   - Maintains `table inet kiban` with `blacklist_v4` and `blacklist_v6` sets configured with `flags interval, timeout; auto-merge;`.
   - Applies bans in atomic batches via `nft -f -`. Once added, the Linux kernel automatically drops packets from the offending IP/prefix and removes the entry when `timeout` expires.
5. **Real-Time Threat Intelligence Integration ([`ip.space.ua`](https://ip.space.ua/docs#endpoint-query))**:
   - On the very first suspicious log entry for an IP in a tracking window, `kiban` queries `GET https://ip.space.ua/api?t=<TOKEN>&s=<SOURCE>&ip=<IP>&r=<REASON>&a=found`.
   - If the API returns `AIDBisWhitelisted=1` or `recommendedAction="allow"`, the IP is ignored for the remainder of the window.
   - If the API returns `action="ban"`, `recommendedAction="ban"`, `recommendedAction="tarpit"`, or `riskScore >= risk_threshold`, `kiban` immediately bans the IP on the 1st attempt using `recommendedTtl` from the API response.
   - Otherwise, `kiban` caches the check in the 24-byte `TrackerSlot` (preventing duplicate `action=found` calls), counts attempts up to `maxretry`, and reports `action=ban` to `ip.space.ua` if the threshold is crossed.

---

## Supported Protections (Jails)

- **`sshd` (OpenSSH)**:
  - Detects `Failed password`, `Failed publickey`, `Failed keyboard-interactive`, `Invalid user`, `Connection closed/reset by authenticating/invalid user [preauth]`, `Disconnecting authenticating/invalid user`, `maximum authentication attempts exceeded`, `Unable to negotiate`, `Did not receive identification string`, `Bad protocol version identification`, and PAM `authentication failure ... rhost=`.
- **`http-access` (Nginx / Caddy / Apache Access Logs — CLF, Combined & JSON)**:
  - Detects authentication brute-force (`401`, `403`, `444` status codes).
  - Detects and immediately penalizes vulnerability scanners probing `/.env`, `/.git/`, `/.aws/`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin`, `/vendor/phpunit`, `/eval-stdin.php`, `/actuator/`, `/cgi-bin/`, `/etc/passwd`, `../`, `/boaform/`, `/HNAP1`, etc. (configurable `scanner_weight`).
- **`http-error` (Nginx / Apache Error Logs)**:
  - Detects basic auth password mismatches, missing users, forbidden rules, ModSecurity denials, and rate-limit violations.
- **`custom` (Arbitrary Text Logs)**:
  - Fast pipe-separated substring matching (`match`, `ignore`, `ip_after`) without regular expression complexity.

---

## Building & Installation

### One-Line Install / Update

Install or update `kiban` directly from GitHub (preserves existing `/etc/kiban/kiban.conf` and active `nftables` bans):

```bash
curl -sSL https://raw.githubusercontent.com/kit400/kiban/main/scripts/update.sh | bash
```

### Build from Source

`kiban` uses only the Rust standard library and Linux `libc` (zero external Cargo dependencies):

```bash
git clone https://github.com/kit400/kiban.git
cd kiban
cargo test
cargo build --release
```

### Install as a Systemd Service

```bash
sudo install -m 0755 target/release/kiban /usr/local/bin/kiban
sudo mkdir -p /etc/kiban
sudo cp kiban.conf.example /etc/kiban/kiban.conf
sudo cp kiban.service /etc/systemd/system/kiban.service
sudo systemctl daemon-reload
sudo systemctl enable --now kiban
```

---

## CLI Usage

```text
USAGE:
  kiban [tui] [-c <kiban.conf>]                   Launch interactive fzf TUI console
  kiban run [-c <kiban.conf>] [--dry-run]         Start the event-driven protection daemon
  kiban status [-c <kiban.conf>]                  Show active jails, nftables bans & counters
  kiban lookup <IP> [reason] [action]             Query ip.space.ua threat verdict for an IP
  kiban preview <IP> [-c <kiban.conf>]            Display full IP dossier & log evidence
  kiban ban <IP> [duration] [-c <kiban.conf>]     Ban an IPv4/IPv6 address (or update timeout)
  kiban unban <IP> [-c <kiban.conf>]              Unban an IPv4 or IPv6 (/64) address
  kiban whitelist <add|remove|list> [IP/CIDR]     Manage whitelist entries & reload daemon
  kiban flush [-c <kiban.conf>]                   Flush all active bans from nftables sets
  kiban test [-c <kiban.conf>] <logfile>          Dry-run log parser & tracker on a log file
  kiban benchmark [num_lines]                     Run zero-alloc speed & RAM footprint benchmark
  kiban print-nft [-c <kiban.conf>]               Print generated nftables ruleset
```

### Interactive `fzf` TUI Console

Running `sudo kiban` (or `sudo kiban tui`) opens a full-screen interactive console powered by `fzf`:
- **Fuzzy Search**: Filter across `[BANNED]` active kernel elements, `[HIST]` historical bans from `journalctl`, and `[WHITE]` whitelist CIDRs from `kiban.conf`.
- **Live Preview Pane (`--preview`)**: Shows real-time `nftables` status, the full `ip.space.ua` Threat Intelligence dossier (Risk Score, Country, ASN/ISP, Blacklists, Attack Count), `kiban` journal history, and matching raw log lines from `/var/log/auth.log` and `/var/log/nginx/*.log`.
- **Hotkeys & Action Menu**:
  - `Enter`: Open context-aware Action Menu for the selected IP(s)
  - `Tab`: Multi-select rows for batch actions
  - `Ctrl-U`: Immediately unban selected IP(s) from `nftables`
  - `Ctrl-W`: Unban and add IP (`/32` or `/128`) to `whitelist` in `kiban.conf` + reload daemon via `SIGHUP`
  - `Ctrl-N`: Unban and add network subnet (`/24` or `/64`) to `whitelist` in `kiban.conf` + reload daemon via `SIGHUP`
  - `Ctrl-E`: Change or extend ban duration (`15m`, `1h`, `6h`, `24h`, `3d`, `7d`, `30d`, `90d`, `365d`, or custom)
  - `Ctrl-B`: Manually ban a new IP address and report `action=ban` to `ip.space.ua`
  - `Ctrl-R`: Refresh table

### Examples

Run synthetic benchmark (2,000,000 log lines):
```bash
./target/release/kiban benchmark 2000000
```

Test configuration against an existing log file without modifying firewall rules:
```bash
./target/release/kiban test -c kiban.conf.example /var/log/auth.log
```

Manually ban an IP for 12 hours or unban it:
```bash
sudo kiban ban 203.0.113.42 12h
sudo kiban ban 2001:db8:abcd:1234::1 24h
sudo kiban status
sudo kiban unban 203.0.113.42
```

---

## License

MIT License — see [LICENSE](LICENSE).
