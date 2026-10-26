use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::config::{Config, LogSource};
use crate::firewall::Firewall;
use crate::matcher;
use crate::tracker::{BanDecision, IpTracker};

// --- Minimal Linux libc FFI declarations (zero external crate dependencies) ---
const EPOLL_CLOEXEC: i32 = 0x80000;
const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLLIN: u32 = 0x001;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;

const IN_NONBLOCK: i32 = 0x800;
const IN_CLOEXEC: i32 = 0x80000;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0x800;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy, Default)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
struct InotifyEventHeader {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
}

extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, pathname: *const u8, mask: u32) -> i32;
    fn inotify_rm_watch(fd: i32, wd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_sig: i32) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

extern "C" fn handle_reload_signal(_sig: i32) {
    RELOAD_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn install_signal_handlers() {
    unsafe {
        signal(SIGHUP, handle_reload_signal as *const () as usize);
        signal(SIGINT, handle_termination_signal as *const () as usize);
        signal(SIGTERM, handle_termination_signal as *const () as usize);
    }
}

/// Fixed-capacity line buffer that slices incoming byte streams without heap allocations per line.
struct LineBuffer {
    buf: Box<[u8; 8192]>,
    len: usize,
}

impl LineBuffer {
    fn new() -> Self {
        Self {
            buf: Box::new([0u8; 8192]),
            len: 0,
        }
    }
}

struct FileTailer {
    path: PathBuf,
    parent_dir: PathBuf,
    jail_indices: Vec<usize>,
    file: Option<File>,
    inode: u64,
    offset: u64,
    file_wd: i32,
    dir_wd: i32,
    line_buf: LineBuffer,
}

impl FileTailer {
    fn new(path: PathBuf, jail_indices: Vec<usize>) -> Self {
        let parent_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        Self {
            path,
            parent_dir,
            jail_indices,
            file: None,
            inode: 0,
            offset: 0,
            file_wd: -1,
            dir_wd: -1,
            line_buf: LineBuffer::new(),
        }
    }

    fn open_initial(&mut self, inotify_fd: RawFd, seek_to_end: bool) {
        self.register_dir_watch(inotify_fd);
        if let Ok(mut f) = OpenOptions::new().read(true).open(&self.path) {
            if let Ok(meta) = f.metadata() {
                self.inode = meta.ino();
                self.offset = if seek_to_end {
                    let end = meta.len();
                    let _ = f.seek(SeekFrom::Start(end));
                    end
                } else {
                    0
                };
            }
            self.file = Some(f);
            self.register_file_watch(inotify_fd);
        }
    }

    fn register_dir_watch(&mut self, inotify_fd: RawFd) {
        if self.dir_wd >= 0 {
            return;
        }
        if let Some(c_path) = to_cstring_bytes(&self.parent_dir) {
            let wd = unsafe {
                inotify_add_watch(
                    inotify_fd,
                    c_path.as_ptr(),
                    IN_CREATE | IN_MOVED_TO | IN_MODIFY,
                )
            };
            if wd >= 0 {
                self.dir_wd = wd;
            }
        }
    }

    fn register_file_watch(&mut self, inotify_fd: RawFd) {
        if self.file_wd >= 0 {
            unsafe {
                inotify_rm_watch(inotify_fd, self.file_wd);
            }
            self.file_wd = -1;
        }
        if let Some(c_path) = to_cstring_bytes(&self.path) {
            let wd = unsafe {
                inotify_add_watch(
                    inotify_fd,
                    c_path.as_ptr(),
                    IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB,
                )
            };
            if wd >= 0 {
                self.file_wd = wd;
            }
        }
    }

    /// Reads newly appended lines, detects log rotation or truncation, and invokes `on_line`.
    fn read_pending<F>(&mut self, inotify_fd: RawFd, mut on_line: F)
    where
        F: FnMut(&[usize], &[u8]),
    {
        if self.file.is_none() {
            self.open_initial(inotify_fd, false);
        }

        // Read all available data from currently open file
        self.drain_open_file(&mut on_line);

        // Check if file was rotated (inode changed on disk) or truncated (size < offset)
        match fs::metadata(&self.path) {
            Ok(disk_meta) => {
                if self.file.is_none() || disk_meta.ino() != self.inode {
                    // File was rotated: drain any last bytes from old file, then open new file from start
                    self.drain_open_file(&mut on_line);
                    self.line_buf.len = 0;
                    self.file = None;
                    self.open_initial(inotify_fd, false);
                    self.drain_open_file(&mut on_line);
                } else if disk_meta.len() < self.offset {
                    // File was truncated in-place (`copytruncate`)
                    if let Some(ref mut f) = self.file {
                        let _ = f.seek(SeekFrom::Start(0));
                        self.offset = 0;
                        self.line_buf.len = 0;
                    }
                    self.drain_open_file(&mut on_line);
                }
            }
            Err(_) => {
                // File temporarily missing during rotation
                self.file = None;
                self.inode = 0;
                self.offset = 0;
            }
        }
    }

    fn drain_open_file<F>(&mut self, on_line: &mut F)
    where
        F: FnMut(&[usize], &[u8]),
    {
        let Some(ref mut file) = self.file else {
            return;
        };

        loop {
            let avail_space = self.line_buf.buf.len() - self.line_buf.len;
            if avail_space == 0 {
                // Line exceeded 8 KB buffer: flush as a chunk and reset to prevent lockup
                on_line(&self.jail_indices, &self.line_buf.buf[..]);
                self.line_buf.len = 0;
                continue;
            }

            match file.read(&mut self.line_buf.buf[self.line_buf.len..]) {
                Ok(0) => break, // EOF reached
                Ok(n) => {
                    self.offset += n as u64;
                    self.line_buf.len += n;
                    process_buffered_lines(&mut self.line_buf, &self.jail_indices, on_line);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
}

struct JournalStream {
    unit: String,
    jail_indices: Vec<usize>,
    child: Option<Child>,
    stdout_fd: RawFd,
    line_buf: LineBuffer,
}

impl JournalStream {
    fn new(unit: String, jail_indices: Vec<usize>) -> Self {
        Self {
            unit,
            jail_indices,
            child: None,
            stdout_fd: -1,
            line_buf: LineBuffer::new(),
        }
    }

    fn spawn(&mut self, epoll_fd: RawFd, token: u64) -> Result<(), String> {
        let child = Command::new("journalctl")
            .args([
                "-f",
                "-q",
                "-o",
                "cat",
                "--no-tail",
                "-n",
                "0",
                "-u",
                &self.unit,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn journalctl for unit '{}': {e}", self.unit))?;

        let stdout = child
            .stdout
            .as_ref()
            .ok_or_else(|| "failed to capture journalctl stdout".to_string())?;
        let fd = stdout.as_raw_fd();
        set_nonblocking(fd);

        let mut ev = EpollEvent {
            events: EPOLLIN,
            data: token,
        };
        let rc = unsafe { epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &mut ev) };
        if rc < 0 {
            return Err(format!(
                "epoll_ctl failed for journalctl unit '{}'",
                self.unit
            ));
        }

        self.stdout_fd = fd;
        self.child = Some(child);
        Ok(())
    }

    fn read_pending<F>(&mut self, mut on_line: F) -> bool
    where
        F: FnMut(&[usize], &[u8]),
    {
        if self.stdout_fd < 0 {
            return false;
        }
        loop {
            let avail = self.line_buf.buf.len() - self.line_buf.len;
            if avail == 0 {
                on_line(&self.jail_indices, &self.line_buf.buf[..]);
                self.line_buf.len = 0;
                continue;
            }
            let n = unsafe {
                read(
                    self.stdout_fd,
                    self.line_buf.buf[self.line_buf.len..].as_mut_ptr() as *mut core::ffi::c_void,
                    avail,
                )
            };
            if n > 0 {
                self.line_buf.len += n as usize;
                process_buffered_lines(&mut self.line_buf, &self.jail_indices, &mut on_line);
            } else if n == 0 {
                // EOF on pipe
                return false;
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return true;
                }
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
        }
    }

    fn cleanup(&mut self, epoll_fd: RawFd) {
        if self.stdout_fd >= 0 {
            unsafe {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, self.stdout_fd, std::ptr::null_mut());
            }
            self.stdout_fd = -1;
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn process_buffered_lines<F>(line_buf: &mut LineBuffer, jail_indices: &[usize], on_line: &mut F)
where
    F: FnMut(&[usize], &[u8]),
{
    let mut start = 0;
    while let Some(rel_nl) = line_buf.buf[start..line_buf.len]
        .iter()
        .position(|&b| b == b'\n')
    {
        let end = start + rel_nl;
        let mut line = &line_buf.buf[start..end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if !line.is_empty() {
            on_line(jail_indices, line);
        }
        start = end + 1;
    }

    if start > 0 {
        let remaining = line_buf.len - start;
        if remaining > 0 {
            line_buf.buf.copy_within(start..line_buf.len, 0);
        }
        line_buf.len = remaining;
    }
}

fn to_cstring_bytes(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return None;
    }
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    Some(v)
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags >= 0 {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
    }
}

const TOKEN_INOTIFY: u64 = 0;
const TOKEN_JOURNAL_BASE: u64 = 1000;

/// Runs the main single-threaded `epoll` + `inotify` event loop.
pub fn run_daemon(cfg: &mut Config, config_path: Option<&str>) -> Result<(), String> {
    install_signal_handlers();

    let mut fw = Firewall::new(cfg);
    fw.init()?;

    let mut tracker = IpTracker::new(cfg.max_tracked_ips);
    let boot_instant = Instant::now();

    let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(format!(
            "epoll_create1 failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let inotify_fd = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
    if inotify_fd < 0 {
        unsafe { close(epoll_fd) };
        return Err(format!(
            "inotify_init1 failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut inotify_ev = EpollEvent {
        events: EPOLLIN,
        data: TOKEN_INOTIFY,
    };
    if unsafe { epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &mut inotify_ev) } < 0 {
        unsafe {
            close(inotify_fd);
            close(epoll_fd);
        }
        return Err("epoll_ctl failed for inotify_fd".to_string());
    }

    // Group file and journal sources across enabled jails so each unique file/unit is read only once
    let mut file_tailers: Vec<FileTailer> = Vec::new();
    let mut journal_streams: Vec<JournalStream> = Vec::new();

    for (jail_idx, jail) in cfg.jails.iter().enumerate() {
        if !jail.enabled {
            continue;
        }
        for src in &jail.sources {
            match src {
                LogSource::File(p) => {
                    let pb = PathBuf::from(p);
                    if let Some(existing) = file_tailers.iter_mut().find(|t| t.path == pb) {
                        if !existing.jail_indices.contains(&jail_idx) {
                            existing.jail_indices.push(jail_idx);
                        }
                    } else {
                        file_tailers.push(FileTailer::new(pb, vec![jail_idx]));
                    }
                }
                LogSource::Journal(unit) => {
                    if let Some(existing) = journal_streams.iter_mut().find(|j| &j.unit == unit) {
                        if !existing.jail_indices.contains(&jail_idx) {
                            existing.jail_indices.push(jail_idx);
                        }
                    } else {
                        journal_streams.push(JournalStream::new(unit.clone(), vec![jail_idx]));
                    }
                }
            }
        }
    }

    for tailer in &mut file_tailers {
        tailer.open_initial(inotify_fd, true);
    }

    for (idx, js) in journal_streams.iter_mut().enumerate() {
        if let Err(e) = js.spawn(epoll_fd, TOKEN_JOURNAL_BASE + idx as u64) {
            eprintln!("[kiban] warning: {e}");
        }
    }

    eprintln!(
        "[kiban] started: watching {} file(s), {} journal stream(s) | tracker capacity={} ({} KB) | rss={} KB",
        file_tailers.len(),
        journal_streams.len(),
        tracker.capacity(),
        tracker.memory_bytes() / 1024,
        read_current_rss_kb().unwrap_or(0)
    );

    let mut events = [EpollEvent::default(); 16];
    let mut inotify_buf = [0u8; 4096];
    let mut pending_bans: Vec<BanDecision> = Vec::with_capacity(16);

    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        if RELOAD_REQUESTED.swap(false, Ordering::SeqCst) {
            if let Some(p) = config_path {
                match Config::load_from_file(p) {
                    Ok(new_cfg) => {
                        cfg.whitelist = new_cfg.whitelist;
                        cfg.ipspace = new_cfg.ipspace;
                        eprintln!(
                            "[kiban] reloaded configuration from '{}' via SIGHUP (whitelist_cidrs={})",
                            p,
                            cfg.whitelist.len()
                        );
                    }
                    Err(e) => eprintln!("[kiban] SIGHUP reload failed: {e}"),
                }
            }
        }

        // Reap any completed async ipspace `curl` child processes so zombies never accumulate
        let has_pending_reports = crate::ipspace::reap_finished_reports();
        let wait_timeout_ms = if has_pending_reports { 500 } else { 30_000 };

        // Sleep in kernel until an event arrives (or wake to reap pending reports / check missing files)
        let n_events = unsafe { epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, wait_timeout_ms) };
        if n_events < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        let now_secs = (boot_instant.elapsed().as_secs() as u32).saturating_add(1);
        pending_bans.clear();

        if n_events == 0 {
            // Periodic check for log files that did not exist at startup
            for tailer in &mut file_tailers {
                if tailer.file.is_none() {
                    tailer.read_pending(inotify_fd, |jail_idxs, line| {
                        evaluate_line(cfg, &mut tracker, jail_idxs, line, now_secs, &mut pending_bans);
                    });
                }
            }
        }

        for i in 0..(n_events as usize) {
            let token = events[i].data;
            let ev_mask = events[i].events;

            if token == TOKEN_INOTIFY {
                // Drain inotify events
                loop {
                    let n = unsafe {
                        read(
                            inotify_fd,
                            inotify_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            inotify_buf.len(),
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    let mut offset = 0usize;
                    while offset + std::mem::size_of::<InotifyEventHeader>() <= (n as usize) {
                        let hdr = unsafe {
                            &*(inotify_buf.as_ptr().add(offset) as *const InotifyEventHeader)
                        };
                        let wd = hdr.wd;
                        for tailer in &mut file_tailers {
                            if tailer.file_wd == wd || tailer.dir_wd == wd {
                                tailer.read_pending(inotify_fd, |jail_idxs, line| {
                                    evaluate_line(
                                        cfg,
                                        &mut tracker,
                                        jail_idxs,
                                        line,
                                        now_secs,
                                        &mut pending_bans,
                                    );
                                });
                            }
                        }
                        offset += std::mem::size_of::<InotifyEventHeader>() + (hdr.len as usize);
                    }
                }
            } else if token >= TOKEN_JOURNAL_BASE {
                let js_idx = (token - TOKEN_JOURNAL_BASE) as usize;
                if let Some(js) = journal_streams.get_mut(js_idx) {
                    let alive = js.read_pending(|jail_idxs, line| {
                        evaluate_line(cfg, &mut tracker, jail_idxs, line, now_secs, &mut pending_bans);
                    });
                    if !alive || (ev_mask & (EPOLLHUP | EPOLLERR)) != 0 {
                        js.cleanup(epoll_fd);
                        let _ = js.spawn(epoll_fd, token);
                    }
                }
            }
        }

        if !pending_bans.is_empty() {
            for ban in &pending_bans {
                let jail = &cfg.jails[ban.jail_id as usize];
                let via = if ban.via_ipspace { "ipspace" } else { "local" };
                eprintln!(
                    "[kiban] BAN ip={} jail={} bantime={}s failures={} strike={} via={}",
                    ban.ip.format_nft(),
                    jail.name,
                    ban.bantime_secs,
                    ban.failures,
                    ban.strikes,
                    via
                );
                if ban.report_to_ipspace {
                    crate::ipspace::report_ban_async(&cfg.ipspace, ban.ip, &jail.reason, cfg.dry_run);
                }
            }
            if let Err(e) = fw.apply_bans(&pending_bans) {
                eprintln!("[kiban] firewall error: {e}");
            }
        }
    }

    for js in &mut journal_streams {
        js.cleanup(epoll_fd);
    }
    unsafe {
        close(inotify_fd);
        close(epoll_fd);
    }
    eprintln!(
        "[kiban] stopped cleanly (events={}, bans={}, ipspace_instant_bans={})",
        tracker.total_events, tracker.total_bans, tracker.ipspace_instant_bans
    );
    Ok(())
}

#[inline]
pub fn evaluate_line(
    cfg: &Config,
    tracker: &mut IpTracker,
    jail_indices: &[usize],
    line: &[u8],
    now_secs: u32,
    pending_bans: &mut Vec<BanDecision>,
) {
    for &j_idx in jail_indices {
        let jail = &cfg.jails[j_idx];
        if let Some(m) = matcher::match_line(&jail.parser, line) {
            if let Some(decision) = tracker.record_offense(cfg, jail, m.ip, m.weight, now_secs) {
                pending_bans.push(decision);
            }
        }
    }
}

#[inline]
pub fn evaluate_line_offline(
    cfg: &Config,
    tracker: &mut IpTracker,
    jail_indices: &[usize],
    line: &[u8],
    now_secs: u32,
    pending_bans: &mut Vec<BanDecision>,
) {
    for &j_idx in jail_indices {
        let jail = &cfg.jails[j_idx];
        if let Some(m) = matcher::match_line(&jail.parser, line) {
            if let Some(decision) =
                tracker.record_offense_offline(cfg, jail, m.ip, m.weight, now_secs)
            {
                pending_bans.push(decision);
            }
        }
    }
}

/// Reads current process Resident Set Size (VmRSS) in KB from `/proc/self/status`.
pub fn read_current_rss_kb() -> Option<usize> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let num_str = rest.trim().strip_suffix("kB").unwrap_or(rest).trim();
            return num_str.parse().ok();
        }
    }
    None
}
