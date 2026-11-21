// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! MAC-Telnet server (port of `mactelnetd.c`): accepts sessions from
//! mactelnet/Winbox clients, authenticates them against the user file and
//! runs a login shell on a PTY. Also answers MAC-Ping and announces itself via MNDP.

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use md5::{Digest, Md5};
use nix::unistd::User;

use mitik_mndp as mndp;
use mitik_net::MacAddr;
use mitik_net::iface;
use mitik_net::raw::{self, RawSocket, UdpEndpoint};

use crate::ec_srp::{self, Curve, PrivateKey};
use crate::protocol::{
    self, Control, ControlType, Direction, MACTELNET_PORT, PING_HEADER_LEN, Packet, PacketType,
    RETRANSMIT_INTERVALS,
};
use crate::users::{self, Secret, UserList};
use crate::util;

/// The client sends a keepalive every 10 s; give up after 15.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const MNDP_INTERVAL: Duration = Duration::from_secs(60);
/// At most ~5 pings per second, counted per MNDP interval.
const MAX_PINGS: u32 = 60 * 5;
const PTY_READ: usize = 1024;
const SOFTID: &str = "MAC-Telnet";

const PLATFORM: &str = if cfg!(target_os = "macos") {
    "Mac OS X"
} else if cfg!(target_os = "linux") {
    "Linux"
} else if cfg!(target_os = "freebsd") {
    "FreeBSD"
} else if cfg!(target_os = "netbsd") {
    "NetBSD"
} else if cfg!(target_os = "openbsd") {
    "OpenBSD"
} else {
    "Unknown"
};

pub struct Options {
    /// Send raw Ethernet frames instead of UDP broadcast (`-n`).
    pub raw: bool,
    /// Legacy MD5 authentication instead of EC-SRP (`-o`).
    pub md5: bool,
    pub foreground: bool,
    pub users_path: PathBuf,
}

/// Why the server could not start or had to stop.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The user file is missing, unreadable or has unsafe permissions.
    Users(users::Error),
    /// A system call failed; `context` says which step.
    Io { context: String, source: io::Error },
    /// No network interface with a MAC address was found.
    NoInterfaces,
    /// Another server holds the lock file at this path.
    AlreadyRunning(PathBuf),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Users(e) => write!(f, "{e}; the user file is invalid, aborting"),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::NoInterfaces => f.write_str("Unable to find any valid network interfaces"),
            Error::AlreadyRunning(path) => write!(
                f,
                "Another MAC-Telnet server is already running (it holds {})",
                path.display()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Users(e) => Some(e),
            Error::Io { source, .. } => Some(source),
            Error::NoInterfaces | Error::AlreadyRunning(_) => None,
        }
    }
}

fn io_context(context: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
    let context = context.into();
    move |source| Error::Io { context, source }
}

// ------------------------------------------------------------------ logging

struct Log {
    stderr: bool,
}

impl Log {
    fn open(stderr: bool) -> Self {
        unsafe { libc::openlog(c"mactelnetd".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
        Log { stderr }
    }

    fn msg(&self, prio: libc::c_int, text: &str) {
        if let Ok(c) = CString::new(text.replace('\0', "")) {
            unsafe { libc::syslog(prio, c"%s".as_ptr(), c.as_ptr()) };
        }
        if self.stderr {
            eprintln!("{text}");
        }
    }
}

// ------------------------------------------------------------------ network

struct Iface {
    name: String,
    mac: MacAddr,
    ipv4: Option<Ipv4Addr>,
    /// UDP socket bound to ipv4:20561 (non-raw mode only).
    sock: Option<UdpSocket>,
}

/// Where a session's packets go.
#[derive(Clone)]
struct Peer {
    iface: String,
    our_mac: MacAddr,
    client_mac: MacAddr,
    client_port: u16,
}

struct Net {
    raw: Option<RawSocket>,
    ifaces: Vec<Iface>,
    ip_id: u16,
}

impl Net {
    fn load_ifaces(raw: bool, log: &Log) -> io::Result<Vec<Iface>> {
        let mut out = Vec::new();
        for i in iface::with_mac()? {
            let sock = match (raw, i.ipv4) {
                (false, Some(ip)) => {
                    // SO_REUSEPORT, see the receiving socket in `run()`.
                    match mitik_net::udp_socket(SocketAddrV4::new(ip, MACTELNET_PORT), true) {
                        Ok(s) => {
                            log.msg(
                                libc::LOG_NOTICE,
                                &format!("Using {} to transmit packets from {}", i.name, i.mac),
                            );
                            Some(s)
                        }
                        Err(e) => {
                            log.msg(
                                libc::LOG_NOTICE,
                                &format!(
                                    "Error binding to {ip}:{MACTELNET_PORT} on {}: {e}",
                                    i.name
                                ),
                            );
                            None
                        }
                    }
                }
                _ => None,
            };
            out.push(Iface {
                name: i.name,
                mac: i.mac,
                ipv4: i.ipv4,
                sock,
            });
        }
        Ok(out)
    }

    fn raw_send(
        &mut self,
        ifname: &str,
        src: UdpEndpoint,
        dst: UdpEndpoint,
        data: &[u8],
    ) -> io::Result<()> {
        self.ip_id = self.ip_id.wrapping_add(1);
        let frame = raw::build_frame(&src, &dst, data, self.ip_id)?;
        self.raw
            .as_mut()
            .expect("raw mode")
            .send(ifname, &frame)
            .map(|_| ())
    }

    /// `send_udp()`: to one client.
    fn send(&mut self, peer: &Peer, data: &[u8]) {
        let _ = if self.raw.is_some() {
            let src = UdpEndpoint {
                mac: peer.our_mac,
                ip: Ipv4Addr::UNSPECIFIED,
                port: MACTELNET_PORT,
            };
            let dst = UdpEndpoint {
                mac: peer.client_mac,
                ip: Ipv4Addr::BROADCAST,
                port: peer.client_port,
            };
            self.raw_send(&peer.iface, src, dst, data)
        } else {
            match self
                .ifaces
                .iter()
                .find(|i| i.name == peer.iface)
                .and_then(|i| i.sock.as_ref())
            {
                Some(s) => s
                    .send_to(
                        data,
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, peer.client_port),
                    )
                    .map(|_| ()),
                None => Ok(()),
            }
        };
    }

    /// `send_special_udp()`: broadcast from an interface (PONG, MNDP).
    fn broadcast(&mut self, idx: usize, port: u16, data: &[u8]) -> bool {
        if self.raw.is_some() {
            let i = &self.ifaces[idx];
            let src = UdpEndpoint {
                mac: i.mac,
                ip: i.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                port,
            };
            let dst = UdpEndpoint {
                mac: MacAddr::BROADCAST,
                ip: Ipv4Addr::BROADCAST,
                port,
            };
            let name = i.name.clone();
            self.raw_send(&name, src, dst, data).is_ok()
        } else {
            match &self.ifaces[idx].sock {
                Some(s) => s
                    .send_to(data, SocketAddrV4::new(Ipv4Addr::BROADCAST, port))
                    .is_ok(),
                None => false,
            }
        }
    }
}

// ------------------------------------------------------------------ sessions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Auth,
    Active,
    Closed,
}

struct InFlight {
    data: Vec<u8>,
    expected_ack: u32,
    attempt: usize,
    deadline: Instant,
}

struct Shell {
    master: OwnedFd,
    child: Child,
    tty: Option<String>,
}

struct Conn {
    session: u16,
    peer: Peer,
    state: State,
    in_counter: Option<u32>,
    out_counter: u32,
    queue: VecDeque<(Vec<u8>, u32)>,
    in_flight: Option<InFlight>,
    /// Send END once everything queued has been acknowledged.
    end_after_flush: bool,
    last_data: Instant,

    username: String,
    try_password: Option<Vec<u8>>,
    invalid_login: bool,
    /// MD5: 16-byte salt. EC-SRP: server public key (33) + salt (16).
    pass_salt: Vec<u8>,
    private_key: Option<PrivateKey>,
    client_key: Option<[u8; ec_srp::PUBKEY_LEN]>,

    term_width: u16,
    term_height: u16,
    term_type: String,
    shell: Option<Shell>,
}

impl Conn {
    fn new(session: u16, peer: Peer) -> Self {
        Conn {
            session,
            peer,
            state: State::Auth,
            in_counter: None,
            out_counter: 0,
            queue: VecDeque::new(),
            in_flight: None,
            end_after_flush: false,
            last_data: Instant::now(),
            username: String::new(),
            try_password: None,
            invalid_login: false,
            pass_salt: Vec::new(),
            private_key: None,
            client_key: None,
            term_width: 0,
            term_height: 0,
            term_type: "vt102".into(),
            shell: None,
        }
    }

    fn packet(&self, ptype: PacketType, counter: u32) -> Packet {
        Packet::new(
            ptype,
            &self.peer.our_mac,
            &self.peer.client_mac,
            self.session,
            counter,
            Direction::FromServer,
        )
    }

    /// Queue a DATA packet built by `fill`; delivered reliably, in order.
    fn send_data(&mut self, net: &mut Net, fill: impl FnOnce(&mut Packet) -> usize) {
        let mut p = self.packet(PacketType::Data, self.out_counter);
        let n = fill(&mut p);
        self.out_counter = self.out_counter.wrapping_add(n as u32);
        self.queue.push_back((p.data, self.out_counter));
        self.pump(net);
    }

    fn send_plain(&mut self, net: &mut Net, text: &[u8]) {
        self.send_data(net, |p| p.add_plain(text));
    }

    fn send_end(&mut self, net: &mut Net) {
        let p = self.packet(PacketType::End, self.out_counter);
        net.send(&self.peer, &p.data);
    }

    fn pump(&mut self, net: &mut Net) {
        if self.in_flight.is_some() {
            return;
        }
        match self.queue.pop_front() {
            Some((data, expected_ack)) => {
                net.send(&self.peer, &data);
                self.in_flight = Some(InFlight {
                    data,
                    expected_ack,
                    attempt: 0,
                    deadline: Instant::now() + Duration::from_millis(RETRANSMIT_INTERVALS[0]),
                });
            }
            None if self.end_after_flush => {
                self.end_after_flush = false;
                self.send_end(net);
            }
            None => {}
        }
    }

    fn retransmit(&mut self, net: &mut Net, now: Instant) {
        let Some(f) = &mut self.in_flight else { return };
        if now < f.deadline {
            return;
        }
        // Back off like the client, then keep trying once a second; the
        // session timeout ends hopeless cases.
        f.attempt += 1;
        let ms = RETRANSMIT_INTERVALS.get(f.attempt).copied().unwrap_or(1000);
        f.deadline = now + Duration::from_millis(ms);
        net.send(&self.peer, &f.data);
    }

    /// `abort_connection()`: show a message, then END.
    fn abort(&mut self, net: &mut Net, message: &str) {
        self.send_plain(net, message.as_bytes());
        self.state = State::Closed;
        self.end_after_flush = true;
        self.pump(net);
    }

    fn wants_pty_read(&self) -> bool {
        self.state == State::Active
            && self.shell.is_some()
            && self.in_flight.is_none()
            && self.queue.is_empty()
    }
}

// ------------------------------------------------------------------ OS helpers

fn read_fd(fd: RawFd, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n <= 0 {
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        data = &data[n as usize..];
    }
}

fn set_winsize(fd: RawFd, width: u16, height: u16) {
    if width == 0 && height == 0 {
        return;
    }
    let ws = libc::winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

fn set_cloexec(fd: RawFd) {
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
}

fn open_pty(width: u16, height: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (-1, -1);
    let ws = libc::winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let r = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const _ as *mut _,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    set_cloexec(master);
    set_cloexec(slave);
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

fn tty_name(fd: RawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 128];
    if unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Some(s.to_string_lossy().into_owned())
}

/// Text file contents for the terminal (bare LF -> CRLF).
fn terminal_text(path: &str) -> Option<Vec<u8>> {
    let t = std::fs::read(path).ok()?;
    let mut out = Vec::with_capacity(t.len() + 16);
    for (i, &b) in t.iter().enumerate() {
        if b == b'\n' && (i == 0 || t[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    Some(out)
}

fn uptime_secs() -> u32 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split('.').next()?.parse().ok())
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::timeval>();
        let r = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                (&mut tv as *mut libc::timeval).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return 0;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        now.as_secs().saturating_sub(tv.tv_sec as u64) as u32
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

struct Uname {
    nodename: String,
    release: String,
    machine: String,
}

fn uname() -> Uname {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    let s = |f: &[libc::c_char]| {
        unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    Uname {
        nodename: s(&u.nodename),
        release: s(&u.release),
        machine: s(&u.machine),
    }
}

/// utmp/wtmp records so that `who`/`last` show MAC-Telnet sessions.
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
mod utmp {
    fn fill(dst: &mut [libc::c_char], src: &str) {
        for (d, s) in dst.iter_mut().zip(src.bytes()) {
            *d = s as libc::c_char;
        }
    }

    fn now() -> (i64, i64) {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (d.as_secs() as i64, d.subsec_micros() as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn updwtmpx(file: *const libc::c_char, ut: *const libc::utmpx);
    }

    fn write(ut: &libc::utmpx) {
        unsafe {
            libc::setutxent();
            libc::pututxline(ut);
            libc::endutxent();
            #[cfg(target_os = "linux")]
            updwtmpx(c"/var/log/wtmp".as_ptr(), ut);
        }
    }

    pub fn login(user: &str, tty: &str, pid: i32, host: &str) {
        let line = tty.strip_prefix("/dev/").unwrap_or(tty);
        let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
        ut.ut_type = libc::USER_PROCESS;
        ut.ut_pid = pid;
        fill(&mut ut.ut_user, user);
        fill(&mut ut.ut_line, line);
        fill(&mut ut.ut_id, line.get(3..).unwrap_or(line));
        fill(&mut ut.ut_host, host);
        let (s, us) = now();
        ut.ut_tv.tv_sec = s as _;
        ut.ut_tv.tv_usec = us as _;
        write(&ut);
    }

    pub fn logout(tty: &str, pid: i32) {
        let line = tty.strip_prefix("/dev/").unwrap_or(tty);
        let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
        ut.ut_type = libc::DEAD_PROCESS;
        ut.ut_pid = pid;
        fill(&mut ut.ut_line, line);
        fill(&mut ut.ut_id, line.get(3..).unwrap_or(line));
        let (s, _) = now();
        ut.ut_tv.tv_sec = s as _;
        write(&ut);
    }
}

#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
mod utmp {
    pub fn login(_: &str, _: &str, _: i32, _: &str) {}
    pub fn logout(_: &str, _: i32) {}
}

/// Spawn `user`'s login shell on the PTY slave, as that user.
fn spawn_shell(user: &User, term: &str, slave: &OwnedFd) -> io::Result<Child> {
    let shell = user.shell.to_string_lossy().into_owned();
    let shell = if shell.is_empty() {
        "/bin/sh".to_string()
    } else {
        shell
    };
    let base = Path::new(&shell)
        .file_name()
        .map(|b| b.to_string_lossy().into_owned())
        .unwrap_or_default();
    let home = if user.dir.is_dir() {
        user.dir.clone()
    } else {
        PathBuf::from("/")
    };

    let mut cmd = Command::new(&shell);
    cmd.arg0(format!("-{base}"))
        .env_clear()
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("HOME", &user.dir)
        .env("SHELL", &shell)
        .env("TERM", term)
        .env(
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
        )
        .current_dir(home)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));

    let name = CString::new(user.name.as_str()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());
    // SAFETY: only async-signal-safe syscalls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            libc::tcsetpgrp(0, libc::getpid());
            if libc::geteuid() == 0 && libc::initgroups(name.as_ptr(), gid as _) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    };
    cmd.spawn()
}

// ------------------------------------------------------------------ single instance

/// Where the server keeps its lock file: a system directory for root, a
/// per-user one otherwise (a non-root server serves only its own user).
fn lock_path() -> PathBuf {
    if mitik_net::is_root() {
        return PathBuf::from("/var/run/mitik-server.lock");
    }
    let uid = nix::unistd::Uid::current();
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if Path::new(&dir).is_dir() => Path::new(&dir).join("mitik-server.lock"),
        _ => std::env::temp_dir().join(format!("mitik-server-{uid}.lock")),
    }
}

/// Take the lock that keeps a second server from running on this host.
///
/// Every server socket sets SO_REUSEPORT (so that MAC-Ping can run next to the
/// server on macOS), which also lets a second server bind the same port: both
/// would then answer every client. The lock is released when the process exits,
/// and `daemon()` keeps it, since the child inherits the descriptor.
fn take_lock(path: &Path) -> Result<OwnedFd, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        // The per-user path may be in a shared /tmp: never follow a planted link.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_context(format!("opening {}", path.display())))?;
    let fd = OwnedFd::from(file);
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        return Err(if e.kind() == io::ErrorKind::WouldBlock {
            Error::AlreadyRunning(path.to_path_buf())
        } else {
            io_context(format!("locking {}", path.display()))(e)
        });
    }
    Ok(fd)
}

// ------------------------------------------------------------------ server

struct Server {
    opts: Options,
    log: Log,
    curve: Curve,
    users: UserList,
    net: Net,
    rx: UdpSocket,
    mndp: Option<UdpSocket>,
    conns: Vec<Conn>,
    zombies: Vec<Child>,
    pings: u32,
    last_mndp: Option<Instant>,
    /// Held for as long as the server runs.
    _lock: OwnedFd,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let log = Log::open(opts.foreground);
    if !mitik_net::is_root() {
        let me = User::from_uid(nix::unistd::Uid::current())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_default();
        log.msg(
            libc::LOG_WARNING,
            &format!(
                "Warning: not running as root, only local user '{me}' will be able to log in."
            ),
        );
    }

    let lock = take_lock(&lock_path())?;

    let users = users::load(&opts.users_path).map_err(Error::Users)?;
    for line in &users.invalid_lines {
        log.msg(libc::LOG_WARNING, &format!("Warning: {line}"));
    }

    let raw = if opts.raw {
        let names: Vec<String> = iface::with_mac()
            .map_err(io_context("listing network interfaces"))?
            .into_iter()
            .map(|i| i.name)
            .collect();
        Some(RawSocket::open(&names).map_err(io_context("opening the raw socket"))?)
    } else {
        None
    };

    // With SO_REUSEPORT: on macOS and the BSDs another program on this host (MAC-Ping,
    // for one) can bind UDP 20561 only if every socket on that port has the option set.
    // Linux lets them share the port with SO_REUSEADDR alone, which is all the C server sets.
    let rx = mitik_net::udp_socket(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MACTELNET_PORT),
        true,
    )
    .map_err(io_context(format!("binding to 0.0.0.0:{MACTELNET_PORT}")))?;
    let mndp =
        match mitik_net::udp_socket(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, mndp::PORT), true) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("MNDP: Error binding to 0.0.0.0:{}, {e}", mndp::PORT);
                None
            }
        };
    log.msg(
        libc::LOG_NOTICE,
        &format!("Bound to 0.0.0.0:{MACTELNET_PORT}"),
    );

    let ifaces =
        Net::load_ifaces(opts.raw, &log).map_err(io_context("listing network interfaces"))?;
    if ifaces.is_empty() {
        return Err(Error::NoInterfaces);
    }

    #[cfg(not(target_os = "macos"))]
    if !opts.foreground && unsafe { libc::daemon(0, 0) } != 0 {
        return Err(io_context("daemon")(io::Error::last_os_error()));
    }

    let mut server = Server {
        opts,
        log,
        curve: Curve::new(),
        users,
        net: Net {
            raw,
            ifaces,
            ip_id: 0,
        },
        rx,
        mndp,
        conns: Vec::new(),
        zombies: Vec::new(),
        pings: 0,
        last_mndp: None,
        _lock: lock,
    };
    server.event_loop().map_err(io_context("event loop"))
}

impl Server {
    fn event_loop(&mut self) -> io::Result<()> {
        let term = Arc::new(AtomicBool::new(false));
        let hup = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;
        signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&hup))?;

        let mut buf = [0u8; protocol::PACKET_LEN];
        loop {
            if term.load(Ordering::Relaxed) {
                self.shutdown();
                return Ok(());
            }
            if hup.swap(false, Ordering::Relaxed) {
                self.reload_interfaces();
            }

            let now = Instant::now();
            let timeout = self
                .conns
                .iter()
                .filter_map(|c| {
                    c.in_flight
                        .as_ref()
                        .map(|f| f.deadline.saturating_duration_since(now))
                })
                .min()
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));

            // fds: rx, [mndp], then PTYs of sessions ready for more output.
            let pty_conns: Vec<usize> = (0..self.conns.len())
                .filter(|&i| self.conns[i].wants_pty_read())
                .collect();
            let ready = {
                let mut fds: Vec<BorrowedFd<'_>> = vec![self.rx.as_fd()];
                if let Some(m) = &self.mndp {
                    fds.push(m.as_fd());
                }
                for &i in &pty_conns {
                    fds.push(self.conns[i].shell.as_ref().unwrap().master.as_fd());
                }
                util::poll_readable(&fds, timeout.as_millis() as i32)?
            };
            let mut it = ready.into_iter();

            if it.next() == Some(true)
                && let Ok((n, from)) = self.rx.recv_from(&mut buf)
            {
                let data = buf[..n].to_vec();
                self.handle_packet(&data, from);
            }
            if self.mndp.is_some() && it.next() == Some(true) {
                let r = self.mndp.as_ref().unwrap().recv_from(&mut buf);
                // A 4-byte packet is a discovery request; answer at most once a second.
                if let Ok((4, _)) = r
                    && self
                        .last_mndp
                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
                {
                    self.mndp_broadcast();
                }
            }
            let ready_ptys: Vec<usize> = pty_conns
                .into_iter()
                .zip(it)
                .filter(|(_, r)| *r)
                .map(|(i, _)| i)
                .collect();
            self.read_ptys(&ready_ptys);

            self.periodic();
        }
    }

    fn periodic(&mut self) {
        let now = Instant::now();
        if self.last_mndp.is_none_or(|t| now - t > MNDP_INTERVAL) {
            self.pings = 0;
            self.mndp_broadcast();
        }
        for c in &mut self.conns {
            c.retransmit(&mut self.net, now);
        }
        let mut i = 0;
        while i < self.conns.len() {
            if now - self.conns[i].last_data >= CONNECTION_TIMEOUT {
                self.log.msg(
                    libc::LOG_INFO,
                    &format!("({}) Session timed out", self.conns[i].session),
                );
                let c = &mut self.conns[i];
                let p = {
                    let mut p = c.packet(PacketType::Data, c.out_counter);
                    p.add_plain(b"Timeout\r\n");
                    p
                };
                self.net.send(&c.peer, &p.data);
                c.send_end(&mut self.net);
                self.remove(i);
            } else {
                i += 1;
            }
        }
        self.zombies
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }

    fn remove(&mut self, idx: usize) {
        let c = self.conns.swap_remove(idx);
        if let Some(sh) = c.shell {
            if let Some(tty) = &sh.tty {
                utmp::logout(tty, sh.child.id() as i32);
            }
            drop(sh.master); // the shell gets SIGHUP
            self.zombies.push(sh.child);
        }
    }

    fn find(&self, session: u16, mac: &MacAddr) -> Option<usize> {
        self.conns
            .iter()
            .position(|c| c.session == session && &c.peer.client_mac == mac)
    }

    fn handle_packet(&mut self, data: &[u8], from: SocketAddr) {
        if data.len() < PING_HEADER_LEN {
            return;
        }
        let ptype = data[1];
        let src: MacAddr = data[2..8].try_into().unwrap();
        let dst: MacAddr = data[8..14].try_into().unwrap();
        // Drop packets that are not addressed to one of our interfaces.
        let Some(iface_idx) = self.net.ifaces.iter().position(|i| i.mac == dst) else {
            return;
        };

        if ptype == PacketType::Ping as u8 {
            if self.pings < MAX_PINGS {
                self.pings += 1;
                let pong =
                    protocol::ping_packet(PacketType::Pong, &dst, &src, &data[PING_HEADER_LEN..]);
                self.net.broadcast(iface_idx, MACTELNET_PORT, &pong);
            }
            return;
        }

        let Some(hdr) = protocol::parse_packet(data, Direction::ToServer) else {
            return;
        };
        let idx = self.find(hdr.session, &src);
        match PacketType::from_u8(ptype) {
            Some(PacketType::SessionStart) => {
                if idx.is_some() {
                    return; // same client seen on another interface
                }
                self.log.msg(
                    libc::LOG_DEBUG,
                    &format!("({}) New connection from {}.", hdr.session, src),
                );
                let iface = &self.net.ifaces[iface_idx];
                let peer = Peer {
                    iface: iface.name.clone(),
                    our_mac: dst,
                    client_mac: src,
                    client_port: from.port(),
                };
                let c = Conn::new(hdr.session, peer);
                let ack = c.packet(PacketType::Ack, hdr.counter);
                self.net.send(&c.peer, &ack.data);
                self.conns.push(c);
            }
            Some(PacketType::End) => {
                let Some(i) = idx else { return };
                let c = &mut self.conns[i];
                if c.state != State::Closed {
                    let p = c.packet(PacketType::End, hdr.counter);
                    self.net.send(&c.peer, &p.data);
                }
                self.log.msg(
                    libc::LOG_DEBUG,
                    &format!("({}) Connection closed.", c.session),
                );
                self.remove(i);
            }
            Some(PacketType::Ack) => {
                let Some(i) = idx else { return };
                let c = &mut self.conns[i];
                if let Some(f) = &c.in_flight
                    && hdr.counter.wrapping_sub(f.expected_ack) < 0x8000_0000
                {
                    c.in_flight = None;
                    c.pump(&mut self.net);
                }
                // Answer the client's keepalive.
                if c.last_data.elapsed() > Duration::from_secs(9) {
                    let p = c.packet(PacketType::Ack, hdr.counter);
                    self.net.send(&c.peer, &p.data);
                }
                c.last_data = Instant::now();
            }
            Some(PacketType::Data) => {
                let Some(i) = idx else { return };
                let c = &mut self.conns[i];
                c.last_data = Instant::now();
                let ack = c.packet(
                    PacketType::Ack,
                    hdr.counter.wrapping_add(hdr.payload.len() as u32),
                );
                self.net.send(&c.peer, &ack.data);
                // Accept new packets (and counter wrap-around); drop retransmissions.
                let fresh = match c.in_counter {
                    None => true,
                    Some(prev) => hdr.counter > prev || prev - hdr.counter > 16_777_216,
                };
                if !fresh {
                    return;
                }
                c.in_counter = Some(hdr.counter);
                let payload = hdr.payload.to_vec();
                self.handle_data(i, &payload);
            }
            _ => {}
        }
    }

    fn handle_data(&mut self, i: usize, payload: &[u8]) {
        let md5 = self.opts.md5;
        let (mut got_user, mut got_pass, mut got_size) = (false, false, false);

        for ctl in protocol::controls(payload) {
            let c = &mut self.conns[i];
            match ctl {
                Control::Plain(data) => {
                    if c.state == State::Active
                        && let Some(sh) = &c.shell
                    {
                        write_all_fd(sh.master.as_raw_fd(), data);
                    }
                }
                Control::Control(t, d) if t == ControlType::TermWidth as u8 && d.len() >= 2 => {
                    c.term_width = u16::from_le_bytes([d[0], d[1]]);
                    got_size = true;
                }
                Control::Control(t, d) if t == ControlType::TermHeight as u8 && d.len() >= 2 => {
                    c.term_height = u16::from_le_bytes([d[0], d[1]]);
                    got_size = true;
                }
                Control::Control(t, d) if t == ControlType::TermType as u8 => {
                    c.term_type = String::from_utf8_lossy(&d[..d.len().min(29)]).into_owned();
                }
                Control::Control(t, d) if c.state == State::Auth => match t {
                    t if t == ControlType::BeginAuth as u8 => {
                        if md5 {
                            if c.pass_salt.is_empty() {
                                c.pass_salt =
                                    util::random_bytes::<16>().unwrap_or_default().to_vec();
                            }
                            let salt = c.pass_salt.clone();
                            c.send_data(&mut self.net, |p| {
                                p.add_control(ControlType::PassSalt, &salt)
                            });
                        }
                        // EC-SRP: the client's key follows in a PASSSALT control.
                    }
                    t if t == ControlType::PassSalt as u8
                        && !md5
                        && d.len() > ec_srp::PUBKEY_LEN + 1 =>
                    {
                        self.ec_srp_challenge(i, d);
                    }
                    t if t == ControlType::Username as u8 => {
                        c.username = String::from_utf8_lossy(&d[..d.len().min(127)]).into_owned();
                        got_user = true;
                    }
                    t if t == ControlType::Password as u8 && (d.len() == 17 || d.len() == 32) => {
                        c.try_password = Some(d.to_vec());
                        got_pass = true;
                    }
                    t if t == ControlType::Password as u8 && d.is_empty() => {
                        got_pass = true;
                        c.invalid_login = true;
                    }
                    _ => self.log.msg(
                        libc::LOG_WARNING,
                        &format!(
                            "({}) Unhandled control packet type: {t}, length: {}",
                            c.session,
                            d.len()
                        ),
                    ),
                },
                Control::Control(t, d) => self.log.msg(
                    libc::LOG_WARNING,
                    &format!(
                        "({}) Unhandled control packet type: {t}, in state: {:?}, length: {}",
                        c.session,
                        c.state,
                        d.len()
                    ),
                ),
            }
        }

        if got_user && got_pass {
            self.login(i);
        }
        let c = &self.conns[i];
        if c.state == State::Active
            && got_size
            && let Some(sh) = &c.shell
        {
            set_winsize(sh.master.as_raw_fd(), c.term_width, c.term_height);
        }
    }

    /// Client sent "username\0public key": answer with our key + salt.
    fn ec_srp_challenge(&mut self, i: usize, d: &[u8]) {
        let nul = d.iter().position(|&b| b == 0).unwrap_or(d.len());
        let username = String::from_utf8_lossy(&d[..nul]).into_owned();
        let c = &mut self.conns[i];
        c.username = username.clone();
        if d.len() != nul + 1 + ec_srp::PUBKEY_LEN {
            self.log.msg(
                libc::LOG_NOTICE,
                &format!("({}) Invalid EC-SRP key by {username}.", c.session),
            );
            c.state = State::Closed; // let it time out
            return;
        }
        c.client_key = Some(d[nul + 1..].try_into().unwrap());

        self.reload_users();
        let c = &mut self.conns[i];
        let (validator, salt) = match self.users.find(&username).map(|u| &u.secret) {
            Some(Secret::Hashed { validator, salt }) => (*validator, *salt),
            Some(Secret::Plain(pw)) => {
                let salt = util::random_bytes::<16>().unwrap_or_default();
                (ec_srp::validator(&username, pw, &salt), salt)
            }
            None => {
                // Carry on with a random validator so that an attacker can't tell
                // whether the user exists; login fails at the password step.
                c.invalid_login = true;
                (
                    util::random_bytes::<32>().unwrap_or_default(),
                    util::random_bytes::<16>().unwrap_or_default(),
                )
            }
        };
        let Ok((private_key, public_key)) = self.curve.keygen(Some(&validator)) else {
            c.state = State::Closed;
            return;
        };
        c.private_key = Some(private_key);
        c.pass_salt = [&public_key[..], &salt[..]].concat();
        let msg = c.pass_salt.clone();
        c.send_data(&mut self.net, |p| {
            p.add_control(ControlType::PassSalt, &msg)
        });
    }

    fn reload_users(&mut self) {
        match users::load(&self.opts.users_path) {
            Ok(u) => self.users = u,
            Err(e) => self.log.msg(
                libc::LOG_WARNING,
                &format!("{e}; falling back to known users."),
            ),
        }
    }

    fn expected_proof(&self, c: &Conn) -> Option<Vec<u8>> {
        if c.invalid_login {
            return None;
        }
        let user = self.users.find(&c.username)?;
        if self.opts.md5 {
            let Secret::Plain(pw) = &user.secret else {
                self.log.msg(
                    libc::LOG_NOTICE,
                    &format!(
                        "({}) User {} tried to login with md5 authentication, but user is not saved in plaintext",
                        c.session, c.username
                    ),
                );
                return None;
            };
            if c.pass_salt.len() != 16 {
                return None;
            }
            let pw = pw.as_bytes();
            let mut h = Md5::new();
            h.update([0u8]);
            h.update(&pw[..pw.len().min(82)]);
            h.update(&c.pass_salt);
            return Some([&[0u8][..], h.finalize().as_slice()].concat());
        }
        let (pubkey, salt) = c.pass_salt.split_at_checked(ec_srp::PUBKEY_LEN)?;
        let validator = match &user.secret {
            Secret::Hashed { validator, .. } => *validator,
            Secret::Plain(pw) => ec_srp::validator(&c.username, pw, salt),
        };
        let proof = self.curve.server_proof(
            c.private_key.as_ref()?,
            c.client_key.as_ref()?,
            pubkey,
            &validator,
        )?;
        Some(proof.to_vec())
    }

    /// `user_login()`
    fn login(&mut self, i: usize) {
        self.reload_users();
        let expected = self.expected_proof(&self.conns[i]);
        let c = &mut self.conns[i];
        c.send_data(&mut self.net, |p| p.add_control(ControlType::EndAuth, &[]));

        let ok = matches!((&expected, &c.try_password), (Some(e), Some(t)) if constant_eq(e, t));
        c.try_password = None;
        if !ok {
            self.log.msg(
                libc::LOG_NOTICE,
                &format!("({}) Invalid login by {}.", c.session, c.username),
            );
            c.abort(
                &mut self.net,
                "Login failed, incorrect username or password\r\n",
            );
            return;
        }

        c.state = State::Active;
        let user = match User::from_name(&c.username) {
            Ok(Some(u)) => u,
            _ => {
                self.log.msg(
                    libc::LOG_WARNING,
                    &format!(
                        "({}) Login ok, but local user not accessible ({}).",
                        c.session, c.username
                    ),
                );
                c.abort(&mut self.net, "Error: Local user not accessible\r\n");
                return;
            }
        };
        if let Err(e) = self.start_shell(i, &user) {
            let c = &mut self.conns[i];
            self.log.msg(
                libc::LOG_ERR,
                &format!("({}) Could not log in {}: {e}", c.session, c.username),
            );
            c.abort(&mut self.net, "Internal error\r\n");
        }
    }

    fn start_shell(&mut self, i: usize, user: &User) -> io::Result<()> {
        let c = &mut self.conns[i];
        if user.uid.as_raw() != 0
            && let Some(text) = terminal_text("/etc/nologin")
        {
            self.log.msg(
                libc::LOG_NOTICE,
                &format!(
                    "({}) User {} disconnected with /etc/nologin message.",
                    c.session, c.username
                ),
            );
            c.send_plain(&mut self.net, &text);
            c.state = State::Closed;
            c.end_after_flush = true;
            c.pump(&mut self.net);
            return Ok(());
        }

        let (master, slave) = open_pty(c.term_width, c.term_height)?;
        // Fails harmlessly when not root (the PTY already belongs to us).
        unsafe { libc::fchown(slave.as_raw_fd(), user.uid.as_raw(), user.gid.as_raw()) };
        if let Some(motd) = terminal_text("/etc/motd") {
            write_all_fd(slave.as_raw_fd(), &motd);
        }
        let tty = tty_name(slave.as_raw_fd());
        let child = spawn_shell(user, &c.term_type, &slave)?;
        drop(slave);
        if let Some(t) = &tty {
            utmp::login(
                &c.username,
                t,
                child.id() as i32,
                &c.peer.client_mac.to_string(),
            );
        }
        self.log.msg(
            libc::LOG_INFO,
            &format!("({}) User {} logged in.", c.session, c.username),
        );
        c.shell = Some(Shell { master, child, tty });
        Ok(())
    }

    fn read_ptys(&mut self, ready: &[usize]) {
        let mut closed = Vec::new();
        for &i in ready {
            let c = &mut self.conns[i];
            let Some(sh) = &c.shell else { continue };
            let mut buf = [0u8; PTY_READ];
            let n = read_fd(sh.master.as_raw_fd(), &mut buf);
            if n > 0 {
                c.send_plain(&mut self.net, &buf[..n as usize]);
            } else if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            } else {
                // Shell exited (EOF/EIO on the master).
                c.send_end(&mut self.net);
                self.log.msg(
                    libc::LOG_INFO,
                    &format!("({}) Connection to user {} closed.", c.session, c.username),
                );
                closed.push(i);
            }
        }
        closed.sort_unstable_by(|a, b| b.cmp(a));
        for i in closed {
            self.remove(i);
        }
    }

    fn mndp_broadcast(&mut self) {
        self.last_mndp = Some(Instant::now());
        let u = uname();
        let uptime = uptime_secs();
        let (mut tried, mut sent) = (0, 0);
        for idx in 0..self.net.ifaces.len() {
            let i = &self.net.ifaces[idx];
            let pkt = mndp::Announcement {
                address: i.mac,
                identity: &u.nodename,
                version: &u.release,
                platform: PLATFORM,
                hardware: &u.machine,
                uptime,
                softid: SOFTID,
                ifname: &i.name,
            }
            .encode();
            tried += 1;
            if self.net.broadcast(idx, mndp::PORT, &pkt) {
                sent += 1;
            }
        }
        if tried > 0 && sent == 0 {
            self.log
                .msg(libc::LOG_WARNING, "Was not able to send any MNDP packets");
        }
    }

    /// SIGHUP: re-read interfaces and move sessions onto the new sockets.
    fn reload_interfaces(&mut self) {
        self.log
            .msg(libc::LOG_NOTICE, "SIGHUP: Reloading interfaces");
        let ifaces = match Net::load_ifaces(self.net.raw.is_some(), &self.log) {
            Ok(i) if !i.is_empty() => i,
            _ => {
                self.log.msg(
                    libc::LOG_ERR,
                    "No devices found! Keeping the old interface list.",
                );
                return;
            }
        };
        self.net.ifaces = ifaces;
        let mut i = 0;
        while i < self.conns.len() {
            if self
                .net
                .ifaces
                .iter()
                .any(|f| f.name == self.conns[i].peer.iface)
            {
                i += 1;
            } else {
                let c = &self.conns[i];
                self.log.msg(
                    libc::LOG_NOTICE,
                    &format!(
                        "({}) Connection closed because interface {} is gone.",
                        c.session, c.peer.iface
                    ),
                );
                self.remove(i);
            }
        }
    }

    fn shutdown(&mut self) {
        self.log.msg(libc::LOG_NOTICE, "Daemon shutting down");
        for c in &mut self.conns {
            if c.state == State::Active {
                let mut p = c.packet(PacketType::Data, c.out_counter);
                p.add_plain(b"\r\n\r\nDaemon shutting down.\r\n");
                self.net.send(&c.peer, &p.data);
                c.send_end(&mut self.net);
            }
        }
        while !self.conns.is_empty() {
            self.remove(0);
        }
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
