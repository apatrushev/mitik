// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! End-to-end tests of the real `mitik` binary:
//!
//! - `mitik telnet` talks over UDP broadcast to a minimal in-process MAC-Telnet
//!   server (EC-SRP and legacy MD5 auth);
//! - `mitik ping` against a mock PONG responder (UDP fallback, no root);
//! - `mitik telnet`, `ping` and `discover` against `mitik server`;
//! - the same binary invoked under the names of the C tools.
//!
//! The network tests need a non-loopback interface with IPv4 + MAC and free
//! UDP port 20561; they are skipped otherwise.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use md5::{Digest, Md5};
use mitik_mactelnet::ec_srp::{self, Curve};
use mitik_mactelnet::protocol::{
    self, Control, ControlType, Direction, Packet, PacketType, parse_packet,
};
use mitik_net::{MacAddr, iface, udp_socket};

const MITIK: &str = env!("CARGO_BIN_EXE_mitik");

const SERVER_MAC: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0x01]);
const USER: &str = "admin";
const PASS: &str = "s3cret";

/// Every network test binds UDP 20561; run them one at a time.
static PORT_LOCK: Mutex<()> = Mutex::new(());

/// How the binary is invoked: as `mitik <subcommand>`, or under the name of
/// the matching C tool (through a symlink).
#[derive(Clone, Copy)]
enum Style {
    Mitik,
    CTool,
}

/// A symlink to the mitik binary named like one of the C tools.
fn c_tool(name: &str) -> std::path::PathBuf {
    static CREATING: Mutex<()> = Mutex::new(());
    let _guard = CREATING.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("c-tool-names");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(name);
    // A link left by an earlier run may point to another build of the binary.
    if std::fs::read_link(&link).ok().as_deref() != Some(std::path::Path::new(MITIK)) {
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(MITIK, &link).unwrap();
    }
    link
}

fn telnet_command(style: Style) -> Command {
    match style {
        Style::Mitik => {
            let mut c = Command::new(MITIK);
            c.arg("telnet");
            c
        }
        Style::CTool => Command::new(c_tool("mactelnet")),
    }
}

fn ping_command(style: Style) -> Command {
    match style {
        Style::Mitik => {
            let mut c = Command::new(MITIK);
            c.arg("ping");
            c
        }
        Style::CTool => Command::new(c_tool("macping")),
    }
}

fn discover_command(style: Style) -> Command {
    match style {
        Style::Mitik => {
            let mut c = Command::new(MITIK);
            c.arg("discover");
            c
        }
        Style::CTool => {
            let mut c = Command::new(c_tool("mactelnet"));
            c.arg("-l");
            c
        }
    }
}

fn server_command(style: Style) -> Command {
    match style {
        Style::Mitik => {
            let mut c = Command::new(MITIK);
            c.arg("server");
            c
        }
        Style::CTool => Command::new(c_tool("mactelnetd")),
    }
}

fn have_interface() -> bool {
    let ok = iface::list().map(|l| !l.is_empty()).unwrap_or(false);
    if !ok {
        eprintln!("skipping: no usable network interface");
    }
    ok
}

struct Server {
    sock: UdpSocket,
    /// Bound to the interface IP: broadcasting from 0.0.0.0 may have no route.
    tx: UdpSocket,
    client_mac: MacAddr,
    client_port: u16,
    session: u16,
    in_counter: Option<u32>,
    out_counter: u32,
}

impl Server {
    fn send(&self, ptype: PacketType, counter: u32, build: impl FnOnce(&mut Packet)) {
        let mut p = Packet::new(
            ptype,
            &SERVER_MAC,
            &self.client_mac,
            self.session,
            counter,
            Direction::FromServer,
        );
        build(&mut p);
        self.tx
            .send_to(
                &p.data,
                SocketAddrV4::new(Ipv4Addr::BROADCAST, self.client_port),
            )
            .unwrap();
    }

    /// Send DATA and wait until the client ACKs it.
    fn send_data(&mut self, build: impl Fn(&mut Packet)) -> Vec<Vec<u8>> {
        let start = self.out_counter;
        let mut p = Packet::new(
            PacketType::Data,
            &SERVER_MAC,
            &self.client_mac,
            self.session,
            start,
            Direction::FromServer,
        );
        build(&mut p);
        self.out_counter += (p.data.len() - protocol::HEADER_LEN) as u32;
        let mut pending = Vec::new();
        for _ in 0..20 {
            self.tx
                .send_to(
                    &p.data,
                    SocketAddrV4::new(Ipv4Addr::BROADCAST, self.client_port),
                )
                .unwrap();
            let deadline = Instant::now() + Duration::from_millis(200);
            while let Some((ptype, counter, payload)) = self.recv(deadline) {
                if ptype == PacketType::Ack as u8 && counter == self.out_counter {
                    return pending;
                }
                if !payload.is_empty() {
                    pending.push(payload);
                }
            }
        }
        panic!("client never acknowledged server data");
    }

    /// Receive one packet from our session; DATA is ACKed and de-duplicated here.
    fn recv(&mut self, deadline: Instant) -> Option<(u8, u32, Vec<u8>)> {
        let mut buf = [0u8; 1500];
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            self.sock
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            let Ok((n, from)) = self.sock.recv_from(&mut buf) else {
                return None;
            };
            let h = parse_packet(&buf[..n], Direction::ToServer)?;
            if h.session != self.session || h.src != self.client_mac {
                continue;
            }
            self.client_port = from.port();
            if h.ptype == PacketType::Data as u8 {
                self.send(PacketType::Ack, h.counter + h.payload.len() as u32, |_| {});
                if self.in_counter.is_some_and(|c| h.counter < c) {
                    continue; // retransmission
                }
                self.in_counter = Some(h.counter + h.payload.len() as u32);
                return Some((h.ptype, h.counter, h.payload.to_vec()));
            }
            return Some((h.ptype, h.counter, Vec::new()));
        }
    }

    fn recv_data(&mut self) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (ptype, _, payload) = self
                .recv(deadline)
                .expect("timed out waiting for client data");
            if ptype == PacketType::Data as u8 {
                return payload;
            }
        }
    }
}

fn control(payload: &[u8], want: ControlType) -> Option<&[u8]> {
    protocol::controls(payload).find_map(|c| match c {
        Control::Control(t, d) if t == want as u8 => Some(d),
        _ => None,
    })
}

/// Runs one session. Returns Err(reason) if authentication was rejected.
fn serve(sock: UdpSocket, tx: UdpSocket, md5_only: bool) -> Result<(), String> {
    let mut buf = [0u8; 1500];
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (n, from) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("no SESSIONSTART: {e}"))?;
    let h = parse_packet(&buf[..n], Direction::ToServer).unwrap();
    assert_eq!(h.ptype, PacketType::SessionStart as u8);
    let mut s = Server {
        sock,
        tx,
        client_mac: h.src,
        client_port: from.port(),
        session: h.session,
        in_counter: None,
        out_counter: 0,
    };
    s.send(PacketType::Ack, 0, |_| {});

    let begin = s.recv_data();
    assert!(control(&begin, ControlType::BeginAuth).is_some());
    let salt = [0x5au8; 16];
    let curve = Curve::new();

    let expected: Vec<u8>;
    match control(&begin, ControlType::PassSalt) {
        Some(key) => {
            assert!(!md5_only, "client sent EC-SRP key despite -o");
            let nul = key.iter().position(|&b| b == 0).unwrap();
            assert_eq!(&key[..nul], USER.as_bytes());
            let client_pub = &key[nul + 1..];
            assert_eq!(client_pub.len(), ec_srp::PUBKEY_LEN);
            let v = ec_srp::validator(USER, PASS, &salt);
            let (spriv, spub) = curve.keygen(Some(&v)).unwrap();
            expected = curve
                .server_proof(&spriv, client_pub, &spub, &v)
                .unwrap()
                .to_vec();
            let mut msg = spub.to_vec();
            msg.extend_from_slice(&salt);
            s.send_data(|p| {
                p.add_control(ControlType::PassSalt, &msg);
            });
        }
        None => {
            assert!(md5_only, "client did not offer EC-SRP");
            let mut h = Md5::new();
            h.update([0u8]);
            h.update(PASS.as_bytes());
            h.update(salt);
            expected = [&[0u8][..], h.finalize().as_slice()].concat();
            s.send_data(|p| {
                p.add_control(ControlType::PassSalt, &salt);
            });
        }
    }

    let auth = s.recv_data();
    assert_eq!(control(&auth, ControlType::Username), Some(USER.as_bytes()));
    assert!(control(&auth, ControlType::TermType).is_some());
    assert_eq!(
        control(&auth, ControlType::TermWidth).map(|d| d.len()),
        Some(2)
    );
    if control(&auth, ControlType::Password) != Some(&expected[..]) {
        s.send(PacketType::End, 0, |_| {});
        return Err("wrong password proof".into());
    }

    s.send_data(|p| {
        p.add_control(ControlType::EndAuth, &[]);
        p.add_plain(b"Welcome to mock RouterOS\r\n");
    });

    // Echo terminal input until a line arrives.
    let mut line = Vec::new();
    while !line.ends_with(b"\n") {
        line.extend(s.recv_data());
    }
    let mut reply = b"echo:".to_vec();
    reply.extend_from_slice(&line);
    s.send_data(|p| {
        p.add_plain(&reply);
    });

    // Close the session; the client must answer with END.
    s.send(PacketType::End, 0, |_| {});
    let deadline = Instant::now() + Duration::from_secs(3);
    while let Some((ptype, ..)) = s.recv(deadline) {
        if ptype == PacketType::End as u8 {
            return Ok(());
        }
    }
    Err("client did not acknowledge END".into())
}

fn run_case(extra_args: &[&str], md5_only: bool) {
    let sock = udp_socket(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, protocol::MACTELNET_PORT),
        true,
    )
    .unwrap();
    let ip = iface::list().unwrap()[0].ipv4.unwrap();
    let out = udp_socket(SocketAddrV4::new(ip, 0), false).unwrap();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || tx.send(serve(sock, out, md5_only)).unwrap());

    let mut child = telnet_command(Style::Mitik)
        .args(["02:00:00:00:00:01", "-A", "-u", USER, "-p", PASS])
        .args(extra_args)
        .env("TERM", "xterm")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"/system identity print\n").unwrap();

    let result = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("server thread hung");
    server.join().unwrap();
    let status = child.wait().unwrap();
    drop(stdin);
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();

    result.unwrap_or_else(|e| panic!("{e}\nclient stdout: {out}\nclient stderr: {err}"));
    assert!(status.success(), "client exit {status}, stderr: {err}");
    assert!(out.contains("Welcome to mock RouterOS"), "stdout: {out}");
    assert!(
        out.contains("echo:/system identity print\n"),
        "stdout: {out}"
    );
}

#[test]
fn session_ec_srp_and_md5() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() {
        return;
    }
    run_case(&[], false);
    run_case(&["-o"], true);
}

/// Answers PINGs addressed to SERVER_MAC (until `stop`), like RouterOS/mactelnetd would.
fn pong_responder(answer: bool, stop: Arc<AtomicBool>) -> thread::JoinHandle<u32> {
    let sock = udp_socket(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, protocol::MACTELNET_PORT),
        true,
    )
    .unwrap();
    let ip = iface::list().unwrap()[0].ipv4.unwrap();
    let tx = udp_socket(SocketAddrV4::new(ip, 0), false).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    thread::spawn(move || {
        let mut pings = 0;
        let mut buf = [0u8; 1500];
        while !stop.load(Ordering::Relaxed) {
            let Ok(n) = sock.recv(&mut buf) else { continue };
            if n < protocol::PING_HEADER_LEN
                || buf[1] != PacketType::Ping as u8
                || buf[8..14] != SERVER_MAC.octets()
            {
                continue;
            }
            assert_eq!(
                &buf[14..18],
                &[0, 0, 0, 0],
                "ping header must have zeroed session bytes"
            );
            pings += 1;
            if answer {
                let src: MacAddr = buf[2..8].try_into().unwrap();
                let pong = protocol::ping_packet(
                    PacketType::Pong,
                    &SERVER_MAC,
                    &src,
                    &buf[protocol::PING_HEADER_LEN..n],
                );
                let to = SocketAddrV4::new(Ipv4Addr::BROADCAST, protocol::MACTELNET_PORT);
                tx.send_to(&pong, to).unwrap();
                // A duplicate must not be counted twice.
                tx.send_to(&pong, to).unwrap();
            }
        }
        pings
    })
}

fn run_ping(args: &[&str], answer: bool) -> (std::process::ExitStatus, String, u32) {
    let stop = Arc::new(AtomicBool::new(false));
    let responder = pong_responder(answer, Arc::clone(&stop));
    let out = ping_command(Style::Mitik)
        .arg("02:00:00:00:00:01")
        .args(args)
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    let pings = responder.join().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status, text, pings)
}

#[test]
fn ping_replies_and_timeouts() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() {
        return;
    }
    if mitik_net::is_root() {
        eprintln!("skipping: as root pings go out as raw frames the mock cannot answer");
        return;
    }

    let (status, out, pings) = run_ping(&["-f", "-c", "3", "-s", "100"], true);
    assert!(status.success(), "{out}");
    assert_eq!(pings, 3, "{out}");
    assert_eq!(
        out.matches("02:00:00:00:00:01 100 byte, ping time").count(),
        3,
        "{out}"
    );
    assert!(
        out.contains("3 packets transmitted, 3 packets received, 0% packet loss"),
        "{out}"
    );

    let (status, out, _) = run_ping(&["-c", "1"], false);
    assert_eq!(status.code(), Some(1), "{out}");
    assert!(out.contains("02:00:00:00:00:01 ping timeout"), "{out}");
    assert!(
        out.contains("1 packets transmitted, 0 packets received, 100% packet loss"),
        "{out}"
    );
}

// ------------------------------------------------------------ our client <-> our server

struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) };
        let _ = self.0.wait();
    }
}

fn current_user() -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .unwrap()
        .unwrap()
        .name
}

fn users_file(tag: &str, content: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("mtd-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mactelnetd.users");
    std::fs::write(&path, content).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn start_server(style: Style, users: &std::path::Path, extra: &[&str]) -> Daemon {
    let child = server_command(style)
        .args(["-f", "--users-file"])
        .arg(users)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Wait until it answers MAC-Ping... simpler: give it a moment to bind.
    thread::sleep(Duration::from_millis(300));
    Daemon(child)
}

/// Connect with the real client, type `input`, return (exit status, stdout).
fn client_session(
    style: Style,
    user: &str,
    pass: &str,
    extra: &[&str],
    input: &str,
) -> (std::process::ExitStatus, String) {
    let mac = iface::list().unwrap()[0].mac.to_string();
    let mut child = telnet_command(style)
        .args([mac.as_str(), "-A", "-u", user, "-p", pass])
        .args(extra)
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "client did not finish");
        thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status, text)
}

#[test]
fn client_against_our_server() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() {
        return;
    }
    let me = current_user();
    let script = "echo MARK_$((40+2))\nexit\n";

    // EC-SRP with a plain-text password in the user file.
    let path = users_file("plain", &format!("# test\n{me}:plainpw\n"));
    {
        let _d = start_server(Style::Mitik, &path, &[]);
        let (st, out) = client_session(Style::Mitik, &me, "plainpw", &[], script);
        assert!(st.success(), "{out}");
        assert!(out.contains("MARK_42"), "{out}");

        let (_, out) = client_session(Style::Mitik, &me, "wrong", &[], script);
        assert!(
            out.contains("Login failed, incorrect username or password"),
            "{out}"
        );
        assert!(!out.contains("MARK_42"), "{out}");

        let (_, out) = client_session(Style::Mitik, "nosuchuser", "x", &[], script);
        assert!(out.contains("Login failed"), "{out}");
    }

    // EC-SRP with a hashed entry created by `mitik server -a`.
    let path = users_file("hashed", "");
    let out = server_command(Style::Mitik)
        .arg("--users-file")
        .arg(&path)
        .args(["-a", "-u", &me, "-p", "hashedpw"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!std::fs::read_to_string(&path).unwrap().contains("hashedpw"));
    {
        let _d = start_server(Style::Mitik, &path, &[]);
        let (st, out) = client_session(Style::Mitik, &me, "hashedpw", &[], script);
        assert!(st.success(), "{out}");
        assert!(out.contains("MARK_42"), "{out}");
    }

    // Legacy MD5 on both sides (needs the plain-text entry), with both programs
    // invoked under the names of the C tools: mactelnetd and mactelnet.
    let path = users_file("md5", &format!("{me}:md5pw\n"));
    {
        let _d = start_server(Style::CTool, &path, &["-o"]);
        let (st, out) = client_session(Style::CTool, &me, "md5pw", &["-o"], script);
        assert!(st.success(), "{out}");
        assert!(out.contains("MARK_42"), "{out}");
    }
}

#[test]
fn ping_our_server() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() || mitik_net::is_root() {
        return;
    }
    let me = current_user();
    let path = users_file("ping", &format!("{me}:x\n"));
    let _d = start_server(Style::Mitik, &path, &[]);
    let mac = iface::list().unwrap()[0].mac.to_string();
    for style in [Style::Mitik, Style::CTool] {
        let out = ping_command(style)
            .args([&mac, "-f", "-c", "3"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{text}");
        assert!(
            text.contains("3 packets transmitted, 3 packets received, 0% packet loss"),
            "{text}"
        );
    }
}

#[test]
fn server_announces_itself_via_mndp() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() {
        return;
    }
    let me = current_user();
    let path = users_file("mndp", &format!("{me}:x\n"));
    let _d = start_server(Style::Mitik, &path, &[]);
    let mac = iface::list().unwrap()[0].mac.to_string();
    for style in [Style::Mitik, Style::CTool] {
        let out = discover_command(style)
            .args(["-B", "-t", "2"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.lines()
                .any(|l| l.starts_with(&format!("'{mac}'")) && l.contains("'MAC-Telnet'")),
            "stdout: {text}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn second_server_refuses_to_start() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !have_interface() {
        return;
    }
    let me = current_user();
    let path = users_file("second", &format!("{me}:x\n"));
    let _first = start_server(Style::Mitik, &path, &[]);

    let mut second = server_command(Style::Mitik)
        .args(["-f", "--users-file"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = second.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = second.kill();
            let _ = second.wait();
            panic!("the second server kept running");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    second
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(!status.success(), "{err}");
    assert!(err.contains("already running"), "{err}");
}

/// No network needed: argument handling under each name.
#[test]
fn names_of_the_c_tools() {
    let text = |out: &std::process::Output| {
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };

    // mactelnetd: user management works on the given user file.
    let path = users_file("names", "alice:plainpw\n");
    let out = Command::new(c_tool("mactelnetd"))
        .arg("--users-file")
        .arg(&path)
        .arg("-l")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Users:"), "{}", text(&out));
    assert!(text(&out).contains("alice"), "{}", text(&out));

    // Each name reports itself, and knows only its own options.
    for (name, option) in [
        ("mactelnet", "-l"),
        ("macping", "-c <count>"),
        ("mactelnetd", "-d <user>"),
    ] {
        let out = Command::new(c_tool(name)).arg("-v").output().unwrap();
        assert!(
            text(&out).starts_with(&format!("{name} ")),
            "{}",
            text(&out)
        );
        let out = Command::new(c_tool(name)).arg("-h").output().unwrap();
        assert!(text(&out).contains(option), "{name} -h: {}", text(&out));
        assert!(
            !text(&out).contains("discover"),
            "{name} -h: {}",
            text(&out)
        );
    }
    let out = Command::new(c_tool("macping")).arg("-l").output().unwrap();
    assert!(!out.status.success(), "{}", text(&out));

    // mactelnet without a target is an error; mitik without arguments shows its commands.
    let out = Command::new(c_tool("mactelnet")).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("missing <MAC|identity>"),
        "{}",
        text(&out)
    );
    let out = Command::new(MITIK).output().unwrap();
    for command in ["telnet", "ping", "discover", "server"] {
        assert!(text(&out).contains(command), "{}", text(&out));
    }
}
