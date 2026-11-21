// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! MAC-Telnet client session (port of `mactelnet.c`): UDP broadcast, or raw
//! Ethernet frames addressed to the device's MAC with `-n`.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use md5::{Digest, Md5};

use mitik_net::MacAddr;
use mitik_net::iface::{self, Interface};
use mitik_net::raw::{self, RawSocket, UdpEndpoint};

use crate::ec_srp::{self, Curve, PrivateKey};
use crate::protocol::{
    self, Control, ControlType, Direction, MACTELNET_PORT, Packet, PacketType, RETRANSMIT_INTERVALS,
};
use crate::term::{self, RawTerminal};
use crate::util;

const KEEPALIVE: Duration = Duration::from_secs(10);

pub struct Options {
    pub dst: MacAddr,
    pub username: String,
    pub password: String,
    pub force_md5: bool,
    pub connect_timeout: Duration,
    pub quiet: bool,
    pub is_tty: bool,
    /// `-n`: send through this raw socket (opened before dropping privileges).
    pub raw: Option<RawSocket>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io(io::Error),
    ConnectionFailed,
    TimedOut,
    InvalidSalt(usize),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::ConnectionFailed => write!(f, "Connection failed."),
            Error::TimedOut => write!(f, "Connection timed out"),
            Error::InvalidSalt(n) => write!(
                f,
                "Invalid salt length: {n} (instead of 16 or 49) received from server"
            ),
        }
    }
}

struct InFlight {
    data: Vec<u8>,
    /// The ACK counter that confirms this packet.
    expected_ack: u32,
    attempt: usize,
    deadline: Instant,
}

struct Session {
    opts: Options,
    rx: UdpSocket,
    tx: Option<UdpSocket>,
    raw_sock: Option<RawSocket>,
    iface: Option<Interface>,
    source_port: u16,
    ip_id: u16,
    src: MacAddr,
    session_key: u16,
    out_counter: u32,
    in_counter: i64,
    in_flight: Option<InFlight>,
    queue: VecDeque<(Vec<u8>, u32)>,
    last_send: Instant,
    curve: Curve,
    private_key: PrivateKey,
    public_key: [u8; ec_srp::PUBKEY_LEN],
    terminal_mode: bool,
    raw: Option<RawTerminal>,
    running: bool,
}

pub fn run(mut opts: Options) -> Result<(), Error> {
    let [a, b] = util::random_bytes::<2>()?;
    let source_port = 1024 + (u16::from_be_bytes([a, b]) % 1024);
    let session_key = u16::from_be_bytes(util::random_bytes::<2>()?) % 65535;

    let curve = Curve::new();
    let (private_key, public_key) = curve.keygen(None)?;

    let rx = mitik_net::udp_socket(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, source_port), false)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Error binding to 0.0.0.0:{source_port}, {e}"),
            )
        })?;

    let raw_sock = opts.raw.take();
    let mut s = Session {
        opts,
        rx,
        tx: None,
        raw_sock,
        iface: None,
        source_port,
        ip_id: 0,
        src: MacAddr::ZERO,
        session_key,
        out_counter: 0,
        in_counter: -1,
        in_flight: None,
        queue: VecDeque::new(),
        last_send: Instant::now(),
        curve,
        private_key,
        public_key,
        terminal_mode: false,
        raw: None,
        running: true,
    };

    if !s.opts.quiet {
        print!("Connecting to {}...", s.opts.dst);
        io::stdout().flush()?;
    }
    s.find_interface(source_port)?;
    if !s.opts.quiet {
        println!("done");
    }

    s.begin_auth()?;
    let result = s.event_loop();
    s.raw = None; // restore terminal before printing anything else
    result
}

impl Session {
    fn packet(&self, ptype: PacketType, counter: u32) -> Packet {
        Packet::new(
            ptype,
            &self.src,
            &self.opts.dst,
            self.session_key,
            counter,
            Direction::ToServer,
        )
    }

    fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.last_send = Instant::now();
        if let (Some(raw), Some(ifc)) = (&mut self.raw_sock, &self.iface) {
            self.ip_id = self.ip_id.wrapping_add(1);
            let src = UdpEndpoint {
                mac: ifc.mac,
                ip: ifc.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                port: self.source_port,
            };
            let dst = UdpEndpoint {
                mac: self.opts.dst,
                ip: Ipv4Addr::BROADCAST,
                port: MACTELNET_PORT,
            };
            let frame = raw::build_frame(&src, &dst, data, self.ip_id)?;
            raw.send(&ifc.name, &frame)?;
        } else if let Some(tx) = &self.tx {
            tx.send_to(data, SocketAddrV4::new(Ipv4Addr::BROADCAST, MACTELNET_PORT))?;
        }
        Ok(())
    }

    /// Queue a packet that must be acknowledged; at most one is in flight.
    fn send_reliable(&mut self, data: Vec<u8>) -> io::Result<()> {
        // Callers have already advanced out_counter past this packet.
        self.queue.push_back((data, self.out_counter));
        self.pump()
    }

    fn pump(&mut self) -> io::Result<()> {
        if self.in_flight.is_none()
            && let Some((data, expected_ack)) = self.queue.pop_front()
        {
            self.send_raw(&data)?;
            self.in_flight = Some(InFlight {
                data,
                expected_ack,
                attempt: 0,
                deadline: Instant::now() + Duration::from_millis(RETRANSMIT_INTERVALS[0]),
            });
        }
        Ok(())
    }

    fn retransmit_if_due(&mut self) -> Result<(), Error> {
        let Some(f) = &mut self.in_flight else {
            return Ok(());
        };
        if Instant::now() < f.deadline {
            return Ok(());
        }
        f.attempt += 1;
        if f.attempt >= RETRANSMIT_INTERVALS.len() {
            return Err(Error::TimedOut);
        }
        f.deadline = Instant::now() + Duration::from_millis(RETRANSMIT_INTERVALS[f.attempt]);
        let data = f.data.clone();
        self.send_raw(&data)?;
        Ok(())
    }

    /// Try every interface: send SESSIONSTART and use the first one that gets an answer.
    fn find_interface(&mut self, port: u16) -> Result<(), Error> {
        let ifaces = if self.raw_sock.is_some() {
            // Raw frames don't need an IPv4 address on the interface. Interfaces
            // that have one are the likeliest to be attached to a network, though,
            // so they go first: every interface that stays silent costs a timeout.
            let mut all = iface::with_mac()?;
            all.sort_by_key(|i| i.ipv4.is_none());
            all
        } else {
            iface::list()?
        };
        if ifaces.is_empty() {
            eprintln!("Error: No suitable devices found");
            return Err(Error::ConnectionFailed);
        }
        let mut buf = [0u8; protocol::PACKET_LEN];
        let mut send_error = None;
        let mut sent = false;
        for ifc in ifaces {
            if self.raw_sock.is_none() {
                let Ok(tx) =
                    mitik_net::udp_socket(SocketAddrV4::new(ifc.ipv4.unwrap(), port), false)
                else {
                    continue;
                };
                self.tx = Some(tx);
            }
            self.src = ifc.mac;
            self.iface = Some(ifc);
            let start = self.packet(PacketType::SessionStart, 0);
            // An interface that cannot send (it may be down) only rules itself out.
            // The C client ignores the result of this send as well.
            if let Err(e) = self.send_raw(&start.data) {
                send_error = Some(e);
                continue;
            }
            sent = true;

            let ready = util::poll_readable(
                &[self.rx.as_fd()],
                self.opts.connect_timeout.as_millis() as i32,
            )?;
            if ready[0] {
                let n = self.rx.recv(&mut buf)?;
                if n == 0 {
                    break;
                }
                self.handle_packet(&buf[..n])?;
                return Ok(());
            }
        }
        self.tx = None;
        self.iface = None;
        match send_error {
            // Nothing could be sent on any interface: say why.
            Some(e) if !sent => Err(Error::Io(e)),
            _ => Err(Error::ConnectionFailed),
        }
    }

    fn begin_auth(&mut self) -> Result<(), Error> {
        let mut p = self.packet(PacketType::Data, 0);
        let mut n = p.add_control(ControlType::BeginAuth, &[]);
        if !self.opts.force_md5 {
            // username \0 client public key: tells the server we speak EC-SRP.
            let mut key = self.opts.username.as_bytes().to_vec();
            key.push(0);
            key.extend_from_slice(&self.public_key);
            n += p.add_control(ControlType::PassSalt, &key);
        }
        self.out_counter = self.out_counter.wrapping_add(n as u32);
        self.send_reliable(p.data)?;
        Ok(())
    }

    fn send_auth(&mut self, salt: &[u8], server_key: Option<&[u8]>) -> Result<(), Error> {
        let password = self.opts.password.as_bytes();
        let proof: Vec<u8> = match server_key {
            None => {
                let pw = &password[..password.len().min(82)];
                let mut h = Md5::new();
                h.update([0u8]);
                h.update(pw);
                h.update(salt);
                let mut out = vec![0u8];
                out.extend_from_slice(h.finalize().as_slice());
                out
            }
            Some(server_key) => {
                // Console parameters after '+' (e.g. "admin+ct") aren't part of the identity.
                let user = self.opts.username.split('+').next().unwrap_or("");
                let v = ec_srp::validator(user, &self.opts.password, salt);
                self.curve
                    .client_proof(&self.private_key, server_key, &self.public_key, &v)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid server public key")
                    })?
                    .to_vec()
            }
        };

        let term = std::env::var("TERM").unwrap_or_else(|_| "vt102".to_string());
        let (w, h) = if self.opts.is_tty {
            term::terminal_size().unwrap_or((0, 0))
        } else {
            (0, 0)
        };

        let mut p = self.packet(PacketType::Data, self.out_counter);
        let mut n = p.add_control(ControlType::Password, &proof);
        n += p.add_control(ControlType::Username, self.opts.username.as_bytes());
        n += p.add_control(ControlType::TermType, term.as_bytes());
        n += p.add_control(ControlType::TermWidth, &w.to_le_bytes());
        n += p.add_control(ControlType::TermHeight, &h.to_le_bytes());
        self.out_counter = self.out_counter.wrapping_add(n as u32);
        self.send_reliable(p.data)?;
        Ok(())
    }

    fn send_window_size(&mut self) -> io::Result<()> {
        if let Some((w, h)) = term::terminal_size() {
            let mut p = self.packet(PacketType::Data, self.out_counter);
            let mut n = p.add_control(ControlType::TermWidth, &w.to_le_bytes());
            n += p.add_control(ControlType::TermHeight, &h.to_le_bytes());
            self.out_counter = self.out_counter.wrapping_add(n as u32);
            self.send_reliable(p.data)?;
        }
        Ok(())
    }

    fn send_keys(&mut self, keys: &[u8]) -> io::Result<()> {
        let mut p = self.packet(PacketType::Data, self.out_counter);
        let n = p.add_plain(keys);
        self.out_counter = self.out_counter.wrapping_add(n as u32);
        self.send_reliable(p.data)
    }

    fn handle_packet(&mut self, buf: &[u8]) -> Result<(), Error> {
        let Some(hdr) = protocol::parse_packet(buf, Direction::FromServer) else {
            return Ok(());
        };
        if hdr.session != self.session_key {
            return Ok(());
        }
        match PacketType::from_u8(hdr.ptype) {
            Some(PacketType::Data) => {
                let ack_counter = hdr.counter.wrapping_add(hdr.payload.len() as u32);
                let ack = self.packet(PacketType::Ack, ack_counter);
                self.send_raw(&ack.data)?;

                // Accept new packets and counter wrap-around; drop duplicates.
                let c = hdr.counter as i64;
                if c > self.in_counter || self.in_counter - c > 65535 {
                    self.in_counter = c;
                } else {
                    return Ok(());
                }
                self.handle_controls(hdr.payload)?;
            }
            Some(PacketType::Ack) => {
                // Only an ACK covering our in-flight packet confirms it: the server
                // also answers keepalives with ACKs carrying older counters.
                if let Some(f) = &self.in_flight
                    && hdr.counter.wrapping_sub(f.expected_ack) < 0x8000_0000
                {
                    self.in_flight = None;
                }
                self.pump()?;
            }
            Some(PacketType::End) => {
                let end = self.packet(PacketType::End, 0);
                self.send_raw(&end.data)?;
                self.raw = None;
                if !self.opts.quiet {
                    eprintln!("Connection closed.");
                }
                self.running = false;
            }
            _ => eprintln!(
                "Unhandled packet type: {} received from server {}",
                hdr.ptype, self.opts.dst
            ),
        }
        Ok(())
    }

    fn handle_controls(&mut self, payload: &[u8]) -> Result<(), Error> {
        for c in protocol::controls(payload) {
            match c {
                Control::Control(t, data) if t == ControlType::PassSalt as u8 => match data.len() {
                    16 => self.send_auth(data, None)?,
                    49 => self.send_auth(
                        &data[ec_srp::PUBKEY_LEN..],
                        Some(&data[..ec_srp::PUBKEY_LEN]),
                    )?,
                    n => return Err(Error::InvalidSalt(n)),
                },
                Control::Control(t, _) if t == ControlType::EndAuth as u8 => {
                    self.terminal_mode = true;
                    if self.opts.is_tty && self.raw.is_none() {
                        self.raw = Some(RawTerminal::enable()?);
                    }
                }
                Control::Control(..) => {}
                Control::Plain(data) => {
                    let mut out = io::stdout().lock();
                    out.write_all(data)?;
                    out.flush()?;
                }
            }
        }
        Ok(())
    }

    fn event_loop(&mut self) -> Result<(), Error> {
        let winch = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGWINCH, Arc::clone(&winch))?;

        let mut stdin_gone = false;
        let mut buf = [0u8; protocol::PACKET_LEN];
        while self.running {
            if winch.swap(false, Ordering::Relaxed) && self.terminal_mode && self.opts.is_tty {
                self.send_window_size()?;
            }

            // Only read keys when nothing is waiting for an ACK, to keep ordering and bound memory.
            let want_stdin = self.terminal_mode
                && !stdin_gone
                && self.in_flight.is_none()
                && self.queue.is_empty();
            let timeout = match &self.in_flight {
                Some(f) => f
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as i32,
                None => 1000,
            };

            let ready = if want_stdin {
                util::poll_readable(&[self.rx.as_fd(), term::stdin_borrowed()], timeout)?
            } else {
                let mut r = util::poll_readable(&[self.rx.as_fd()], timeout)?;
                r.push(false);
                r
            };

            if ready[0] {
                match self.rx.recv(&mut buf) {
                    Ok(n) => self.handle_packet(&buf[..n])?,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if ready[1] {
                let mut keys = [0u8; 512];
                match term::read_stdin(&mut keys) {
                    Ok(0) => stdin_gone = true,
                    Ok(n) => self.send_keys(&keys[..n])?,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => stdin_gone = true,
                }
            }

            self.retransmit_if_due()?;

            if self.in_flight.is_none() && self.last_send.elapsed() >= KEEPALIVE {
                let ka = self.packet(PacketType::Ack, self.out_counter);
                self.send_raw(&ka.data)?;
            }
        }
        Ok(())
    }
}
