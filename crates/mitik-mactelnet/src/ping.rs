// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! MAC-Ping (port of `macping.c`): PING/PONG packets on UDP port 20561.
//!
//! RouterOS only answers pings whose Ethernet frame is addressed to its own MAC,
//! so as root we send hand-built frames through a raw socket (like the C tool).
//! Without root we fall back to UDP broadcast, which mactelnetd-like servers may
//! answer but RouterOS usually ignores.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mitik_net::MacAddr;
use mitik_net::iface::{self, Interface};
use mitik_net::raw::{self, RawSocket, UdpEndpoint};

use crate::protocol::{self, MACTELNET_PORT, PING_HEADER_LEN, PacketType};

/// Default total packet size (`-s`), header included; same as macping.
pub const DEFAULT_SIZE: usize = PING_HEADER_LEN + 38;
pub const MAX_SIZE: usize = raw::MAX_PAYLOAD;
const TIMESTAMP_LEN: usize = 16;
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

pub struct Options {
    pub dst: MacAddr,
    /// 0 = until interrupted.
    pub count: u32,
    /// Total packet size including the 18-byte header.
    pub size: usize,
    pub fast: bool,
}

/// Ping options that cannot work.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OptionsError {
    /// Fast mode needs a count from 1 to 100.
    FastCount,
    /// The size is outside `PING_HEADER_LEN..=MAX_SIZE`.
    Size,
}

impl std::fmt::Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsError::FastCount => f.write_str(
                "Number of packets to send must be more than 0 and up to 100 in fast mode.",
            ),
            OptionsError::Size => write!(
                f,
                "Packet size must be between {PING_HEADER_LEN} and {MAX_SIZE}"
            ),
        }
    }
}

impl std::error::Error for OptionsError {}

pub fn validate(count: u32, size: usize, fast: bool) -> Result<(), OptionsError> {
    if fast && !(1..=100).contains(&count) {
        return Err(OptionsError::FastCount);
    }
    if !(PING_HEADER_LEN..=MAX_SIZE).contains(&size) {
        return Err(OptionsError::Size);
    }
    Ok(())
}

enum Transport {
    Raw(RawSocket, Vec<Interface>),
    Udp(Vec<(Interface, UdpSocket)>),
}

impl Transport {
    fn open() -> io::Result<Self> {
        if mitik_net::is_root() {
            let ifaces = iface::with_mac()?;
            let names: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
            return Ok(Transport::Raw(RawSocket::open(&names)?, ifaces));
        }
        eprintln!(
            "Warning: not running as root, sending pings as UDP broadcast. \
             RouterOS only answers pings addressed to its MAC; run as root for that."
        );
        let socks = iface::list()?
            .into_iter()
            .filter_map(|i| {
                let s =
                    mitik_net::udp_socket(SocketAddrV4::new(i.ipv4?, MACTELNET_PORT), true).ok()?;
                Some((i, s))
            })
            .collect();
        Ok(Transport::Udp(socks))
    }

    /// Send the ping from every interface; returns how many sends succeeded.
    fn send(&mut self, dst: &MacAddr, payload: &[u8], ip_id: u16) -> usize {
        let mut sent = 0;
        match self {
            Transport::Raw(sock, ifaces) => {
                for ifc in ifaces.iter() {
                    let pkt = protocol::ping_packet(PacketType::Ping, &ifc.mac, dst, payload);
                    let src = UdpEndpoint {
                        mac: ifc.mac,
                        ip: Ipv4Addr::UNSPECIFIED,
                        port: MACTELNET_PORT,
                    };
                    let to = UdpEndpoint {
                        mac: *dst,
                        ip: Ipv4Addr::BROADCAST,
                        port: MACTELNET_PORT,
                    };
                    if let Ok(frame) = raw::build_frame(&src, &to, &pkt, ip_id)
                        && sock.send(&ifc.name, &frame).is_ok()
                    {
                        sent += 1;
                    }
                }
            }
            Transport::Udp(socks) => {
                for (ifc, s) in socks.iter() {
                    let pkt = protocol::ping_packet(PacketType::Ping, &ifc.mac, dst, payload);
                    if s.send_to(&pkt, SocketAddrV4::new(Ipv4Addr::BROADCAST, MACTELNET_PORT))
                        .is_ok()
                    {
                        sent += 1;
                    }
                }
            }
        }
        sent
    }
}

#[derive(Default)]
struct Stats {
    sent: u32,
    received: u32,
    min: f64,
    max: f64,
    total: f64,
}

impl Stats {
    fn record(&mut self, ms: f64) {
        if self.received == 0 || ms < self.min {
            self.min = ms;
        }
        self.max = self.max.max(ms);
        self.total += ms;
        self.received += 1;
    }

    fn print(&self) {
        let loss = (self.received * 100)
            .checked_div(self.sent)
            .map_or(0, |pct| 100 - pct.min(100));
        let avg = if self.received == 0 {
            0.0
        } else {
            self.total / self.received as f64
        };
        println!();
        println!(
            "{} packets transmitted, {} packets received, {loss}% packet loss",
            self.sent, self.received
        );
        println!(
            "round-trip min/avg/max = {:.2}/{avg:.2}/{:.2} ms",
            self.min, self.max
        );
    }
}

fn make_payload(data_len: usize) -> io::Result<Vec<u8>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut p = Vec::with_capacity(data_len);
    p.extend_from_slice(&now.as_secs().to_le_bytes());
    p.extend_from_slice(&(now.subsec_micros() as u64).to_le_bytes());
    let mut rnd = vec![0u8; data_len - TIMESTAMP_LEN];
    std::fs::File::open("/dev/urandom").and_then(|mut f| io::Read::read_exact(&mut f, &mut rnd))?;
    p.extend_from_slice(&rnd);
    Ok(p)
}

/// Sleep, but wake up early on Ctrl+C.
fn sleep_interruptible(d: Duration, stop: &AtomicBool) {
    let end = Instant::now() + d;
    while !stop.load(Ordering::Relaxed) {
        let Some(left) = end.checked_duration_since(Instant::now()) else {
            break;
        };
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// Returns true if at least one reply was received (exit status for scripts).
pub fn run(opts: Options) -> io::Result<bool> {
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;

    let rx = mitik_net::udp_socket(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MACTELNET_PORT),
        true,
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Error binding to 0.0.0.0:{MACTELNET_PORT}: {e}"),
        )
    })?;
    let mut transport = Transport::open()?;

    let data_len = (opts.size - PING_HEADER_LEN).max(TIMESTAMP_LEN);
    let expected_len = PING_HEADER_LEN + data_len;
    let mut stats = Stats::default();
    let mut previous: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; protocol::PACKET_LEN];
    let mut seq: u32 = 0;

    while !stop.load(Ordering::Relaxed) && (opts.count == 0 || seq < opts.count) {
        seq += 1;
        let payload = make_payload(data_len)?;
        let started = Instant::now();
        if transport.send(&opts.dst, &payload, seq as u16) == 0 {
            eprintln!("Error sending packet.");
            sleep_interruptible(REPLY_TIMEOUT, &stop);
            continue;
        }
        stats.sent += 1;

        let deadline = started + REPLY_TIMEOUT;
        let mut answered = false;
        while !stop.load(Ordering::Relaxed) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            rx.set_read_timeout(Some(
                left.clamp(Duration::from_millis(1), Duration::from_millis(100)),
            ))?;
            let n = match rx.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            };
            if n != expected_len || buf[1] != PacketType::Pong as u8 {
                continue;
            }
            let src: MacAddr = buf[2..8].try_into().unwrap();
            let data = &buf[PING_HEADER_LEN..n];
            if data == payload.as_slice() {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                println!("{} {n} byte, ping time {ms:.2} ms", src);
                stats.record(ms);
            } else if previous.iter().any(|p| p.as_slice() == data) {
                continue; // late reply to an earlier ping
            } else {
                println!("{} Reply of {n} bytes of unequal data", src);
                stats.received += 1;
            }
            answered = true;
            break;
        }

        if !answered && !stop.load(Ordering::Relaxed) {
            eprintln!("{} ping timeout", opts.dst);
        }
        previous.push(payload);
        if previous.len() > 8 {
            previous.remove(0);
        }
        let last = opts.count != 0 && seq >= opts.count;
        if answered && !opts.fast && !last {
            sleep_interruptible(Duration::from_secs(1), &stop);
        }
    }

    stats.print();
    Ok(stats.received > 0)
}
