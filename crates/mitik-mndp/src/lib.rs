// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

#![doc = include_str!("../README.md")]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use mitik_net::MacAddr;

/// UDP port of MNDP.
pub const PORT: u16 = 5678;

/// Largest packet we receive; attribute values are cut to a quarter of it when encoding.
const PACKET_LEN: usize = 1500;

// ---------------------------------------------------------------- wire format

/// What a device tells about itself in an announcement.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Device {
    pub address: MacAddr,
    pub identity: String,
    pub version: String,
    pub platform: String,
    pub hardware: String,
    pub softid: String,
    pub ifname: String,
    pub uptime: u32,
}

const MNDP_ADDRESS: u16 = 0x0001;
const MNDP_IDENTITY: u16 = 0x0005;
const MNDP_VERSION: u16 = 0x0007;
const MNDP_PLATFORM: u16 = 0x0008;
const MNDP_TIMESTAMP: u16 = 0x000a;
const MNDP_SOFTID: u16 = 0x000b;
const MNDP_HARDWARE: u16 = 0x000c;
const MNDP_IFNAME: u16 = 0x0010;

/// Decode an announcement (`parse_mndp()` in C): 4-byte header followed by TLV attributes (big-endian type/len).
pub fn parse(buf: &[u8]) -> Option<Device> {
    if buf.len() < 18 {
        return None;
    }
    let mut info = Device::default();
    let mut p = 4;
    while p + 4 < buf.len() {
        let typ = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + len > buf.len() {
            break;
        }
        let val = &buf[p..p + len];
        let s = || String::from_utf8_lossy(&val[..len.min(127)]).into_owned();
        match typ {
            MNDP_ADDRESS if len >= 6 => info.address = val[..6].try_into().unwrap(),
            MNDP_IDENTITY => info.identity = s(),
            MNDP_VERSION => info.version = s(),
            MNDP_PLATFORM => info.platform = s(),
            MNDP_HARDWARE => info.hardware = s(),
            MNDP_SOFTID => info.softid = s(),
            MNDP_IFNAME => info.ifname = s(),
            // Uptime is little-endian, unlike everything else.
            MNDP_TIMESTAMP if len >= 4 => {
                info.uptime = u32::from_le_bytes(val[..4].try_into().unwrap())
            }
            _ => {}
        }
        p += len;
    }
    Some(info)
}

/// An announcement to send, as `mactelnetd` does.
pub struct Announcement<'a> {
    pub address: MacAddr,
    pub identity: &'a str,
    pub version: &'a str,
    pub platform: &'a str,
    pub hardware: &'a str,
    pub uptime: u32,
    pub softid: &'a str,
    pub ifname: &'a str,
}

impl Announcement<'_> {
    /// `mndp_init_packet(0, 1)` + attributes + Internet checksum in the header.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = vec![0u8, 1, 0, 0];
        let mut tlv = |t: u16, v: &[u8]| {
            let v = &v[..v.len().min(PACKET_LEN / 4)];
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&(v.len() as u16).to_be_bytes());
            p.extend_from_slice(v);
        };
        tlv(MNDP_ADDRESS, &self.address.octets());
        tlv(MNDP_IDENTITY, self.identity.as_bytes());
        tlv(MNDP_VERSION, self.version.as_bytes());
        tlv(MNDP_PLATFORM, self.platform.as_bytes());
        tlv(MNDP_HARDWARE, self.hardware.as_bytes());
        tlv(MNDP_TIMESTAMP, &self.uptime.to_le_bytes());
        tlv(MNDP_SOFTID, self.softid.as_bytes());
        tlv(MNDP_IFNAME, self.ifname.as_bytes());
        let sum = mitik_net::raw::internet_checksum(&p);
        p[2..4].copy_from_slice(&sum.to_be_bytes());
        p
    }
}

// ---------------------------------------------------------------- discovery

/// A listening MNDP socket that has asked every device to announce itself.
pub struct Discovery {
    sock: UdpSocket,
    request_sent: bool,
}

impl Discovery {
    /// Bind UDP port 5678 and broadcast the discovery request.
    pub fn start() -> io::Result<Self> {
        let sock = mitik_net::udp_socket(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT), true)
            .map_err(|e| {
                io::Error::new(e.kind(), format!("Error binding to 0.0.0.0:{PORT}: {e}"))
            })?;
        // An all-zero 4-byte packet asks every router to announce itself. Send it from
        // every interface address as well: a broadcast from 0.0.0.0 only leaves via the
        // default route, which may not exist (or point to the wrong network).
        let request = [0u8; 4];
        let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, PORT);
        let mut sent = sock.send_to(&request, dest).is_ok();
        for ifc in mitik_net::iface::list().unwrap_or_default() {
            if let Ok(tx) = mitik_net::udp_socket(SocketAddrV4::new(ifc.ipv4.unwrap(), PORT), true)
            {
                sent |= tx.send_to(&request, dest).is_ok();
            }
        }
        Ok(Discovery {
            sock,
            request_sent: sent,
        })
    }

    /// False when the discovery request could not be broadcast on any interface.
    /// Devices still announce themselves about once a minute on their own, so
    /// [`recv`](Self::recv) keeps working, only slower.
    pub fn request_sent(&self) -> bool {
        self.request_sent
    }

    /// Receive one announcement and its sender, or None once `deadline` has passed.
    /// Without a deadline it waits forever.
    pub fn recv(&self, deadline: Option<Instant>) -> io::Result<Option<(Device, SocketAddr)>> {
        let mut buf = [0u8; PACKET_LEN];
        loop {
            let timeout = match deadline {
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    Some(t) if !t.is_zero() => Some(t),
                    _ => return Ok(None),
                },
                None => None,
            };
            self.sock.set_read_timeout(timeout)?;
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Some(info) = parse(&buf[..n]) {
                        return Ok(Some((info, from)));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Find a device MAC by its identity (case-insensitive).
pub fn query(identity: &str, timeout: Duration) -> io::Result<Option<MacAddr>> {
    let discovery = Discovery::start()?;
    let deadline = Instant::now() + timeout;
    while let Some((p, _)) = discovery.recv(Some(deadline))? {
        if p.identity.eq_ignore_ascii_case(identity) {
            return Ok(Some(p.address));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddr = MacAddr::new([1, 2, 3, 4, 5, 6]);

    #[test]
    fn mndp() {
        let mut d = vec![0, 0, 0, 0];
        let mut tlv = |t: u16, v: &[u8]| {
            d.extend_from_slice(&t.to_be_bytes());
            d.extend_from_slice(&(v.len() as u16).to_be_bytes());
            d.extend_from_slice(v);
        };
        tlv(MNDP_ADDRESS, &A.octets());
        tlv(MNDP_IDENTITY, b"MikroTik");
        tlv(MNDP_TIMESTAMP, &90061u32.to_le_bytes());
        tlv(MNDP_PLATFORM, b"MikroTik");
        let i = parse(&d).unwrap();
        assert_eq!(i.address, A);
        assert_eq!(i.identity, "MikroTik");
        assert_eq!(i.uptime, 90061);
    }

    #[test]
    fn mndp_announce_roundtrip() {
        let pkt = Announcement {
            address: A,
            identity: "host",
            version: "6.1",
            platform: "Linux",
            hardware: "aarch64",
            uptime: 3600,
            softid: "MAC-Telnet",
            ifname: "eth0",
        }
        .encode();
        assert_eq!(mitik_net::raw::internet_checksum(&pkt), 0);
        let i = parse(&pkt).unwrap();
        assert_eq!(
            (i.address, i.identity.as_str(), i.uptime),
            (A, "host", 3600)
        );
        assert_eq!(
            (i.softid.as_str(), i.ifname.as_str()),
            ("MAC-Telnet", "eth0")
        );
    }
}
