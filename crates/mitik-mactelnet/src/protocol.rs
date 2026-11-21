// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Wire format of the MAC-Telnet protocol (port of `protocol.c`).

use mitik_net::MacAddr;

pub const HEADER_LEN: usize = 22;
pub(crate) const CPHEADER_LEN: usize = 9;
pub const PACKET_LEN: usize = 1500;

pub const MACTELNET_PORT: u16 = 20561;

pub(crate) const CPMAGIC: [u8; 4] = [0x56, 0x34, 0x12, 0xff];
pub(crate) const CLIENT_TYPE: [u8; 2] = [0x00, 0x15];

/// Retransmission back-off schedule, milliseconds.
pub(crate) const RETRANSMIT_INTERVALS: [u64; 9] = [15, 20, 30, 50, 90, 170, 330, 660, 1000];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    SessionStart = 0,
    Data = 1,
    Ack = 2,
    Ping = 4,
    Pong = 5,
    End = 255,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::SessionStart,
            1 => Self::Data,
            2 => Self::Ack,
            4 => Self::Ping,
            5 => Self::Pong,
            255 => Self::End,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlType {
    BeginAuth = 0,
    PassSalt = 1,
    Password = 2,
    Username = 3,
    TermType = 4,
    TermWidth = 5,
    TermHeight = 6,
    PacketError = 7,
    EndAuth = 9,
}

/// Which side builds/parses the packet: the session key and client type
/// fields swap places depending on direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ToServer,
    FromServer,
}

pub struct Packet {
    pub data: Vec<u8>,
}

impl Packet {
    /// `init_packet()`: build the 22-byte header.
    pub fn new(
        ptype: PacketType,
        src: &MacAddr,
        dst: &MacAddr,
        session: u16,
        counter: u32,
        dir: Direction,
    ) -> Self {
        let mut data = Vec::with_capacity(PACKET_LEN);
        data.push(1);
        data.push(ptype as u8);
        data.extend_from_slice(&src.octets());
        data.extend_from_slice(&dst.octets());
        match dir {
            Direction::ToServer => {
                data.extend_from_slice(&session.to_be_bytes());
                data.extend_from_slice(&CLIENT_TYPE);
            }
            Direction::FromServer => {
                data.extend_from_slice(&CLIENT_TYPE);
                data.extend_from_slice(&session.to_be_bytes());
            }
        }
        data.extend_from_slice(&counter.to_be_bytes());
        Packet { data }
    }

    /// Append a control packet; returns the number of bytes added (counts towards the counter).
    pub fn add_control(&mut self, cptype: ControlType, payload: &[u8]) -> usize {
        let len = CPHEADER_LEN + payload.len();
        assert!(
            self.data.len() + len <= PACKET_LEN,
            "control packet too large"
        );
        self.data.extend_from_slice(&CPMAGIC);
        self.data.push(cptype as u8);
        self.data
            .extend_from_slice(&(payload.len() as u32).to_be_bytes());
        self.data.extend_from_slice(payload);
        len
    }

    /// Append raw terminal data; returns the number of bytes added.
    pub fn add_plain(&mut self, payload: &[u8]) -> usize {
        assert!(
            self.data.len() + payload.len() <= PACKET_LEN,
            "data packet too large"
        );
        self.data.extend_from_slice(payload);
        payload.len()
    }
}

/// MAC-Ping header: like the regular header, but session/client-type bytes are
/// zero and the counter is omitted.
pub const PING_HEADER_LEN: usize = 18;

/// `init_pingpacket()` / `init_pongpacket()` + payload.
pub fn ping_packet(ptype: PacketType, src: &MacAddr, dst: &MacAddr, payload: &[u8]) -> Vec<u8> {
    let mut p = Packet::new(ptype, src, dst, 0, 0, Direction::ToServer).data;
    p.truncate(PING_HEADER_LEN);
    p[14..18].fill(0);
    p.extend_from_slice(payload);
    p
}

#[derive(Debug, Clone)]
pub struct Header<'a> {
    pub ver: u8,
    pub ptype: u8,
    pub src: MacAddr,
    pub dst: MacAddr,
    pub session: u16,
    pub client_type: [u8; 2],
    pub counter: u32,
    pub payload: &'a [u8],
}

/// `parse_packet()`. `dir` is the direction the packet travelled.
pub fn parse_packet(buf: &[u8], dir: Direction) -> Option<Header<'_>> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let (sk, ct) = match dir {
        Direction::ToServer => (14, 16),
        Direction::FromServer => (16, 14),
    };
    Some(Header {
        ver: buf[0],
        ptype: buf[1],
        src: buf[2..8].try_into().unwrap(),
        dst: buf[8..14].try_into().unwrap(),
        session: u16::from_be_bytes([buf[sk], buf[sk + 1]]),
        client_type: [buf[ct], buf[ct + 1]],
        counter: u32::from_be_bytes(buf[18..22].try_into().unwrap()),
        payload: &buf[HEADER_LEN..],
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Control<'a> {
    /// A control packet with known magic: (type byte, payload).
    Control(u8, &'a [u8]),
    /// Remaining bytes without control magic: raw terminal data.
    Plain(&'a [u8]),
}

/// Iterator over control packets inside a DATA payload (`parse_control_packet()`).
pub struct ControlIter<'a> {
    data: &'a [u8],
}

pub fn controls(data: &[u8]) -> ControlIter<'_> {
    ControlIter { data }
}

impl<'a> Iterator for ControlIter<'a> {
    type Item = Control<'a>;

    fn next(&mut self) -> Option<Control<'a>> {
        let d = self.data;
        if d.is_empty() {
            return None;
        }
        if d.len() >= CPHEADER_LEN && d[..4] == CPMAGIC {
            let cptype = d[4];
            let len = (u32::from_be_bytes(d[5..9].try_into().unwrap()) as usize)
                .min(d.len() - CPHEADER_LEN);
            let payload = &d[CPHEADER_LEN..CPHEADER_LEN + len];
            self.data = &d[CPHEADER_LEN + len..];
            Some(Control::Control(cptype, payload))
        } else {
            self.data = &[];
            Some(Control::Plain(d))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddr = MacAddr::new([1, 2, 3, 4, 5, 6]);
    const B: MacAddr = MacAddr::new([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);

    #[test]
    fn header_roundtrip_both_directions() {
        for dir in [Direction::ToServer, Direction::FromServer] {
            let p = Packet::new(PacketType::Data, &A, &B, 0x1234, 0xdeadbeef, dir);
            assert_eq!(p.data.len(), HEADER_LEN);
            let h = parse_packet(&p.data, dir).unwrap();
            assert_eq!(
                (h.src, h.dst, h.session, h.counter),
                (A, B, 0x1234, 0xdeadbeef)
            );
            assert_eq!(h.client_type, CLIENT_TYPE);
        }
        let p = Packet::new(PacketType::Data, &A, &B, 0x1234, 0, Direction::ToServer);
        assert_eq!(&p.data[14..18], &[0x12, 0x34, 0x00, 0x15]);
    }

    #[test]
    fn controls_then_plain() {
        let mut p = Packet::new(PacketType::Data, &A, &B, 1, 0, Direction::ToServer);
        assert_eq!(p.add_control(ControlType::Username, b"admin"), 14);
        p.add_control(ControlType::EndAuth, b"");
        p.add_plain(b"hello");
        let items: Vec<_> = controls(&p.data[HEADER_LEN..]).collect();
        assert_eq!(
            items,
            vec![
                Control::Control(3, b"admin"),
                Control::Control(9, b""),
                Control::Plain(b"hello")
            ]
        );
    }

    #[test]
    fn truncated_control_is_clamped() {
        let mut d = CPMAGIC.to_vec();
        d.push(2);
        d.extend_from_slice(&100u32.to_be_bytes());
        d.extend_from_slice(b"abc");
        assert_eq!(
            controls(&d).collect::<Vec<_>>(),
            vec![Control::Control(2, b"abc")]
        );
    }
}
