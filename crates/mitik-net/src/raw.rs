// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Sending hand-built Ethernet/IPv4/UDP frames, so that the Ethernet destination
//! is the device's real MAC instead of broadcast (port of `net_send_udp()`).
//! Requires root: AF_PACKET on Linux, BPF on macOS/BSD.

use std::io;
use std::net::Ipv4Addr;

use crate::MacAddr;

pub const ETH_FRAME_LEN: usize = 1514;
const HEADERS_LEN: usize = 14 + 20 + 8;
/// Largest UDP payload that fits in one Ethernet frame.
pub const MAX_PAYLOAD: usize = ETH_FRAME_LEN - HEADERS_LEN;

fn ones_complement_sum(data: &[u8], mut sum: u32) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u16::from_be_bytes(*pair) as u32;
    }
    if let [last] = rest {
        sum += (*last as u32) << 8;
    }
    sum
}

/// RFC 1071 Internet checksum (`in_cksum()`), big-endian.
pub fn internet_checksum(data: &[u8]) -> u16 {
    fold(ones_complement_sum(data, 0))
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct UdpEndpoint {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// Build a complete Ethernet frame carrying one UDP datagram.
pub fn build_frame(
    src: &UdpEndpoint,
    dst: &UdpEndpoint,
    payload: &[u8],
    ip_id: u16,
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet size too large",
        ));
    }
    let udp_len = (8 + payload.len()) as u16;
    let mut f = Vec::with_capacity(HEADERS_LEN + payload.len());

    // Ethernet
    f.extend_from_slice(&dst.mac.octets());
    f.extend_from_slice(&src.mac.octets());
    f.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 (TOS 0x10 and DF, like the C implementation)
    let ip_start = f.len();
    f.extend_from_slice(&[0x45, 0x10]);
    f.extend_from_slice(&(20 + udp_len).to_be_bytes());
    f.extend_from_slice(&ip_id.to_be_bytes());
    f.extend_from_slice(&0x4000u16.to_be_bytes());
    f.extend_from_slice(&[64, 17, 0, 0]);
    f.extend_from_slice(&src.ip.octets());
    f.extend_from_slice(&dst.ip.octets());
    let ip_sum = fold(ones_complement_sum(&f[ip_start..], 0));
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());

    // UDP
    let udp_start = f.len();
    f.extend_from_slice(&src.port.to_be_bytes());
    f.extend_from_slice(&dst.port.to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.ip.octets());
    pseudo.extend_from_slice(&dst.ip.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    let mut udp_sum = fold(ones_complement_sum(
        &f[udp_start..],
        ones_complement_sum(&pseudo, 0),
    ));
    if udp_sum == 0 {
        udp_sum = 0xffff; // 0 means "no checksum" in UDP
    }
    f[udp_start + 6..udp_start + 8].copy_from_slice(&udp_sum.to_be_bytes());
    Ok(f)
}

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::ffi::CString;

    pub struct RawSocket {
        fd: libc::c_int,
    }

    impl RawSocket {
        /// One AF_PACKET socket serves every interface; `_ifnames` is only
        /// needed on BSD, where devices must be opened up front.
        pub fn open(_ifnames: &[String]) -> io::Result<Self> {
            let fd = check(unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
                )
            })?;
            Ok(RawSocket { fd })
        }

        pub fn send(&mut self, ifname: &str, frame: &[u8]) -> io::Result<usize> {
            let name = CString::new(ifname).map_err(|_| io::ErrorKind::InvalidInput)?;
            let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if ifindex == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
            sll.sll_ifindex = ifindex as i32;
            sll.sll_halen = 6;
            sll.sll_addr[..6].copy_from_slice(&frame[..6]);
            let n = unsafe {
                libc::sendto(
                    self.fd,
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    (&sll as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Drop for RawSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod imp {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd};

    /// One BPF device per interface (BIOCSETIF binds it permanently).
    pub struct RawSocket {
        devices: Vec<(String, OwnedFd)>,
    }

    fn open_bpf(ifname: &str) -> io::Result<OwnedFd> {
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for i in 0..256 {
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/dev/bpf{i}"))
            {
                Ok(f) => f,
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => continue,
                Err(e) => {
                    last = e;
                    if last.kind() == io::ErrorKind::NotFound {
                        break;
                    } else {
                        continue;
                    }
                }
            };
            let fd: OwnedFd = file.into();
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            for (d, s) in req
                .ifr_name
                .iter_mut()
                .zip(ifname.bytes().take(libc::IFNAMSIZ - 1))
            {
                *d = s as libc::c_char;
            }
            check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSETIF, &req) })?;
            // We supply the Ethernet source address ourselves.
            let one: libc::c_uint = 1;
            check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSHDRCMPLT, &one) })?;
            return Ok(fd);
        }
        Err(last)
    }

    impl RawSocket {
        /// Open BPF devices for all interfaces now, while we still are root
        /// (so privileges can be dropped afterwards, see `-U`).
        pub fn open(ifnames: &[String]) -> io::Result<Self> {
            let mut devices = Vec::new();
            let mut last = None;
            for name in ifnames {
                match open_bpf(name) {
                    Ok(fd) => devices.push((name.clone(), fd)),
                    Err(e) => last = Some(e),
                }
            }
            match (devices.is_empty(), last) {
                (true, Some(e)) => Err(e),
                _ => Ok(RawSocket { devices }),
            }
        }

        pub fn send(&mut self, ifname: &str, frame: &[u8]) -> io::Result<usize> {
            let idx = match self.devices.iter().position(|(n, _)| n == ifname) {
                Some(i) => i,
                None => {
                    self.devices.push((ifname.to_string(), open_bpf(ifname)?));
                    self.devices.len() - 1
                }
            };
            let fd = self.devices[idx].1.as_raw_fd();
            let n = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }
}

pub use imp::RawSocket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_and_checksums() {
        let src = UdpEndpoint {
            mac: MacAddr::new([2, 0, 0, 0, 0, 1]),
            ip: Ipv4Addr::UNSPECIFIED,
            port: 20561,
        };
        let dst = UdpEndpoint {
            mac: MacAddr::new([2, 0, 0, 0, 0, 2]),
            ip: Ipv4Addr::BROADCAST,
            port: 20561,
        };
        let f = build_frame(&src, &dst, b"hello", 1).unwrap();
        assert_eq!(f.len(), HEADERS_LEN + 5);
        assert_eq!(f[..6], dst.mac.octets());
        assert_eq!(f[6..12], src.mac.octets());
        // A correct header checksums to zero.
        assert_eq!(fold(ones_complement_sum(&f[14..34], 0)), 0);
        let mut pseudo = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, 17];
        pseudo.extend_from_slice(&13u16.to_be_bytes());
        assert_eq!(
            fold(ones_complement_sum(
                &f[34..],
                ones_complement_sum(&pseudo, 0)
            )),
            0
        );
        assert!(build_frame(&src, &dst, &[0; MAX_PAYLOAD + 1], 1).is_err());
    }
}
