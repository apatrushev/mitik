// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Ethernet hardware (MAC) addresses.

use std::array::TryFromSliceError;
use std::fmt;
use std::str::FromStr;

/// An Ethernet hardware address.
///
/// It prints as `aa:bb:cc:dd:ee:ff` and parses from `aa:bb:cc:dd:ee:ff` or
/// `aa-bb-cc-dd-ee-ff`, with one or two hex digits per octet (like `ether_aton`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    /// `00:00:00:00:00:00`
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

/// Takes exactly six bytes.
impl TryFrom<&[u8]> for MacAddr {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 6]>::try_from(bytes).map(MacAddr)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// The text is not a MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMacError;

impl fmt::Display for ParseMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address")
    }
}

impl std::error::Error for ParseMacError {}

impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sep = if s.contains(':') { ':' } else { '-' };
        let mut octets = [0u8; 6];
        let mut parts = s.split(sep);
        for octet in &mut octets {
            let part = parts.next().ok_or(ParseMacError)?;
            if part.is_empty() || part.len() > 2 {
                return Err(ParseMacError);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| ParseMacError)?;
        }
        if parts.next().is_some() {
            return Err(ParseMacError);
        }
        Ok(MacAddr(octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_print() {
        assert_eq!(
            "01:02:03:04:05:06".parse(),
            Ok(MacAddr::new([1, 2, 3, 4, 5, 6]))
        );
        let mac: MacAddr = "a-b-c-d-e-f".parse().unwrap();
        assert_eq!(mac.octets(), [0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
        assert_eq!(mac.to_string(), "0a:0b:0c:0d:0e:0f");
        assert_eq!(format!("{mac:?}"), "MacAddr(0a:0b:0c:0d:0e:0f)");
        for bad in ["router", "1:2:3:4:5", "1:2:3:4:5:6:7", "1:2:3:4:5:", "100:2:3:4:5:6", "g:2:3:4:5:6"] {
            assert_eq!(bad.parse::<MacAddr>(), Err(ParseMacError), "{bad}");
        }
    }

    #[test]
    fn from_slice() {
        assert_eq!(
            MacAddr::try_from(&[1u8, 2, 3, 4, 5, 6][..]).ok(),
            Some(MacAddr::new([1, 2, 3, 4, 5, 6]))
        );
        assert!(MacAddr::try_from(&[1u8, 2, 3][..]).is_err());
    }
}
