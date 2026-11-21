// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Network interface enumeration (IPv4 address + hardware address per interface).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::MacAddr;

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub mac: MacAddr,
}

/// All non-loopback interfaces with a non-zero MAC, with their first IPv4 address if any.
pub fn with_mac() -> std::io::Result<Vec<Interface>> {
    let mut ips: BTreeMap<String, Ipv4Addr> = BTreeMap::new();
    let mut macs: BTreeMap<String, MacAddr> = BTreeMap::new();

    for ifa in nix::ifaddrs::getifaddrs().map_err(std::io::Error::from)? {
        let Some(addr) = ifa.address else { continue };
        if let Some(sin) = addr.as_sockaddr_in() {
            ips.entry(ifa.interface_name.clone()).or_insert(sin.ip());
        } else if let Some(mac) = addr.as_link_addr().and_then(|l| l.addr())
            && mac != [0u8; 6]
        {
            macs.insert(ifa.interface_name.clone(), MacAddr::new(mac));
        }
    }

    Ok(macs
        .into_iter()
        .filter(|(name, _)| !name.starts_with("lo"))
        .map(|(name, mac)| Interface {
            ipv4: ips.get(&name).copied(),
            name,
            mac,
        })
        .collect())
}

/// Interfaces usable for UDP broadcast: both an IPv4 address and a MAC.
pub fn list() -> std::io::Result<Vec<Interface>> {
    Ok(with_mac()?
        .into_iter()
        .filter(|i| i.ipv4.is_some())
        .collect())
}
