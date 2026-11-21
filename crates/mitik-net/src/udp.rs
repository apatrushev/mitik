// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! UDP broadcast sockets.

use std::io;
use std::net::{SocketAddrV4, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

/// UDP socket with SO_REUSEADDR (+SO_REUSEPORT) and SO_BROADCAST, bound to `addr`.
pub fn udp_socket(addr: SocketAddrV4, reuse_port: bool) -> io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    if reuse_port {
        s.set_reuse_port(true)?;
    }
    s.set_broadcast(true)?;
    s.bind(&addr.into())?;
    Ok(s.into())
}
