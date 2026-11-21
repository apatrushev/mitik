// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Network plumbing shared by the mitik crates: MAC addresses, interface
//! enumeration, UDP broadcast sockets, hand-built Ethernet frames and raw sockets.
//!
//! Unix only: Linux, macOS and the BSDs.

/// Items compiled only on the systems mitik supports.
macro_rules! supported {
    ($($item:item)*) => {
        $(
            #[cfg(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            $item
        )*
    };
}

// Every other mitik crate depends on this one, so on any other system this is the
// only error the build shows, instead of a pile of missing Unix APIs.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
compile_error!(
    "mitik supports only Linux, macOS, FreeBSD, NetBSD and OpenBSD: it needs PTYs, \
     raw sockets (AF_PACKET or BPF) and other Unix APIs."
);

supported! {
    pub mod iface;
    mod mac;
    mod privileges;
    pub mod raw;
    mod udp;

    pub use mac::{MacAddr, ParseMacError};
    pub use privileges::{drop_privileges, is_root};
    pub use udp::udp_socket;
}
