// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! MikroTik MAC-Telnet: packet codec, EC-SRP and MD5 authentication, client,
//! server (mactelnetd) and MAC-Ping.
//!
//! Unix only: Linux, macOS and the BSDs.

pub mod autologin;
pub mod client;
pub mod ec_srp;
pub mod ping;
pub mod protocol;
pub mod server;
mod term;
pub mod users;
mod util;
