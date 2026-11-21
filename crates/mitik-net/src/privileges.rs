// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Root privileges: raw sockets need them, and they should be dropped afterwards.

use std::io;

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Switch to `username` (gid, supplementary groups, uid) and make sure root
/// cannot be regained (`drop_privileges()` in the C client).
pub fn drop_privileges(username: &str) -> io::Result<()> {
    use nix::unistd::{Uid, User, setgid, setuid};
    let user = User::from_name(username)
        .map_err(io::Error::from)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("The user {username} is not a valid username on local system."),
            )
        })?;
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let cname = std::ffi::CString::new(username).map_err(|_| io::ErrorKind::InvalidInput)?;
    // initgroups' gid argument is int on macOS and gid_t elsewhere.
    if unsafe { libc::initgroups(cname.as_ptr(), user.gid.as_raw() as _) } != 0 {
        return Err(io::Error::last_os_error());
    }
    setgid(user.gid).map_err(io::Error::from)?;
    setuid(user.uid).map_err(io::Error::from)?;
    if setuid(Uid::from_raw(0)).is_ok() {
        return Err(io::Error::other("Failed to drop privileges"));
    }
    Ok(())
}
