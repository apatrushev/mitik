// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Small OS helpers: randomness and poll().

use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd};

pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

/// poll() on a set of fds for readability; returns readiness flags in the same order.
pub fn poll_readable(fds: &[BorrowedFd<'_>], timeout_ms: i32) -> io::Result<Vec<bool>> {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&fd.as_fd()),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout_ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![false; fds.len()]);
        }
        return Err(e);
    }
    Ok(pfds
        .iter()
        .map(|p| p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
        .collect())
}
