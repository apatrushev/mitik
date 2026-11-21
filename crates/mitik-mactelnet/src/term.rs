// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Terminal helpers for the interactive client: raw mode, window size and
//! unbuffered reads from stdin.

use std::io;
use std::os::fd::BorrowedFd;

use nix::sys::termios::{self, SetArg, Termios};

fn stdin_fd() -> BorrowedFd<'static> {
    // SAFETY: fd 0 lives for the whole process.
    unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) }
}

/// Terminal size (columns, rows) of stdout.
pub fn terminal_size() -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    (r == 0).then_some((ws.ws_col, ws.ws_row))
}

/// Puts stdin into raw mode; restores the original settings on drop.
pub struct RawTerminal {
    saved: Termios,
}

impl RawTerminal {
    pub fn enable() -> io::Result<Self> {
        let saved = termios::tcgetattr(stdin_fd())?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(stdin_fd(), SetArg::TCSANOW, &raw)?;
        Ok(RawTerminal { saved })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(stdin_fd(), SetArg::TCSANOW, &self.saved);
    }
}

/// Unbuffered read from fd 0 (so that poll() readiness stays accurate).
pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

pub fn stdin_borrowed() -> BorrowedFd<'static> {
    stdin_fd()
}
