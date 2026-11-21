// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Terminal input for the prompts.

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;

/// Both stdin and stdout are terminals.
pub fn is_tty() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// Read one line from stdin, byte by byte.
///
/// `io::stdin()` is buffered and could swallow input that follows the line. The
/// MAC-Telnet session reads the rest of stdin straight from the file descriptor
/// later, so nothing past the newline may be consumed here.
pub fn read_line_stdin() -> io::Result<String> {
    // SAFETY: fd 0 stays open for the whole process; ManuallyDrop keeps it open.
    let mut stdin = ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stdin.read(&mut b) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) if b[0] == b'\r' => {}
            Ok(_) => out.push(b[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}
