// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! `mitik server -a / -d / -l`: manage the users of the MAC-Telnet server.

use std::io;
use std::path::Path;

use mitik_mactelnet::users::{self, Secret};
use nix::unistd::User;

pub fn add(path: &Path, username: Option<String>, password: Option<String>) -> Result<(), String> {
    let username = match username {
        Some(u) => u,
        None => {
            print!("Username: ");
            let _ = io::Write::flush(&mut io::stdout());
            crate::tty::read_line_stdin().map_err(|e| e.to_string())?
        }
    };
    if username.is_empty() {
        return Err("Username must be specified.".into());
    }
    if username.len() > 32 {
        return Err("Username too long.".into());
    }
    if username.contains(':') || username.contains('\n') {
        return Err("Username must not contain ':' or newlines.".into());
    }
    if User::from_name(&username).ok().flatten().is_none() {
        eprintln!("Warning: Local user '{username}' does not exist.");
    }
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ").map_err(|e| e.to_string())?,
    };
    if password.is_empty() {
        return Err("Password must be specified.".into());
    }
    match users::modify(path, &username, Some(&password)).map_err(|e| e.to_string())? {
        users::Change::Added => println!("User {username} was added."),
        _ => println!("User {username} was updated."),
    }
    Ok(())
}

pub fn delete(path: &Path, username: &str) -> Result<(), String> {
    match users::modify(path, username, None).map_err(|e| e.to_string())? {
        users::Change::Deleted => println!("User {username} was deleted."),
        _ => println!("User {username} did not exist."),
    }
    Ok(())
}

pub fn list(path: &Path) -> Result<(), String> {
    let list = users::load(path).map_err(|e| e.to_string())?;
    for line in &list.invalid_lines {
        eprintln!("Warning: {line}");
    }
    println!("Users:");
    for u in list.credentials {
        let note = match User::from_name(&u.username).ok().flatten() {
            None => Some("local user not found!"),
            Some(l) if l.uid.is_root() || l.gid.as_raw() == 0 => Some("has root access!"),
            _ if matches!(u.secret, Secret::Plain(_)) => Some("plain-text password!"),
            _ => None,
        };
        match note {
            Some(n) => println!("\t{} ({n})", u.username),
            None => println!("\t{}", u.username),
        }
    }
    println!();
    Ok(())
}
