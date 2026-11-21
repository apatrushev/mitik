// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! mitik — tools for MikroTik RouterOS devices: MAC-Telnet client and server,
//! MAC-Ping and MNDP discovery.
//!
//! Invoked as `mactelnet`, `macping` or `mactelnetd` (for example through a
//! symlink), it accepts the options of the C tool of that name.

mod args;
mod discover;
mod server_users;
mod tty;

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mitik_mactelnet::{autologin, client, ping, server};
use mitik_net::raw::RawSocket;
use mitik_net::{MacAddr, iface};

use args::{
    Cli, Command, MacpingCompat, MactelnetCompat, MactelnetdCompat, PingArgs, ServerArgs,
    TelnetArgs,
};

const DEFAULT_CONNECT_TIMEOUT: u64 = 2;
const MNDP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn resolve(target: &str, verbose: bool) -> std::io::Result<Option<MacAddr>> {
    if let Ok(mac) = target.parse::<MacAddr>() {
        return Ok(Some(mac));
    }
    if verbose {
        eprint!("Searching for '{target}'...");
    }
    let found = mitik_mndp::query(target, MNDP_LOOKUP_TIMEOUT)?;
    if verbose {
        eprintln!(
            "{}",
            if found.is_some() {
                "found"
            } else {
                "not found"
            }
        );
    }
    Ok(found)
}

fn cmd_telnet(args: TelnetArgs) -> Result<(), String> {
    let TelnetArgs { target, opts } = args;
    let is_tty = tty::is_tty();
    let quiet = opts.quiet || !is_tty;

    let (mut username, mut password) = (opts.user, opts.password);
    if !opts.no_autologin
        && let Some(p) = autologin::load(&opts.autologin_path, &target)
    {
        if !quiet && (p.username.is_some() || p.password.is_some()) {
            eprintln!("Using autologin credentials from {}", opts.autologin_path);
        }
        username = username.or(p.username);
        password = password.or(p.password);
    }

    // Like the C client: open the raw socket and drop root before doing anything else.
    let raw = if opts.raw {
        if !mitik_net::is_root() {
            return Err("You need to have root privileges to use the -n parameter.".into());
        }
        let names: Vec<String> = iface::with_mac()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|i| i.name)
            .collect();
        let sock = RawSocket::open(&names).map_err(|e| format!("raw socket: {e}"))?;
        if let Some(user) = &opts.drop_to {
            mitik_net::drop_privileges(user)
                .map_err(|e| format!("Failed dropping privileges: {e}"))?;
        }
        Some(sock)
    } else {
        None
    };

    let dst = resolve(&target, !quiet)
        .map_err(|e| e.to_string())?
        .ok_or("")?;

    let username = match username {
        Some(u) => u,
        None => {
            if !quiet {
                print!("Login: ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            tty::read_line_stdin().map_err(|e| e.to_string())?
        }
    };
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")
            .or_else(|_| tty::read_line_stdin())
            .map_err(|e| e.to_string())?,
    };

    client::run(client::Options {
        dst,
        username,
        password,
        force_md5: opts.force_md5,
        connect_timeout: Duration::from_secs(opts.timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT)),
        quiet,
        is_tty,
        raw,
    })
    .map_err(|e| e.to_string())
}

fn cmd_ping(args: PingArgs) -> Result<(), String> {
    ping::validate(args.count, args.size, args.fast).map_err(|e| e.to_string())?;
    let dst = resolve(&args.target, true)
        .map_err(|e| e.to_string())?
        .ok_or("")?;
    let ok = ping::run(ping::Options {
        dst,
        count: args.count,
        size: args.size,
        fast: args.fast,
    })
    .map_err(|e| e.to_string())?;
    // Exit status 1 when nothing answered, for scripts (like macping).
    if ok { Ok(()) } else { Err(String::new()) }
}

fn cmd_server(args: ServerArgs) -> Result<(), String> {
    if args.add {
        return server_users::add(&args.users_file, args.user, args.password);
    }
    if let Some(user) = &args.delete {
        return server_users::delete(&args.users_file, user);
    }
    if args.list {
        return server_users::list(&args.users_file);
    }
    if args.raw && !mitik_net::is_root() {
        return Err("You need to have root privileges to use the -n parameter.".into());
    }
    server::run(server::Options {
        raw: args.raw,
        md5: args.md5,
        foreground: args.foreground || cfg!(target_os = "macos"),
        users_path: args.users_file,
    })
    .map_err(|e| e.to_string())
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Telnet(a) => cmd_telnet(a),
        Command::Ping(a) => cmd_ping(a),
        Command::Discover(a) => {
            discover::run(a.timeout.unwrap_or(0), a.batch).map_err(|e| e.to_string())
        }
        Command::Server(a) => cmd_server(a),
    }
}

/// The C tools are separate programs. mitik is one, and behaves like the C tool
/// whose name it is invoked under.
fn parse_args() -> Result<Command, String> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let invoked_as = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match invoked_as.as_str() {
        "mactelnet" => MactelnetCompat::parse_from(args).into_command(),
        "macping" => Ok(Command::Ping(MacpingCompat::parse_from(args).args)),
        "mactelnetd" => Ok(Command::Server(MactelnetdCompat::parse_from(args).args)),
        _ => Ok(Cli::parse_from(args).command),
    }
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("\n{msg}");
            }
            ExitCode::FAILURE
        }
    }
}
