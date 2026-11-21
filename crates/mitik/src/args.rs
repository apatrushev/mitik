// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! Command-line arguments: the `mitik` subcommands, and the option sets of the
//! C tools (`mactelnet`, `macping`, `mactelnetd`) for when mitik is invoked
//! under one of their names.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};
use mitik_mactelnet::{ping, users};

const AUTOLOGIN_PATH: &str = "~/.mactelnet";
const SERVER_AFTER_HELP: &str = "If any of -a, -d or -l is specified, the server will not start.";

#[derive(Parser, Debug)]
#[command(
    name = "mitik",
    version,
    about = "Tools for MikroTik RouterOS devices",
    arg_required_else_help = true,
    after_help = "Invoked as mactelnet, macping or mactelnetd (for example through a symlink), mitik\naccepts the options of the C tool of that name."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Log in to a device by its MAC address or identity (MAC-Telnet)
    Telnet(TelnetArgs),
    /// MAC-Ping a device (raw frames as root, UDP broadcast otherwise)
    Ping(PingArgs),
    /// List MikroTik devices on the local network (MNDP)
    Discover(DiscoverArgs),
    /// Run the MAC-Telnet server (mactelnetd), or manage its users
    #[command(after_help = SERVER_AFTER_HELP)]
    Server(ServerArgs),
}

#[derive(Args, Debug)]
pub struct TelnetArgs {
    /// MAC address of the RouterOS/mactelnetd device, or its identity (resolved via MNDP)
    #[arg(value_name = "MAC|identity")]
    pub target: String,

    #[command(flatten)]
    pub opts: TelnetOpts,
}

#[derive(Args, Debug)]
pub struct TelnetOpts {
    /// Do not use broadcast: send raw frames to the device MAC (needs root)
    #[arg(short = 'n')]
    pub raw: bool,

    /// Drop privileges to this user after opening the raw socket (with -n)
    #[arg(short = 'U', value_name = "user", requires = "raw")]
    pub drop_to: Option<String>,

    /// Seconds to wait for a connection [default: 2]
    #[arg(short = 't', value_name = "timeout")]
    pub timeout: Option<u64>,

    /// Username
    #[arg(short = 'u', value_name = "user")]
    pub user: Option<String>,

    /// Password
    #[arg(short = 'p', value_name = "password")]
    pub password: Option<String>,

    /// Quiet mode
    #[arg(short = 'q')]
    pub quiet: bool,

    /// Force the old MD5 authentication algorithm
    #[arg(short = 'o')]
    pub force_md5: bool,

    /// Disable autologin
    #[arg(short = 'A')]
    pub no_autologin: bool,

    /// Autologin config file
    #[arg(short = 'a', value_name = "path", default_value = AUTOLOGIN_PATH)]
    pub autologin_path: String,
}

#[derive(Args, Debug)]
pub struct PingArgs {
    /// MAC address of the device, or its identity (resolved via MNDP)
    #[arg(value_name = "MAC|identity")]
    pub target: String,

    /// Number of packets to send (0 = unlimited)
    #[arg(short = 'c', value_name = "count", default_value_t = 5)]
    pub count: u32,

    /// Packet size in bytes, including the 18-byte header
    #[arg(short = 's', value_name = "packet size", default_value_t = ping::DEFAULT_SIZE)]
    pub size: usize,

    /// Fast mode: do not wait before sending the next request
    #[arg(short = 'f')]
    pub fast: bool,
}

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Batch mode: machine-readable CSV output
    #[arg(short = 'B')]
    pub batch: bool,

    /// Stop after this many seconds [default: run until interrupted]
    #[arg(short = 't', value_name = "timeout")]
    pub timeout: Option<u64>,
}

#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Run in the foreground (always on macOS) and also log to stderr
    #[arg(short = 'f')]
    pub foreground: bool,

    /// Do not use broadcast packets: send raw frames to the client MAC (needs root)
    #[arg(short = 'n')]
    pub raw: bool,

    /// Use the legacy MD5 authentication instead of EC-SRP (needs plain-text passwords)
    #[arg(short = 'o')]
    pub md5: bool,

    /// List users from the user file
    #[arg(short = 'l', conflicts_with_all = ["add", "delete"])]
    pub list: bool,

    /// Add or update a user (stored as an EC-SRP hash)
    #[arg(short = 'a', conflicts_with = "delete")]
    pub add: bool,

    /// Username for -a (asked for if omitted)
    #[arg(short = 'u', value_name = "user", requires = "add")]
    pub user: Option<String>,

    /// Password for -a (asked for if omitted)
    #[arg(short = 'p', value_name = "password", requires = "add")]
    pub password: Option<String>,

    /// Delete a user
    #[arg(short = 'd', value_name = "user")]
    pub delete: Option<String>,

    /// User file
    #[arg(long = "users-file", value_name = "path", default_value = users::DEFAULT_PATH)]
    pub users_file: PathBuf,
}

// ------------------------------------------------------------ names of the C tools

/// `mactelnet`: the client, plus device discovery with `-l`.
#[derive(Parser, Debug)]
#[command(
    name = "mactelnet",
    version,
    disable_version_flag = true,
    about = "MAC-Telnet client for MikroTik RouterOS devices (mitik invoked as mactelnet)",
    override_usage = "mactelnet <MAC|identity> [-nqoA] [-U <user>] [-a <path>] [-t <timeout>] [-u <user>] [-p <password>]\n       mactelnet -l [-B] [-t <timeout>]"
)]
pub struct MactelnetCompat {
    /// MAC address of the RouterOS/mactelnetd device, or its identity (resolved via MNDP)
    #[arg(value_name = "MAC|identity")]
    pub target: Option<String>,

    /// List/search for routers nearby (MNDP); -t then limits the search time
    #[arg(short = 'l', conflicts_with = "raw")]
    pub list: bool,

    /// Batch mode: machine-readable CSV output, for use with -l
    #[arg(short = 'B')]
    pub batch: bool,

    #[command(flatten)]
    pub opts: TelnetOpts,

    /// Print version
    #[arg(short = 'v', action = ArgAction::Version)]
    version: (),
}

impl MactelnetCompat {
    pub fn into_command(self) -> Result<Command, String> {
        if self.list {
            return Ok(Command::Discover(DiscoverArgs {
                batch: self.batch,
                timeout: self.opts.timeout,
            }));
        }
        let target = self.target.ok_or("missing <MAC|identity>; see --help")?;
        Ok(Command::Telnet(TelnetArgs {
            target,
            opts: self.opts,
        }))
    }
}

/// `macping`.
#[derive(Parser, Debug)]
#[command(
    name = "macping",
    version,
    disable_version_flag = true,
    about = "MAC-Ping for MikroTik RouterOS devices (mitik invoked as macping)"
)]
pub struct MacpingCompat {
    #[command(flatten)]
    pub args: PingArgs,

    /// Print version
    #[arg(short = 'v', action = ArgAction::Version)]
    version: (),
}

/// `mactelnetd`.
#[derive(Parser, Debug)]
#[command(
    name = "mactelnetd",
    version,
    disable_version_flag = true,
    about = "MAC-Telnet server for users in the user file (mitik invoked as mactelnetd)",
    after_help = SERVER_AFTER_HELP
)]
pub struct MactelnetdCompat {
    #[command(flatten)]
    pub args: ServerArgs,

    /// Print version
    #[arg(short = 'v', action = ArgAction::Version)]
    version: (),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definitions_are_valid() {
        Cli::command().debug_assert();
        MactelnetCompat::command().debug_assert();
        MacpingCompat::command().debug_assert();
        MactelnetdCompat::command().debug_assert();
    }

    #[test]
    fn subcommands() {
        let cli = Cli::parse_from(["mitik", "telnet", "MyRouter", "-u", "admin", "-t", "7"]);
        let Command::Telnet(a) = cli.command else {
            panic!("expected telnet")
        };
        assert_eq!(a.target, "MyRouter");
        assert_eq!(a.opts.user.as_deref(), Some("admin"));
        assert_eq!(a.opts.timeout, Some(7));
        assert_eq!(a.opts.autologin_path, AUTOLOGIN_PATH);

        let cli = Cli::parse_from(["mitik", "ping", "0:1:2:3:4:5", "-f", "-c", "3"]);
        let Command::Ping(a) = cli.command else {
            panic!("expected ping")
        };
        assert_eq!((a.count, a.size, a.fast), (3, ping::DEFAULT_SIZE, true));

        assert!(Cli::try_parse_from(["mitik", "telnet"]).is_err());
        // -U only makes sense together with -n.
        assert!(Cli::try_parse_from(["mitik", "telnet", "x", "-U", "nobody"]).is_err());
        assert!(Cli::try_parse_from(["mitik", "telnet", "x", "-n", "-U", "nobody"]).is_ok());
    }

    #[test]
    fn mactelnet_name_maps_to_commands() {
        let c = MactelnetCompat::parse_from(["mactelnet", "-l", "-B", "-t", "3"])
            .into_command()
            .unwrap();
        let Command::Discover(a) = c else {
            panic!("expected discover")
        };
        assert_eq!((a.batch, a.timeout), (true, Some(3)));

        let c = MactelnetCompat::parse_from(["mactelnet", "MyRouter", "-o", "-A"])
            .into_command()
            .unwrap();
        let Command::Telnet(a) = c else {
            panic!("expected telnet")
        };
        assert_eq!(a.target, "MyRouter");
        assert!(a.opts.force_md5 && a.opts.no_autologin);

        assert!(
            MactelnetCompat::parse_from(["mactelnet"])
                .into_command()
                .is_err()
        );
        assert!(MactelnetCompat::try_parse_from(["mactelnet", "-l", "-n"]).is_err());
    }

    #[test]
    fn server_user_management_flags() {
        let a = MactelnetdCompat::parse_from(["mactelnetd", "-a", "-u", "bob", "-p", "pw"]).args;
        assert!(a.add);
        assert_eq!(a.user.as_deref(), Some("bob"));
        assert_eq!(a.users_file, PathBuf::from(users::DEFAULT_PATH));
        assert!(MactelnetdCompat::try_parse_from(["mactelnetd", "-u", "bob"]).is_err());
        assert!(MactelnetdCompat::try_parse_from(["mactelnetd", "-a", "-d", "bob"]).is_err());
    }
}
