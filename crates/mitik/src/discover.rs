// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! `mitik discover` (`mactelnet -l`): print the devices that announce themselves over MNDP.

use std::io;
use std::time::{Duration, Instant};

use mitik_mndp::Discovery;

/// Print discovered devices until the timeout (0 = forever).
pub fn run(timeout_secs: u64, batch: bool) -> io::Result<()> {
    let discovery = Discovery::start()?;
    if !discovery.request_sent() {
        eprintln!("Unable to send broadcast packet: operating in receive only mode.");
    }
    eprintln!("Searching for MikroTik routers... Abort with CTRL+C.");
    if batch {
        println!("MAC-Address,Identity,Platform,Version,Hardware,Uptime,Softid,Ifname,IP");
    } else {
        println!(
            "\n\x1b[1m{:<15} {:<17} Identity (platform version hardware) uptime\x1b[m",
            "IP", "MAC-Address"
        );
    }
    let deadline = (timeout_secs > 0).then(|| Instant::now() + Duration::from_secs(timeout_secs));

    while let Some((p, from)) = discovery.recv(deadline)? {
        let ip = from.ip();
        let mac = p.address.to_string();
        if batch {
            println!(
                "'{mac}','{}','{}','{}','{}','{}','{}','{}','{ip}'",
                p.identity, p.platform, p.version, p.hardware, p.uptime, p.softid, p.ifname
            );
        } else {
            let mut line = format!("{:<15} {mac:<17} {}", ip.to_string(), p.identity);
            if !p.platform.is_empty() {
                line += &format!(" ({} {} {})", p.platform, p.version, p.hardware);
            }
            if p.uptime > 0 {
                line += &format!(
                    "  up {} days {} hours",
                    p.uptime / 86400,
                    p.uptime % 86400 / 3600
                );
            }
            if !p.softid.is_empty() {
                line += &format!("  {}", p.softid);
            }
            if !p.ifname.is_empty() {
                line += &format!(" {}", p.ifname);
            }
            println!("{line}");
        }
    }
    Ok(())
}
