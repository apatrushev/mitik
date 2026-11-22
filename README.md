# mitik

Tools and libraries for MikroTik RouterOS devices, in pure Rust (no OpenSSL).

The `mitik` command currently provides:

| Command | What it does |
|---|---|
| `mitik telnet` | MAC-Telnet client. Logs in to a RouterOS device (or a `mactelnetd` server) by its MAC address or identity, even when the device has no IP configuration. |
| `mitik ping` | MAC-Ping, the equivalent of `macping`. |
| `mitik discover` | Lists MikroTik devices on the local network (MNDP). |
| `mitik server` | MAC-Telnet server, the equivalent of `mactelnetd`: shell access over MAC-Telnet. |

The MAC-Telnet part is a port of
[haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet). Its protocol and
file formats stay compatible with that project, and `mitik` can be invoked under the names
of the C tools (see below).

> **Security:** MAC-Telnet works over unencrypted UDP broadcasts. Use it only on networks you trust.

## Installation

```sh
cargo install mitik
```

It runs on Linux, macOS and the BSDs. Windows is not supported. Building it needs Rust 1.88 or newer.

## Discovering devices

```sh
mitik discover           # print devices as they announce themselves, until Ctrl+C
mitik discover -t 5 -B   # stop after 5 seconds; CSV output
```

## MAC-Telnet client

```sh
mitik telnet 00:0c:42:aa:bb:cc -u admin   # connect by MAC address
mitik telnet MyRouter -u admin -p secret  # connect by identity (resolved via MNDP)
```

- It supports EC-SRP authentication (RouterOS 6.43 and later) and the legacy MD5
  authentication (`-o`).
- `-n` sends raw Ethernet frames addressed to the device's MAC instead of broadcasts. This
  needs root. Use `-U <user>` to drop privileges once the raw socket is open.
- Autologin profiles are read from `~/.mactelnet`. The format is the same as in the C
  version:

  ```ini
  [default]
  user=admin

  [00:0c:42:aa:bb:cc]
  password=secret
  ```

## MAC-Ping

```sh
sudo mitik ping 00:0c:42:aa:bb:cc -c 10   # -s <size>, -f for fast mode
```

RouterOS answers MAC-Ping only when the frame is addressed to its own MAC. Sending such a
frame takes raw sockets, so ping needs root. The raw socket is `AF_PACKET` on Linux and BPF
on macOS and the BSDs. Without root, ping falls back to UDP broadcast and prints a warning.

## MAC-Telnet server

```sh
sudo mitik server -a -u admin   # add or update a user (stored as an EC-SRP hash)
sudo mitik server -l            # list users
sudo mitik server -d admin      # delete a user
sudo mitik server               # run as a daemon; -f to stay in the foreground
```

- Each logged-in user gets a login shell on a PTY. EC-SRP and MD5 (`-o`) authentication
  are both supported.
- The server answers MAC-Ping and announces itself over MNDP.
- It writes login records to utmp/wtmp and logs to syslog.
- `-n` makes it send raw frames instead of broadcasts.
- On `SIGHUP` it re-reads the network interfaces.
- Users are stored in `/etc/mactelnetd.users` by default; `--users-file` sets another path.
  The file format is compatible with the C version. Passwords may be stored in plain text
  or as hashes. MD5 authentication works only with plain-text passwords.
- Run as root, the server lets any listed user log in. Run as a normal user, it lets in
  only the user it runs as.
- Only one server runs at a time. It holds a lock on `/var/run/mitik-server.lock` (as
  root) or on a per-user file in `$XDG_RUNTIME_DIR` or the temporary directory.

## Names of the C tools

`mitik` is a single binary. When it is invoked as `mactelnet`, `macping` or `mactelnetd`,
it accepts the options of the C tool of that name. A symlink is enough:

```sh
ln -s "$(command -v mitik)" /usr/local/bin/mactelnet
```

| Invoked as | Same as |
|---|---|
| `mactelnet <MAC\|identity> [options]` | `mitik telnet <MAC\|identity> [options]` |
| `mactelnet -l [-B] [-t <timeout>]` | `mitik discover [-B] [-t <timeout>]` |
| `macping <MAC\|identity> [options]` | `mitik ping <MAC\|identity> [options]` |
| `mactelnetd [options]` | `mitik server [options]` |

## Crates

| Crate | Contents |
|---|---|
| `mitik` | The `mitik` command. |
| `mitik-mactelnet` | MAC-Telnet protocol, EC-SRP authentication, client, server and MAC-Ping. |
| `mitik-mndp` | MNDP: discovering devices and announcing a host. |
| `mitik-net` | Network plumbing: interfaces, raw Ethernet frames, UDP broadcast, MAC addresses. |

The sources of all four are in `crates/`. The library crates were split out of the command,
and their API may still change between 0.x releases.

## Differences from the C version

- One binary with subcommands replaces the three C programs.
- The server retransmits packets that were not acknowledged. The C server sends each
  packet only once.
- The client treats a packet as delivered only when an ACK carries that packet's counter.
  The C client accepts any ACK.
- The server ignores repeated copies of the first packet of a session.
- The server can run without root, with the limit described above.
- A second server refuses to start. The C server does not check for one.
- The user file can belong to the user running the server. `-a` creates it with mode 0600
  if it does not exist.
- Not implemented:
  - `/etc/ethers` lookup;
  - translations (gettext);
  - man pages;
  - noticing interface changes automatically (netlink). The server re-reads interfaces
    only on `SIGHUP`.

## Testing

```sh
cargo test
```

- **EC-SRP:** the output matches the reference C implementation (`mtwei.c` with OpenSSL)
  byte for byte, using fixed keys.
- **Client against a mock server:** a full EC-SRP session and a full MD5 session, over real
  UDP broadcast.
- **MAC-Ping against a mock responder:** replies, duplicates, timeouts and exit codes.
- **Our client against our server:** a real PTY running a real shell. The tests cover:
  - EC-SRP with a plain-text password and with a hashed one;
  - MD5;
  - a wrong password;
  - an unknown user;
  - the server's MAC-Ping replies and MNDP announcements.
- **Names of the C tools:** the same sessions, pings and discovery through `mactelnet`,
  `macping` and `mactelnetd` symlinks.

Tests that need a network interface are skipped when there is none, or when UDP broadcast
does not work on it (as on GitHub's macOS runners). Code paths that need
root are not covered by the tests: raw frames, `-U`, switching to another user, utmp. See
`TODO.md`.

## License

GPL-2.0-or-later. The full text is in the `LICENSE` file.

- Copyright (C) 2010, Håkon Nessjøen: MAC-Telnet
- Copyright (C) 2022, Yandex and (C) 2024, Google: EC-SRP (`mtwei.c`, ported as
  `crates/mitik-mactelnet/src/ec_srp.rs`)
- Copyright (C) 2026, Anton Patrushev: the Rust port

## Trademarks

mitik is an independent project. It is not affiliated with or endorsed by MikroTik.
MikroTik and RouterOS are trademarks of SIA Mikrotīkls.
