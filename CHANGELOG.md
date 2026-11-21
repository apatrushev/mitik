# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, minor releases
(0.x) may change the library APIs.

## [Unreleased]

## [0.1.0]

First release: a Rust port of the tools from
[haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet), as one
`mitik` command and four crates.

### Added

- `mitik telnet`: MAC-Telnet client with EC-SRP and legacy MD5 authentication,
  connection by MAC address or by identity (resolved over MNDP), autologin profiles in
  `~/.mactelnet`, raw Ethernet frames with `-n` and dropping root with `-U`.
- `mitik ping`: MAC-Ping, over raw frames as root and over UDP broadcast otherwise.
- `mitik discover`: lists MikroTik devices on the local network over MNDP, as text or
  CSV.
- `mitik server`: MAC-Telnet server (`mactelnetd`) with a login shell on a PTY,
  MAC-Ping replies, MNDP announcements, utmp/wtmp records and syslog, and user
  management with `-a`, `-d` and `-l`. A lock file keeps a second server from starting.
- Invoked as `mactelnet`, `macping` or `mactelnetd`, `mitik` accepts the options of the
  C tool of that name.
- Library crates: `mitik-net`, `mitik-mndp` and `mitik-mactelnet`.
- Supported systems: Linux, macOS, FreeBSD, NetBSD and OpenBSD; Rust 1.88 or newer.

[Unreleased]: https://github.com/apatrushev/mitik/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/apatrushev/mitik/releases/tag/v0.1.0
