# mitik-mactelnet

MikroTik MAC-Telnet in Rust: a port of
[MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet) and the engine behind the
[mitik](https://crates.io/crates/mitik) command.

- `protocol`: the packet format (headers, control packets, MAC-Ping packets).
- `ec_srp`: EC-SRP authentication, as used by RouterOS 6.43 and later. Its output matches the
  C implementation byte for byte.
- `client`: an interactive MAC-Telnet session on the current terminal.
- `server`: the `mactelnetd` equivalent, with a login shell on a PTY per session.
- `ping`: MAC-Ping.
- `users`: the `mactelnetd.users` file. `autologin`: the `~/.mactelnet` file.

The client, server and ping modules are the programs of the C version turned into
functions: they print to the terminal and read from it. The API may change between 0.x
releases.

It runs on Linux, macOS and the BSDs. MAC-Telnet is not encrypted: use it only on networks
you trust.

## License

GPL-2.0-or-later.

- Copyright (C) 2010, Håkon Nessjøen: MAC-Telnet
- Copyright (C) 2022, Yandex and (C) 2024, Google: EC-SRP (`mtwei.c`, ported as `src/ec_srp.rs`)
- Copyright (C) 2026, Anton Patrushev: the Rust port
