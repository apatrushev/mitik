# mitik-net

Network plumbing for [mitik](https://crates.io/crates/mitik), a set of tools for MikroTik
RouterOS devices.

- `MacAddr`: an Ethernet hardware address. It prints as `aa:bb:cc:dd:ee:ff` and parses
  from text with `str::parse`.
- `iface`: network interfaces with their MAC and IPv4 addresses.
- `udp_socket`: UDP sockets set up for broadcast.
- `raw`: hand-built Ethernet + IPv4 + UDP frames and a raw socket to send them (`AF_PACKET`
  on Linux, BPF on macOS and the BSDs). Sending needs root.
- `is_root`, `drop_privileges`: check for root, and give it up once the raw socket is open.

It runs on Linux, macOS and the BSDs. The API follows the needs of the `mitik` command and
may change between 0.x releases.

## License

GPL-2.0-or-later. Based on [MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet) by
Håkon Nessjøen.
