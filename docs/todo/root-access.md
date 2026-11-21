# Why many items need root

The port was written in an environment without root: a Linux container running as `uid=1000`
with no `sudo`. The code paths that need root could not be run there.

On 2026-11-21 the raw-frame paths were run by hand as root on macOS against a real MikroTik
device: `mitik ping` and `mitik telnet -n -U <user>` work. The items below list what is still
unverified.

RouterOS answers MAC-Ping only when the Ethernet frame is addressed to the device's real
MAC. It ignores a broadcast frame (`ff:ff:ff:ff:ff:ff`), and a plain UDP send to
`255.255.255.255` produces exactly that. The only way to choose the destination MAC is to
build the whole frame (Ethernet + IPv4 + UDP) by hand and send it through a raw socket:

- Linux: `AF_PACKET` / `SOCK_RAW`;
- macOS/BSD: `/dev/bpfN` with `BIOCSETIF` and `BIOCSHDRCMPLT`.

Both require root. The code is in `crates/mitik-net/src/raw.rs`, a port of `net_send_udp()`
from the C version.

Related items:

- [raw-ping.md](raw-ping.md): MAC-Ping over raw frames
- [client-raw-mode.md](client-raw-mode.md): `mitik telnet -n` / `-U`
- [server-as-root.md](server-as-root.md): server running as root
- [cap-net-raw.md](cap-net-raw.md): `CAP_NET_RAW` instead of full root
- [ping-drop-privileges.md](ping-drop-privileges.md): `-U` for `mitik ping`
