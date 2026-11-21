# `mitik telnet -n` / `-U`

Status: `-n` and `-U` work on macOS, never run on Linux. Background:
[root-access.md](root-access.md).

## `-n`: session over raw frames

Code: `crates/mitik-mactelnet/src/client.rs`, `find_interface` and `send_raw`.

On 2026-11-21 `-n` first failed on macOS with `Network is down (os error 50)`. The interface
scan stopped at the first interface that could not send, and a Mac has several interfaces
that are down. The scan now skips such interfaces, as the C client does, and tries
interfaces with an IPv4 address first. After that fix a session with `-n -U <user>` was
opened on macOS (BPF) against RouterOS 7.25.1.

Still to test on Linux (`AF_PACKET`):

```sh
sudo mitik telnet <MAC> -n -u admin
```

## `-U <user>`: drop privileges

Code: `mitik_net::drop_privileges`. It calls `initgroups`, `setgid` and `setuid`, then checks
that `setuid(0)` fails.

The raw socket is opened before privileges are dropped. On macOS the BPF devices for every
interface are opened up front (`RawSocket::open`) for this reason, and the session on macOS
kept working after the drop. Check the same on Linux:

```sh
sudo mitik telnet <MAC> -n -U nobody -u admin
```
