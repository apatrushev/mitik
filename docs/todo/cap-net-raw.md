# `CAP_NET_RAW` instead of full root (Linux)

Status: idea. Background: [root-access.md](root-access.md).

On Linux, `CAP_NET_RAW` may be enough for raw frames:

```sh
sudo setcap cap_net_raw+ep ./target/release/mitik
```

Instead of checking `is_root()`, the code should try to open the raw socket and fall back
if that fails. Affected places: `mitik ping` (`crates/mitik-mactelnet/src/ping.rs`),
`mitik telnet -n` and `mitik server -n`.
