# mitik-mndp

MikroTik Neighbor Discovery Protocol (MNDP): find RouterOS devices on the local network,
resolve an identity to a MAC address, and announce a host. Part of
[mitik](https://crates.io/crates/mitik), a set of tools for MikroTik RouterOS devices.

```rust,no_run
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    // Resolve an identity to a MAC address.
    if let Some(mac) = mitik_mndp::query("MyRouter", Duration::from_secs(5))? {
        println!("MyRouter is {mac}");
    }

    // List every device that announces itself within five seconds.
    let discovery = mitik_mndp::Discovery::start()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while let Some((device, from)) = discovery.recv(Some(deadline))? {
        println!("{} {} {}", from.ip(), device.address, device.identity);
    }
    Ok(())
}
```

- `Discovery`, `query`: listen on UDP port 5678 (`PORT`) and ask devices to announce
  themselves.
- `parse`, `Device`: decode an announcement.
- `Announcement`: encode one, as `mactelnetd` does.

It runs on Linux, macOS and the BSDs. The API follows the needs of the `mitik` command and
may change between 0.x releases.

## License

GPL-2.0-or-later. Based on [MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet) by
Håkon Nessjøen.
