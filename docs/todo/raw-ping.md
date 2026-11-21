# MAC-Ping over raw frames

Status: works on macOS, never run on Linux. Background: [root-access.md](root-access.md).

On 2026-11-21 `sudo mitik ping <router MAC>` was run on macOS (BPF) against a real MikroTik
device. The pings go out and the replies arrive.

## To check

- **Linux (`AF_PACKET`) as root against a real MikroTik.** This path has never run.

  ```sh
  sudo ./target/release/mitik ping <router MAC> -c 5
  ```

- **Without root.** Check whether RouterOS answers any broadcast pings at all. The warning in
  `crates/mitik-mactelnet/src/ping.rs` says it does not, based on a comment in `macping.c`.

## Tests

The e2e test `ping_replies_and_timeouts` (`crates/mitik/tests/e2e.rs`) is skipped when run as
root, because the mock responder cannot see raw frames. Automated tests cover only frame
building and checksums (`raw::tests` in `mitik-net`).
