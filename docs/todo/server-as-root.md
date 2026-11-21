# Server running as root

Status: works as root on macOS. Not run as root on Linux. Background:
[root-access.md](root-access.md).

On 2026-11-21 `sudo mitik server -f` on macOS accepted two sessions from a local client.
`who` showed the session on `ttys028` with the client MAC as the host, the entry was gone
after logout, and `last` kept both sessions with their logout times. Inside a session `id`
showed the user's uid, primary group and all supplementary groups, and `ps` showed the login
shell (`-zsh`) running as that user, not as root.

## To check with `mitik server` as root

- **Logging in as another user.** `initgroups`/`setgid`/`setuid` in `pre_exec`, and `fchown`
  of the PTY. Works on macOS; check on Linux.
- **utmp/wtmp records** (`who`, `last`). Without root they are silently not written. Works
  on macOS; check on Linux.
- **`-n`.** Replies to the client go out as raw frames; PONG and MNDP go out to
  `ff:ff:ff:ff:ff:ff`.
- **`/etc/nologin`** for non-root users.
- **Interoperability.** Connect to the server from Winbox and from the original C
  `mactelnet`.

## Compare with the C `mactelnetd`

Compare the behaviour with the original C `mactelnetd` from
[haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet). It could not be
run without root either. Known intentional differences are listed in the README section
"Differences from the C version".
