# `-U` for `mitik ping`

Status: idea. Background: [root-access.md](root-access.md).

At the moment `-U` exists only in `mitik telnet` (with `-n`), so `mitik ping` keeps full root
for its whole run. Ping could open the raw socket and then drop privileges the same way the
client does (`mitik_net::drop_privileges`).
