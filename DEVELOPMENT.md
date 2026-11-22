# Developing mitik

## Layout

A Cargo workspace with four crates. Each depends only on the ones above it in this list:

| Path | Crate | Contents |
|---|---|---|
| `crates/mitik-net` | `mitik-net` | MAC addresses, interfaces, UDP broadcast sockets, raw Ethernet frames, dropping root |
| `crates/mitik-mndp` | `mitik-mndp` | MNDP: discovery and announcements |
| `crates/mitik-mactelnet` | `mitik-mactelnet` | MAC-Telnet protocol, EC-SRP, client, server, MAC-Ping, user and autologin files |
| `crates/mitik` | `mitik` | The command: argument parsing and terminal output. End-to-end tests in `tests/e2e.rs` |

Shared metadata, versions of dependencies and the versions of the workspace crates are in
the root `Cargo.toml`.

The C original lives at
[haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet). Comments name the
C function a piece of code was ported from, for example `parse_mndp()`.

## Tasks

Common tasks are in the `justfile` ([just](https://github.com/casey/just)); `just` lists them.

```sh
just ci             # everything CI checks: formatting, lints, tests, docs, Rust 1.88
just fmt            # format the code
just install        # install `mitik` into ~/.cargo/bin
just install-links  # the same, plus the mactelnet, macping and mactelnetd symlinks
just package        # check that every crate packages as it would on crates.io
just release        # tag the version from Cargo.toml and push the tag
```

The minimum supported Rust version is 1.88: the code uses `let` chains, and `sha2` needs it.
`just msrv` builds with it.

## Testing

```sh
cargo test
```

- **EC-SRP:** the output matches the reference C implementation (`mtwei.c` with OpenSSL)
  byte for byte, using fixed keys.
- **Client against a mock server:** a full EC-SRP session and a full MD5 session, over real
  UDP broadcast.
- **MAC-Ping against a mock responder:** replies, duplicates, timeouts and exit codes.
- **Our client against our server:** a real PTY running a real shell. The tests cover:
  - EC-SRP with a plain-text password and with a hashed one;
  - MD5;
  - a wrong password;
  - an unknown user;
  - the server's MAC-Ping replies and MNDP announcements;
  - a second server refusing to start.
- **Names of the C tools:** the same sessions, pings and discovery through `mactelnet`,
  `macping` and `mactelnetd` symlinks.

The network tests bind UDP port 20561 and run one at a time. They are skipped when there is
no network interface with IPv4 and a MAC, or when UDP broadcast does not work on it (as on
GitHub's macOS runners).

Code paths that need root are not covered by the tests: raw frames, `-U`, switching to
another user, utmp. They have been checked by hand; what is still unchecked is listed in
`TODO.md`.

## CI

`.github/workflows/ci.yml` runs on pushes to `master` and on pull requests: formatting,
clippy, tests and docs on Linux and macOS, and a build with Rust 1.88. `just ci` runs the
same checks locally.

## Releasing

1. Set the new version in the root `Cargo.toml`, in three kinds of places:
   `[workspace.package] version`, and the `version` of each `mitik-*` entry in
   `[workspace.dependencies]`.
2. In `CHANGELOG.md`, move the entries from `[Unreleased]` into a section for the new
   version, and update the links at the bottom.
3. Commit, push to `master` and wait for CI to pass.
4. Run `just release`. It checks that the working tree is clean, that `CHANGELOG.md` has the
   section and that the tag does not exist yet, runs `just ci` and `just package`, then
   pushes the tag `v<version>`.

The tag starts `.github/workflows/release.yml`:

1. checks that the tag matches the version and that the changelog has its section;
2. builds the binaries: Linux x86_64 and arm64 with glibc and with musl, macOS arm64 and
   x86_64;
3. publishes the crates to crates.io, in dependency order;
4. creates the GitHub release with the archives, `SHA256SUMS` and the changelog section as
   notes.

Publishing needs the repository secret `CARGO_REGISTRY_TOKEN`, a crates.io token with the
`publish-new` and `publish-update` scopes:

```sh
gh secret set CARGO_REGISTRY_TOKEN --repo apatrushev/mitik
```

A version on crates.io cannot be replaced, only yanked. If the workflow fails after the
publish step, fix the release by hand rather than pushing the tag again.

## Conventions

- Everything in the repository is written in English.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/);
  `AGENTS.md` has the types, scopes and examples.
- `TODO.md` holds one line per item, with the details in `docs/todo/`. See `AGENTS.md`.
- New source files start with the GPL header used in the existing ones.
