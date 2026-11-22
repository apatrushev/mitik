# Tasks for mitik. Run `just` to list them.

# The workspace version, from Cargo.toml.
version := `sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1`

# List the recipes
default:
    @just --list

# Format the code
fmt:
    cargo fmt --all

# Lint with clippy; warnings are errors, as in CI
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run all tests
test:
    cargo test --workspace --locked

# Build the API docs; warnings are errors, as in CI
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Build with the minimum supported Rust version (installs it with rustup if missing)
msrv:
    cargo +1.88.0 check --workspace --all-targets --locked

# Everything CI checks: formatting, lints, tests, docs and the minimum Rust version
ci: && lint test doc msrv
    cargo fmt --all --check

# Install the `mitik` command into ~/.cargo/bin
install:
    cargo install --path crates/mitik --locked

# Also create mactelnet, macping and mactelnetd symlinks next to `mitik`
install-links: install
    #!/usr/bin/env sh
    set -eu
    bin="$(dirname "$(command -v mitik)")"
    for name in mactelnet macping mactelnetd; do
        ln -sf mitik "$bin/$name"
        echo "$bin/$name -> mitik"
    done

# Check that every crate packages and builds as it would on crates.io
package:
    cargo publish --workspace --locked --dry-run

# Tag the current version and push the tag; CI then builds, publishes and releases
release: release-check ci package
    git tag -a "v{{version}}" -m "mitik {{version}}"
    git push origin "v{{version}}"
    @echo "Pushed v{{version}}. Follow the release with: gh run watch"

# Check that the current version can be released
[private]
release-check:
    #!/usr/bin/env sh
    set -eu
    if [ -n "$(git status --porcelain)" ]; then
        echo "error: the working tree has uncommitted changes" >&2
        exit 1
    fi
    if ! grep -q "^## \[{{version}}\]" CHANGELOG.md; then
        echo "error: CHANGELOG.md has no section for {{version}}" >&2
        exit 1
    fi
    if git rev-parse -q --verify "refs/tags/v{{version}}" >/dev/null; then
        echo "error: tag v{{version}} already exists" >&2
        exit 1
    fi
    echo "Releasing v{{version}}"
