# Instructions for agents

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <summary>

<body>
```

- Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
- The scope is optional. Use the crate or area the change is about: `net`, `mndp`,
  `mactelnet`, `cli`, `server`, `client`, `ping`, `release`.
- The summary is in English, in the imperative mood, lower case, without a final period,
  and fits in about 72 characters with the prefix.
- The body explains why, not what. Wrap it at 72 characters.
- A change that breaks the public API of a library crate or the command line gets `!` after
  the type or scope and a `BREAKING CHANGE:` footer that says what to do instead.
- One logical change per commit.

Examples:

```text
feat(ping): drop root after opening the raw socket with -U
fix(client): skip interfaces that are down when scanning with -n
ci: build glibc Linux binaries for releases
feat(mndp)!: rename MndpInfo to Device

BREAKING CHANGE: use mitik_mndp::Device instead of mitik_mndp::MndpInfo.
```

## TODO

- Each item in `TODO.md` is one line: a checkbox, a short description and a link to the item's
  details file. `TODO.md` holds nothing else.

  ```markdown
  - [ ] Run `mitik ping` as root against real RouterOS — [details](docs/todo/raw-ping.md)
  ```

- Details go in `docs/todo/<name>.md`, where `<name>` is short kebab-case. The details cover
  background, what to check and how, related code and open questions.
- Several closely related items in `TODO.md` may link to the same details file.
- When an item is done, remove its line from `TODO.md`. Delete its details file too, unless
  another item still links to it.
- Write `TODO.md` and `docs/todo/` in English.
