# Instructions for agents

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
