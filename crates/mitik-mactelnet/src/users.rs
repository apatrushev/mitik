// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! mactelnetd user file (port of `users.c`), compatible with the C format:
//!
//! ```text
//! # plain-text password (works with both EC-SRP and MD5 auth)
//! admin:secret
//! # hashed: user:HEX(sha256 validator):HEX(16-byte salt) (EC-SRP only)
//! alice:4F1C...:9A0B...
//! ```

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::{error, fmt};

use crate::{ec_srp, util};

pub const DEFAULT_PATH: &str = "/etc/mactelnetd.users";
const MAX_USERNAME: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Secret {
    Plain(String),
    Hashed { validator: [u8; 32], salt: [u8; 16] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub secret: Secret,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

enum Line {
    Skip,
    Invalid(&'static str),
    Entry(Credential),
}

fn parse_line(line: &str) -> Line {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.starts_with('#') {
        return Line::Skip;
    }
    let Some((user, rest)) = line.split_once(':') else {
        return Line::Skip;
    };
    if user.is_empty() || rest.is_empty() {
        return Line::Skip;
    }
    let username = user.chars().take(MAX_USERNAME).collect();
    let secret = match rest.split_once(':') {
        None => Secret::Plain(rest.to_string()),
        Some((hash, salt)) => {
            let Some(validator) = hex_decode::<32>(hash) else {
                return Line::Invalid("Invalid password hash");
            };
            let Some(salt) = hex_decode::<16>(salt) else {
                return Line::Invalid("Invalid salt");
            };
            Secret::Hashed { validator, salt }
        }
    };
    Line::Entry(Credential { username, secret })
}

/// A line of the user file that looks like an entry but could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLine {
    /// 1-based line number.
    pub line: usize,
    pub reason: &'static str,
}

impl fmt::Display for InvalidLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on line {} of user file", self.reason, self.line)
    }
}

/// The contents of a user file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserList {
    pub credentials: Vec<Credential>,
    /// Lines that were skipped because they could not be read.
    pub invalid_lines: Vec<InvalidLine>,
}

impl UserList {
    pub fn find(&self, username: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.username == username)
    }
}

pub fn parse(text: &str) -> UserList {
    let mut out = UserList::default();
    for (n, line) in text.lines().enumerate() {
        match parse_line(line) {
            Line::Entry(c) => out.credentials.push(c),
            Line::Invalid(reason) => out.invalid_lines.push(InvalidLine {
                line: n + 1,
                reason,
            }),
            Line::Skip => {}
        }
    }
    out
}

/// Errors reading or writing the user file.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    /// The file holds passwords, so it must belong to root (or to the user running
    /// the server, when that is not root).
    NotOwnedByRoot(PathBuf),
    /// The file must not be writable by group or others.
    WritableByOthers(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Error::NotOwnedByRoot(path) => write!(f, "{} is not owned by root", path.display()),
            Error::WritableByOthers(path) => write!(
                f,
                "{} is writable by others; it should have permissions 0600",
                path.display()
            ),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn check_file(path: &Path) -> Result<(), Error> {
    let md = fs::metadata(path).map_err(io_error(path))?;
    let euid = unsafe { libc::geteuid() };
    if md.uid() != 0 && md.uid() != euid {
        return Err(Error::NotOwnedByRoot(path.to_path_buf()));
    }
    if md.mode() & 0o022 != 0 {
        return Err(Error::WritableByOthers(path.to_path_buf()));
    }
    Ok(())
}

/// Read the user file, after checking its owner and permissions.
pub fn load(path: &Path) -> Result<UserList, Error> {
    check_file(path)?;
    let text = fs::read_to_string(path).map_err(io_error(path))?;
    Ok(parse(&text))
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    Added,
    Updated,
    Deleted,
    NotFound,
}

/// Add/update `username` with a freshly salted hash, or delete it when
/// `password` is None. Other lines (comments included) are kept as they are.
pub fn modify(path: &Path, username: &str, password: Option<&str>) -> Result<Change, Error> {
    let (text, mode, owner) = match fs::metadata(path) {
        Ok(md) => {
            check_file(path)?;
            let text = fs::read_to_string(path).map_err(io_error(path))?;
            (text, md.mode() & 0o7777, Some((md.uid(), md.gid())))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && password.is_some() => {
            (String::new(), 0o600, None)
        }
        Err(e) => return Err(io_error(path)(e)),
    };

    let new_line = match password {
        Some(pw) => {
            let salt: [u8; 16] =
                util::random_bytes().map_err(io_error(Path::new("/dev/urandom")))?;
            let v = ec_srp::validator(username, pw, &salt);
            Some(format!(
                "{username}:{}:{}\n",
                hex_encode(&v),
                hex_encode(&salt)
            ))
        }
        None => None,
    };

    let mut out = String::with_capacity(text.len() + 128);
    let mut found = false;
    for line in text.split_inclusive('\n') {
        let is_target =
            !found && matches!(parse_line(line), Line::Entry(ref c) if c.username == username);
        if is_target {
            found = true;
            if let Some(l) = &new_line {
                out += l;
            }
        } else {
            out += line;
            if !line.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if !found && let Some(l) = &new_line {
        out += l;
    }

    let tmp = path.with_extension("users.tmp");
    let write = || -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error(path)(e)
    })?;

    Ok(match (password.is_some(), found) {
        (true, false) => Change::Added,
        (true, true) => Change::Updated,
        (false, true) => Change::Deleted,
        (false, false) => Change::NotFound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_formats() {
        let v = "AB".repeat(32);
        let s = "cd".repeat(16);
        let users = parse(&format!(
            "# c\nadmin:pa:ss\nplain:se cret\nbad:zz:{s}\nh:{v}:{s}\n"
        ));
        // "pa:ss" has two fields -> treated as hash and rejected, like the C parser.
        assert_eq!(users.credentials.len(), 2);
        assert_eq!(
            users.invalid_lines,
            vec![
                InvalidLine {
                    line: 2,
                    reason: "Invalid password hash"
                },
                InvalidLine {
                    line: 4,
                    reason: "Invalid password hash"
                }
            ]
        );
        assert_eq!(users.credentials[0].secret, Secret::Plain("se cret".into()));
        assert_eq!(
            users.credentials[1].secret,
            Secret::Hashed {
                validator: [0xab; 32],
                salt: [0xcd; 16]
            }
        );
    }

    #[test]
    fn modify_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mtusers-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mactelnetd.users");
        let _ = fs::remove_file(&path);

        assert_eq!(modify(&path, "bob", Some("pw")).unwrap(), Change::Added);
        fs::write(
            &path,
            format!(
                "# keep me\nalice:plain\n{}",
                fs::read_to_string(&path).unwrap()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(modify(&path, "bob", Some("pw2")).unwrap(), Change::Updated);
        let users = load(&path).unwrap();
        let Secret::Hashed { validator, salt } = &users.find("bob").unwrap().secret else {
            panic!("bob must be hashed")
        };
        assert_eq!(*validator, ec_srp::validator("bob", "pw2", salt));
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .starts_with("# keep me\nalice:plain\n")
        );

        assert_eq!(modify(&path, "bob", None).unwrap(), Change::Deleted);
        assert_eq!(modify(&path, "bob", None).unwrap(), Change::NotFound);
        assert_eq!(load(&path).unwrap().credentials.len(), 1);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(load(&path), Err(Error::WritableByOthers(_))));
        fs::remove_dir_all(&dir).unwrap();
    }
}
