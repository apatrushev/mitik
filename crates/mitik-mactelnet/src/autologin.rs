// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! `~/.mactelnet` autologin profiles, compatible with the C implementation:
//!
//! ```text
//! # comment
//! [default]
//! user=admin
//!
//! [00:0c:42:43:58:a5]
//! user=foo
//! password=bar
//! ```

use std::path::PathBuf;

#[derive(Debug, Default, Clone)]
pub struct Profile {
    pub identifier: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

fn expand_path(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(rest),
        None => PathBuf::from(path),
    }
}

pub fn parse(text: &str, source: &str) -> Vec<Profile> {
    let mut profiles: Vec<Profile> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(id) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            profiles.push(Profile {
                identifier: id.trim().to_string(),
                ..Default::default()
            });
            continue;
        }
        let Some(profile) = profiles.last_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // The C parser ignores spaces inside values as well.
        let value: String = value.chars().filter(|c| *c != ' ').collect();
        match key.trim().to_ascii_lowercase().as_str() {
            "user" => profile.username = Some(value),
            "password" => profile.password = Some(value),
            other => eprintln!(
                "Warning on line {} of {source}: Unknown parameter {other}, ignoring.",
                lineno + 1
            ),
        }
    }
    profiles
}

/// Exact (case-insensitive) match on identifier, otherwise the `default` profile.
pub fn find(profiles: &[Profile], identifier: &str) -> Option<Profile> {
    profiles
        .iter()
        .find(|p| p.identifier.eq_ignore_ascii_case(identifier))
        .or_else(|| {
            profiles
                .iter()
                .find(|p| p.identifier.eq_ignore_ascii_case("default"))
        })
        .cloned()
}

pub fn load(path: &str, identifier: &str) -> Option<Profile> {
    let p = expand_path(path);
    let text = std::fs::read_to_string(&p).ok()?;
    find(&parse(&text, &p.display().to_string()), identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup() {
        let ps = parse(
            "# x\n[default]\nuser=admin\n\n[Router1]\nuser = foo\npassword=bar # c\n",
            "t",
        );
        let r = find(&ps, "router1").unwrap();
        assert_eq!(
            (r.username.as_deref(), r.password.as_deref()),
            (Some("foo"), Some("bar"))
        );
        assert_eq!(
            find(&ps, "other").unwrap().username.as_deref(),
            Some("admin")
        );
    }
}
