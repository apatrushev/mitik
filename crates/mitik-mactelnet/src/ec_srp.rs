// mitik - tools and libraries for MikroTik RouterOS devices
// Copyright (C) 2022, Yandex <kmeaw@yandex-team.ru>
// Copyright (C) 2024, Google <kmeaw@google.com>
// Copyright (C) 2026, Anton Patrushev (Rust port)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the LICENSE file for details.

//! EC-SRP (IEEE P1363.2 draft) key exchange as used by MikroTik RouterOS >= 6.43.
//!
//! Port of `mtwei.c` from the reference MAC-Telnet implementation. Curve25519 is
//! handled in its short Weierstrass form; public keys travel on the wire as a
//! 32-byte Montgomery x-coordinate followed by one y-parity byte.

use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

pub const PUBKEY_LEN: usize = 33;
pub const VALIDATOR_LEN: usize = 32;

fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid hex constant")
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// Big-endian, left-padded to 32 bytes (like `BN_bn2binpad(.., 32)`).
fn to32(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_be();
    let mut out = [0u8; 32];
    let take = b.len().min(32);
    out[32 - take..].copy_from_slice(&b[b.len() - take..]);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Point {
    Infinity,
    Affine(BigUint, BigUint),
}

pub struct Curve {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    g: Point,
    order: BigUint,
    /// Weierstrass -> Montgomery x offset.
    w2m: BigUint,
    /// Montgomery -> Weierstrass x offset.
    m2w: BigUint,
}

pub struct PrivateKey(BigUint);

impl Default for Curve {
    fn default() -> Self {
        Self::new()
    }
}

impl Curve {
    pub fn new() -> Self {
        Curve {
            p: hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
            a: hex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144"),
            b: hex("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864"),
            g: Point::Affine(
                hex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a"),
                hex("5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14"),
            ),
            order: hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
            w2m: hex("555555555555555555555555555555555555555555555555555555555552db9c"),
            m2w: hex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451"),
        }
    }

    fn add_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x + y) % &self.p
    }

    fn sub_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        ((x % &self.p) + &self.p - (y % &self.p)) % &self.p
    }

    fn mul_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x * y) % &self.p
    }

    fn inv(&self, x: &BigUint) -> BigUint {
        x.modpow(&(&self.p - 2u32), &self.p)
    }

    fn add(&self, p1: &Point, p2: &Point) -> Point {
        let (x1, y1, x2, y2) = match (p1, p2) {
            (Point::Infinity, q) | (q, Point::Infinity) => return q.clone(),
            (Point::Affine(x1, y1), Point::Affine(x2, y2)) => (x1, y1, x2, y2),
        };
        let lambda = if x1 == x2 {
            if (y1 + y2) % &self.p == BigUint::zero() {
                return Point::Infinity;
            }
            // Doubling: (3x^2 + a) / 2y
            let num = self.add_mod(
                &self.mul_mod(&BigUint::from(3u32), &self.mul_mod(x1, x1)),
                &self.a,
            );
            self.mul_mod(&num, &self.inv(&self.mul_mod(&BigUint::from(2u32), y1)))
        } else {
            self.mul_mod(&self.sub_mod(y2, y1), &self.inv(&self.sub_mod(x2, x1)))
        };
        let x3 = self.sub_mod(&self.sub_mod(&self.mul_mod(&lambda, &lambda), x1), x2);
        let y3 = self.sub_mod(&self.mul_mod(&lambda, &self.sub_mod(x1, &x3)), y1);
        Point::Affine(x3, y3)
    }

    fn mul(&self, k: &BigUint, pt: &Point) -> Point {
        let mut acc = Point::Infinity;
        for i in (0..k.bits()).rev() {
            acc = self.add(&acc, &acc);
            if k.bit(i) {
                acc = self.add(&acc, pt);
            }
        }
        acc
    }

    /// Square root modulo p (p ≡ 5 mod 8, Atkin-style), if it exists.
    fn sqrt(&self, a: &BigUint) -> Option<BigUint> {
        let a = a % &self.p;
        if a.is_zero() {
            return Some(a);
        }
        let exp = (&self.p + 3u32) >> 3;
        let mut r = a.modpow(&exp, &self.p);
        if self.mul_mod(&r, &r) != a {
            let i = BigUint::from(2u32).modpow(&((&self.p - 1u32) >> 2), &self.p);
            r = self.mul_mod(&r, &i);
            if self.mul_mod(&r, &r) != a {
                return None;
            }
        }
        Some(r)
    }

    /// Equivalent of `EC_POINT_set_compressed_coordinates`.
    fn decompress(&self, x: &BigUint, y_odd: bool) -> Option<Point> {
        let x = x % &self.p;
        let rhs = self.add_mod(
            &self.add_mod(
                &self.mul_mod(&self.mul_mod(&x, &x), &x),
                &self.mul_mod(&self.a, &x),
            ),
            &self.b,
        );
        let mut y = self.sqrt(&rhs)?;
        if y.bit(0) != y_odd {
            if y.is_zero() {
                return None;
            }
            y = &self.p - y;
        }
        Some(Point::Affine(x, y))
    }

    fn x_montgomery(&self, pt: &Point) -> [u8; 32] {
        match pt {
            Point::Affine(x, _) => to32(&self.add_mod(x, &self.w2m)),
            Point::Infinity => [0u8; 32],
        }
    }

    fn encode(&self, pt: &Point) -> [u8; PUBKEY_LEN] {
        let mut out = [0u8; PUBKEY_LEN];
        out[..32].copy_from_slice(&self.x_montgomery(pt));
        out[32] = matches!(pt, Point::Affine(_, y) if y.bit(0)) as u8;
        out
    }

    fn decode(&self, key: &[u8]) -> Option<Point> {
        if key.len() < PUBKEY_LEN {
            return None;
        }
        let x = self.add_mod(&BigUint::from_bytes_be(&key[..32]), &self.m2w);
        self.decompress(&x, key[32] != 0)
    }

    /// Mix the password-derived point gamma into `target` (`tangle()` in C).
    /// Returns the validator as a scalar.
    fn tangle(&self, target: &Point, validator: &[u8; 32], negate: bool) -> (Point, BigUint) {
        let v = BigUint::from_bytes_be(validator);
        let vpub = self.mul(&v, &self.g);
        let mut edpx = BigUint::from_bytes_be(&sha256(&[&self.x_montgomery(&vpub)]));
        let gamma = loop {
            let h = BigUint::from_bytes_be(&sha256(&[&to32(&edpx)]));
            let x = self.add_mod(&h, &self.m2w);
            if let Some(pt) = self.decompress(&x, negate) {
                break pt;
            }
            edpx += 1u32;
        };
        (self.add(target, &gamma), v)
    }

    fn keypair_from(
        &self,
        mut priv_bytes: [u8; 32],
        validator: Option<&[u8; 32]>,
    ) -> (PrivateKey, [u8; PUBKEY_LEN]) {
        priv_bytes[0] &= 248;
        priv_bytes[31] &= 127;
        priv_bytes[31] |= 64;
        let k = BigUint::from_bytes_be(&priv_bytes);
        let mut pubpt = self.mul(&k, &self.g);
        if let Some(v) = validator {
            pubpt = self.tangle(&pubpt, v, false).0;
        }
        (PrivateKey(k), self.encode(&pubpt))
    }

    /// Generate a random keypair, optionally entangled with a validator (server side).
    pub fn keygen(
        &self,
        validator: Option<&[u8; 32]>,
    ) -> std::io::Result<(PrivateKey, [u8; PUBKEY_LEN])> {
        Ok(self.keypair_from(crate::util::random_bytes()?, validator))
    }

    /// Client side: compute the 32-byte proof sent as MT_CPTYPE_PASSWORD.
    pub fn client_proof(
        &self,
        privkey: &PrivateKey,
        server_key: &[u8],
        client_key: &[u8],
        validator: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let server_pt = self.decode(server_key)?;
        let (server_pt, v) = self.tangle(&server_pt, validator, true);
        let h = sha256(&[&client_key[..32], &server_key[..32]]);
        let vh = (v * BigUint::from_bytes_be(&h) + &privkey.0) % &self.order;
        let z = self.mul(&vh, &server_pt);
        Some(sha256(&[&h, &self.x_montgomery(&z)]))
    }

    /// Server side: predict the proof the client must send.
    pub fn server_proof(
        &self,
        privkey: &PrivateKey,
        client_key: &[u8],
        server_key: &[u8],
        validator: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let client_pt = self.decode(client_key)?;
        let v = BigUint::from_bytes_be(validator);
        let h = sha256(&[&client_key[..32], &server_key[..32]]);
        let hv = self.mul(&BigUint::from_bytes_be(&h), &self.mul(&v, &self.g));
        let z = self.mul(&privkey.0, &self.add(&client_pt, &hv));
        Some(sha256(&[&h, &self.x_montgomery(&z)]))
    }
}

/// SRP identifier: sha256(salt || sha256(user ":" password)).
pub fn validator(username: &str, password: &str, salt: &[u8]) -> [u8; VALIDATOR_LEN] {
    let inner = sha256(&[username.as_bytes(), b":", password.as_bytes()]);
    sha256(&[salt, &inner])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve_and_order() {
        let c = Curve::new();
        if let Point::Affine(x, y) = &c.g {
            let enc = c.encode(&c.g);
            assert_eq!(c.decode(&enc).unwrap(), Point::Affine(x.clone(), y.clone()));
        }
        assert_eq!(c.mul(&c.order, &c.g), Point::Infinity);
    }

    #[test]
    fn client_and_server_agree() {
        let c = Curve::new();
        let salt = [7u8; 16];
        let v = validator("admin", "secret", &salt);
        let (cpriv, cpub) = c.keypair_from([0x11; 32], None);
        let (spriv, spub) = c.keypair_from([0x22; 32], Some(&v));
        let client = c.client_proof(&cpriv, &spub, &cpub, &v).unwrap();
        let server = c.server_proof(&spriv, &cpub, &spub, &v).unwrap();
        assert_eq!(client, server);

        // Vectors produced by the reference C mtwei.c (OpenSSL) with the same fixed key material.
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            h(&v),
            "126abe3aecefc240728bf00e3171a6374b169beec70ed83f3f6fbec890f19e38"
        );
        assert_eq!(
            h(&cpub),
            "5eb4bca0a2d5b14c1bd8c80c82762dd40dde2c387dee519021b1b36f0489dc1601"
        );
        assert_eq!(
            h(&spub),
            "7c77d0bdcc14624895ede2478a50cfc248c36203568cf078e8a37d206bb628ca01"
        );
        assert_eq!(
            h(&client),
            "b4af61b4fd0e488866b27fb5b89f62224ddb382b691e3b9278e79cf18b390319"
        );

        let wrong = validator("admin", "wrong", &salt);
        let bad = c.client_proof(&cpriv, &spub, &cpub, &wrong).unwrap();
        assert_ne!(bad, server);
    }
}
