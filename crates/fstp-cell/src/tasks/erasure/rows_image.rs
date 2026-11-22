//! The App keystore snapshot image `"FAK1"`: every row of the ten
//! `keystore` tables, as `fstp_pgstore::KeystoreRows` holds them (ADR-012
//! record of lane L27, row "App plaintext").
//!
//! Every key in it is sealed or wrapped, as in the tables: the seal keys
//! under their roots, the chain state, group secrets and signing keys
//! under a seal key, the data keys to their group keys and the texts under
//! their data keys. So an image opens only through custody, and only while
//! a root of its rows lives (I-80, I-81).
//!
//! ```text
//! image   = "FAK1" | version u8 (1 or 2) | cell 16 | has_chain u8 | chain?
//!           | n u32 | root* | n u32 | group* | n u32 | key* | n u32 | text*
//!           | n u32 | signer* | n u32 | digest* | n u32 | login* | n u32 | requested*
//!           | (n u32 | display*, version 2 only)
//! chain   = epoch u64 | len u32 | state | opt lookup | opt login group | opt startup unwrap
//! opt     = 0 | 1 id 16
//! root    = epoch u64 | backend u8 | status u8 (1 live, 2 pending, 3 destroyed)
//!           | receipt digest 32 when destroyed | len u16 | handle | len u16 | wrapped
//! group   = group 16 | generation u32 | purpose u8 | epoch u64 | len u32 | public
//!           | len u32 | sealed
//! key     = id 16 | group 16 | generation u32 | len u16 | sealed
//! text    = id 16 | dek 16 | generation u32 | len u32 | envelope
//! signer  = purpose u8 | generation u32 | created i64 | len u32 | public
//!           | has u8 | (epoch u64 | len u32 | sealed)?
//! digest  = digest 32 | account 16
//! login   = account 16 | text 16
//! requested = text 16
//! display = account 16 | text 16 | fingerprint 32
//! ```
//!
//! Integers are big-endian. Rows are strictly increasing by their table's
//! key, so the decoder admits one spelling only. It bounds every length
//! and refuses trailing bytes. Version 2 adds the display name index of
//! `keystore.display_name` (SA-11 amendment, ADR-004 section "Written by
//! lane L26"). The encoder writes version 2, and the decoder reads a
//! version 1 image as one with no display name.
//! Fuzzed (`app_keystore_image_decode`). A
//! refusal names its rule and never quotes the input (R-NF-02).

use fstp_pgstore::{
    ChainRow, DataKeyRow, DisplayNameRow, GroupKeyRow, KeystoreRows, KeystoreTextRow,
    LoginDigestRow, LoginTextRow, RootRow, RootStatus, SignerRow,
};

/// The magic of an App keystore image.
pub const MAGIC: [u8; 4] = *b"FAK1";
/// The version the encoder writes.
pub const VERSION: u8 = 2;
/// The first version, which held no display name index.
pub const VERSION_1: u8 = 1;
/// The longest handle, wrapped seal key or sealed data key.
pub const MAX_SHORT: usize = 4096;
/// The longest public key, sealed secret or sealed chain state.
pub const MAX_FIELD: usize = 64 * 1024 * 1024;

/// Why an image did not decode or encode. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageError(pub &'static str);

fn bad(rule: &'static str) -> ImageError {
    ImageError(rule)
}

fn count(out: &mut Vec<u8>, n: usize) -> Result<(), ImageError> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| bad("count"))?.to_be_bytes());
    Ok(())
}

fn put16(out: &mut Vec<u8>, f: &[u8]) -> Result<(), ImageError> {
    if f.len() > MAX_SHORT {
        return Err(bad("length"));
    }
    out.extend_from_slice(
        &u16::try_from(f.len())
            .map_err(|_| bad("length"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(f);
    Ok(())
}

fn put32(out: &mut Vec<u8>, f: &[u8]) -> Result<(), ImageError> {
    if f.len() > MAX_FIELD {
        return Err(bad("length"));
    }
    out.extend_from_slice(
        &u32::try_from(f.len())
            .map_err(|_| bad("length"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(f);
    Ok(())
}

fn opt(out: &mut Vec<u8>, v: Option<[u8; 16]>) {
    match v {
        None => out.push(0),
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
    }
}

fn ordered<K: Ord>(keys: impl Iterator<Item = K>, rule: &'static str) -> Result<(), ImageError> {
    let mut last: Option<K> = None;
    for k in keys {
        if last.as_ref().is_some_and(|l| *l >= k) {
            return Err(bad(rule));
        }
        last = Some(k);
    }
    Ok(())
}

/// Encodes the image of `rows` of `cell`.
///
/// # Errors
///
/// [`ImageError`] for rows out of order, a field too long or a code out
/// of range.
pub fn encode(cell: [u8; 16], rows: &KeystoreRows) -> Result<Vec<u8>, ImageError> {
    ordered(rows.roots.iter().map(|r| r.epoch), "root order")?;
    ordered(
        rows.groups.iter().map(|g| (g.group, g.generation)),
        "group order",
    )?;
    ordered(rows.keys.iter().map(|k| k.id), "key order")?;
    ordered(rows.texts.iter().map(|t| t.id), "text order")?;
    ordered(
        rows.signers.iter().map(|s| (s.purpose, s.generation)),
        "signer order",
    )?;
    ordered(rows.digests.iter().map(|d| d.digest), "digest order")?;
    ordered(rows.logins.iter().map(|l| l.account), "login order")?;
    ordered(rows.requested.iter().copied(), "request order")?;
    ordered(rows.displays.iter().map(|d| d.account), "display order")?;
    let mut out = MAGIC.to_vec();
    out.push(VERSION);
    out.extend_from_slice(&cell);
    match &rows.chain {
        None => out.push(0),
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c.epoch.to_be_bytes());
            put32(&mut out, &c.state)?;
            opt(&mut out, c.lookup_group);
            opt(&mut out, c.login_group);
            opt(&mut out, c.startup_unwrap);
        }
    }
    count(&mut out, rows.roots.len())?;
    for r in &rows.roots {
        out.extend_from_slice(&r.epoch.to_be_bytes());
        let backend = u8::try_from(r.backend)
            .ok()
            .filter(|b| (1..=3).contains(b))
            .ok_or(bad("backend"))?;
        out.push(backend);
        match r.status {
            RootStatus::Live => out.push(1),
            RootStatus::Pending => out.push(2),
            RootStatus::Destroyed(d) => {
                out.push(3);
                out.extend_from_slice(&d);
            }
        }
        put16(&mut out, &r.handle)?;
        put16(&mut out, &r.wrapped)?;
    }
    count(&mut out, rows.groups.len())?;
    for g in &rows.groups {
        out.extend_from_slice(&g.group);
        out.extend_from_slice(&g.generation.to_be_bytes());
        out.push(g.purpose);
        out.extend_from_slice(&g.epoch.to_be_bytes());
        put32(&mut out, &g.public_key)?;
        put32(&mut out, &g.sealed_secret)?;
    }
    count(&mut out, rows.keys.len())?;
    for k in &rows.keys {
        out.extend_from_slice(&k.id);
        out.extend_from_slice(&k.group);
        out.extend_from_slice(&k.generation.to_be_bytes());
        put16(&mut out, &k.sealed)?;
    }
    count(&mut out, rows.texts.len())?;
    for t in &rows.texts {
        out.extend_from_slice(&t.id);
        out.extend_from_slice(&t.dek);
        out.extend_from_slice(&t.generation.to_be_bytes());
        put32(&mut out, &t.envelope)?;
    }
    count(&mut out, rows.signers.len())?;
    for s in &rows.signers {
        out.push(s.purpose);
        out.extend_from_slice(&s.generation.to_be_bytes());
        out.extend_from_slice(&s.created_at.to_be_bytes());
        put32(&mut out, &s.public_key)?;
        match &s.sealed {
            None => out.push(0),
            Some((epoch, sealed)) => {
                out.push(1);
                out.extend_from_slice(&epoch.to_be_bytes());
                put32(&mut out, sealed)?;
            }
        }
    }
    count(&mut out, rows.digests.len())?;
    for d in &rows.digests {
        out.extend_from_slice(&d.digest);
        out.extend_from_slice(&d.account);
    }
    count(&mut out, rows.logins.len())?;
    for l in &rows.logins {
        out.extend_from_slice(&l.account);
        out.extend_from_slice(&l.text);
    }
    count(&mut out, rows.requested.len())?;
    for r in &rows.requested {
        out.extend_from_slice(r);
    }
    count(&mut out, rows.displays.len())?;
    for d in &rows.displays {
        out.extend_from_slice(&d.account);
        out.extend_from_slice(&d.text);
        out.extend_from_slice(&d.fingerprint);
    }
    Ok(out)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ImageError> {
        let (h, t) = self.rest.split_at_checked(n).ok_or(bad("truncated"))?;
        self.rest = t;
        Ok(h)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N], ImageError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ImageError> {
        Ok(self.arr::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, ImageError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }

    fn u64(&mut self) -> Result<u64, ImageError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }

    fn count(&mut self) -> Result<u32, ImageError> {
        self.u32()
    }

    fn f16(&mut self) -> Result<Vec<u8>, ImageError> {
        let n = usize::from(u16::from_be_bytes(self.arr()?));
        if n > MAX_SHORT {
            return Err(bad("length"));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn f32(&mut self) -> Result<Vec<u8>, ImageError> {
        let n = usize::try_from(self.u32()?).map_err(|_| bad("length"))?;
        if n > MAX_FIELD {
            return Err(bad("length"));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn flag(&mut self) -> Result<bool, ImageError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad("flag")),
        }
    }

    fn opt(&mut self) -> Result<Option<[u8; 16]>, ImageError> {
        Ok(if self.flag()? {
            Some(self.arr()?)
        } else {
            None
        })
    }
}

/// Decodes an image into its cell and rows. Fuzzed
/// (`app_keystore_image_decode`).
///
/// # Errors
///
/// [`ImageError`] naming the rule broken.
pub fn decode(bytes: &[u8]) -> Result<([u8; 16], KeystoreRows), ImageError> {
    let mut r = Reader { rest: bytes };
    if r.arr::<4>()? != MAGIC {
        return Err(bad("magic"));
    }
    let version = r.u8()?;
    if version != VERSION && version != VERSION_1 {
        return Err(bad("version"));
    }
    let cell = r.arr::<16>()?;
    let mut rows = KeystoreRows::default();
    if r.flag()? {
        rows.chain = Some(ChainRow {
            epoch: r.u64()?,
            state: r.f32()?,
            lookup_group: r.opt()?,
            login_group: r.opt()?,
            startup_unwrap: r.opt()?,
        });
    }
    for _ in 0..r.count()? {
        let epoch = r.u64()?;
        let backend = r.u8()?;
        if !(1..=3).contains(&backend) {
            return Err(bad("backend"));
        }
        let status = match r.u8()? {
            1 => RootStatus::Live,
            2 => RootStatus::Pending,
            3 => RootStatus::Destroyed(r.arr()?),
            _ => return Err(bad("root status")),
        };
        rows.roots.push(RootRow {
            epoch,
            backend: i16::from(backend),
            handle: r.f16()?,
            wrapped: r.f16()?,
            status,
        });
    }
    for _ in 0..r.count()? {
        rows.groups.push(GroupKeyRow {
            group: r.arr()?,
            generation: r.u32()?,
            purpose: r.u8()?,
            epoch: r.u64()?,
            public_key: r.f32()?,
            sealed_secret: r.f32()?,
        });
    }
    for _ in 0..r.count()? {
        rows.keys.push(DataKeyRow {
            id: r.arr()?,
            group: r.arr()?,
            generation: r.u32()?,
            sealed: r.f16()?,
        });
    }
    for _ in 0..r.count()? {
        rows.texts.push(KeystoreTextRow {
            id: r.arr()?,
            dek: r.arr()?,
            generation: r.u32()?,
            envelope: r.f32()?,
        });
    }
    for _ in 0..r.count()? {
        let purpose = r.u8()?;
        let generation = r.u32()?;
        let created_at = i64::from_be_bytes(r.arr()?);
        let public_key = r.f32()?;
        let sealed = if r.flag()? {
            Some((r.u64()?, r.f32()?))
        } else {
            None
        };
        rows.signers.push(SignerRow {
            purpose,
            generation,
            public_key,
            created_at,
            sealed,
        });
    }
    for _ in 0..r.count()? {
        rows.digests.push(LoginDigestRow {
            digest: r.arr()?,
            account: r.arr()?,
        });
    }
    for _ in 0..r.count()? {
        rows.logins.push(LoginTextRow {
            account: r.arr()?,
            text: r.arr()?,
        });
    }
    for _ in 0..r.count()? {
        rows.requested.push(r.arr()?);
    }
    if version == VERSION {
        for _ in 0..r.count()? {
            rows.displays.push(DisplayNameRow {
                account: r.arr()?,
                text: r.arr()?,
                fingerprint: r.arr()?,
            });
        }
    }
    if !r.rest.is_empty() {
        return Err(bad("trailing bytes"));
    }
    ordered(rows.roots.iter().map(|x| x.epoch), "root order")?;
    ordered(
        rows.groups.iter().map(|g| (g.group, g.generation)),
        "group order",
    )?;
    ordered(rows.keys.iter().map(|k| k.id), "key order")?;
    ordered(rows.texts.iter().map(|t| t.id), "text order")?;
    ordered(
        rows.signers.iter().map(|s| (s.purpose, s.generation)),
        "signer order",
    )?;
    ordered(rows.digests.iter().map(|d| d.digest), "digest order")?;
    ordered(rows.logins.iter().map(|l| l.account), "login order")?;
    ordered(rows.requested.iter().copied(), "request order")?;
    ordered(rows.displays.iter().map(|d| d.account), "display order")?;
    Ok((cell, rows))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    fn rows() -> KeystoreRows {
        KeystoreRows {
            chain: Some(ChainRow {
                epoch: 2,
                state: vec![1; 40],
                lookup_group: Some([2; 16]),
                login_group: None,
                startup_unwrap: Some([3; 16]),
            }),
            roots: vec![
                RootRow {
                    epoch: 1,
                    backend: 2,
                    handle: vec![4; 9],
                    wrapped: vec![5; 60],
                    status: RootStatus::Destroyed([6; 32]),
                },
                RootRow {
                    epoch: 2,
                    backend: 2,
                    handle: vec![7; 9],
                    wrapped: vec![8; 60],
                    status: RootStatus::Live,
                },
                RootRow {
                    epoch: 3,
                    backend: 2,
                    handle: vec![9; 9],
                    wrapped: Vec::new(),
                    status: RootStatus::Pending,
                },
            ],
            groups: vec![GroupKeyRow {
                group: [10; 16],
                generation: 1,
                purpose: 2,
                public_key: vec![11; 1216],
                sealed_secret: vec![12; 2460],
                epoch: 2,
            }],
            keys: vec![DataKeyRow {
                id: [13; 16],
                group: [10; 16],
                generation: 1,
                sealed: vec![14; 1210],
            }],
            texts: vec![KeystoreTextRow {
                id: [15; 16],
                dek: [13; 16],
                generation: 1,
                envelope: vec![16; 80],
            }],
            signers: vec![
                SignerRow {
                    purpose: 14,
                    generation: 1,
                    public_key: vec![17; 40],
                    created_at: 0,
                    sealed: None,
                },
                SignerRow {
                    purpose: 14,
                    generation: 2,
                    public_key: vec![18; 40],
                    created_at: 99,
                    sealed: Some((2, vec![19; 100])),
                },
            ],
            digests: vec![LoginDigestRow {
                digest: [20; 32],
                account: [21; 16],
            }],
            logins: vec![LoginTextRow {
                account: [21; 16],
                text: [15; 16],
            }],
            requested: vec![[22; 16]],
            displays: vec![DisplayNameRow {
                account: [23; 16],
                text: [24; 16],
                fingerprint: [25; 32],
            }],
        }
    }

    /// ADR-012 record of lane L27, row "App plaintext": the App keystore
    /// image round trips every table, re-encodes byte for byte, and
    /// refuses a cut, a trailing byte, rows out of order and a bad code.
    #[test]
    fn adr012_app_keystore_image_round_trips_in_one_spelling() {
        let cell = [0x42; 16];
        let r = rows();
        let bytes = encode(cell, &r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), (cell, r.clone()));
        assert_eq!(
            encode(cell, &KeystoreRows::default()).map(|b| decode(&b).unwrap().1),
            Ok(KeystoreRows::default())
        );
        for cut in [0, 4, 21, bytes.len() - 1] {
            assert!(decode(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode(&long).is_err());
        let mut swapped = r.clone();
        swapped.roots.swap(0, 1);
        assert!(encode(cell, &swapped).is_err());
        let mut bad_flag = bytes;
        bad_flag[21] = 2;
        assert!(decode(&bad_flag).is_err());
    }

    /// SA-11 amendment, ADR-004 section "Written by lane L26", ADR-012
    /// record of lane L27: a version 2 image carries the display name
    /// index, so a restore from a snapshot keeps every name and its
    /// uniqueness. A version 1 image reads as one with no display name.
    #[test]
    fn sa11_app_keystore_image_carries_the_display_name_index() {
        let cell = [0x42; 16];
        let r = rows();
        let bytes = encode(cell, &r).unwrap();
        assert_eq!(bytes[4], VERSION);
        assert_eq!(decode(&bytes).unwrap().1.displays, r.displays);
        // The version 1 spelling: no display section.
        let mut old = r.clone();
        old.displays.clear();
        let mut v1 = encode(cell, &old).unwrap();
        v1[4] = VERSION_1;
        v1.truncate(v1.len() - 4);
        assert_eq!(decode(&v1).unwrap(), (cell, old));
        let mut v3 = bytes;
        v3[4] = 3;
        assert!(decode(&v3).is_err());
    }
}
