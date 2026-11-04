//! The binary codec of [`CellToCp`] and [`CpToCell`] (I-19, design sections
//! 9.1 and 15).
//!
//! A frame is the version octet [`VERSION`], one tag octet for the
//! variant, then the variant's fields in declaration order:
//!
//! | Field type | Encoding |
//! | --- | --- |
//! | `CellId`, `CaseRef`, `StaffRef` | 16 octets |
//! | `SpkiDigest` | 32 octets |
//! | `ProductVersion` | three big-endian `u16` |
//! | `i64`, `u64` | eight octets, big-endian |
//! | closed enums | one octet, the variant's index |
//! | `Health` | one octet, then the `DegradedReason` octet for `Degraded` |
//! | `PopSig`, `ScramVerifier`, `CertDer` | a big-endian `u16` length, then the bytes |
//! | `CompositeSig` | exactly 3373 octets, no length |
//! | `Vec<(CounterKind, u64)>` | a count octet, then each pair, kinds strictly ascending |
//!
//! Tags of [`CellToCp`] lie in `0x01..=0x04` and tags of [`CpToCell`] in
//! `0x81..=0x85`, so a frame never decodes in the wrong direction.
//!
//! The encoding is a bijection. Every value has exactly one frame, and a
//! frame decodes only if it is the frame of its value. Each decoder checks
//! this a second time by encoding the decoded value again and comparing.
//! A byte left free would be a channel for tenant data (I-19).

use crate::types::{
    BreakGlassScope, CaseRef, CellId, CertDer, Component, CompositeSig, CounterKind,
    DegradedReason, PopSig, ProductVersion, RoleName, ScramVerifier, SpkiDigest, StaffRef,
    TicketKind,
};
use crate::{CellToCp, CpToCell, Health, ProtoError, grammar};

/// The protocol version octet that opens every frame.
pub const VERSION: u8 = 1;

/// The longest frame either direction accepts, in octets.
pub const MAX_FRAME_LEN: usize = 16 * 1024;

/// The most counters one `Metering` message holds: one per kind.
pub const MAX_COUNTERS: usize = 3;

const TAG_HEARTBEAT: u8 = 0x01;
const TAG_ROLE_CREDENTIAL: u8 = 0x02;
const TAG_CERT_RENEWAL: u8 = 0x03;
const TAG_METERING: u8 = 0x04;
const TAG_ACK: u8 = 0x81;
const TAG_CERTIFICATE: u8 = 0x82;
const TAG_OPERATOR_TICKET: u8 = 0x83;
const TAG_BREAK_GLASS: u8 = 0x84;
const TAG_ERASE_SCHEDULED: u8 = 0x85;

// ---------------------------------------------------------------------------
// Closed enums as octets.

fn role_code(r: RoleName) -> u8 {
    match r {
        RoleName::Migrator => 0,
        RoleName::Writer => 1,
        RoleName::App => 2,
        RoleName::Keys => 3,
        RoleName::Auditor => 4,
        RoleName::Vault => 5,
    }
}

fn role_of(c: u8) -> Option<RoleName> {
    RoleName::ALL.get(usize::from(c)).copied()
}

fn component_code(c: Component) -> u8 {
    match c {
        Component::Cell => 0,
        Component::Vault => 1,
        Component::Backup => 2,
    }
}

fn component_of(c: u8) -> Option<Component> {
    match c {
        0 => Some(Component::Cell),
        1 => Some(Component::Vault),
        2 => Some(Component::Backup),
        _ => None,
    }
}

fn counter_code(c: CounterKind) -> u8 {
    match c {
        CounterKind::ActiveAccounts => 0,
        CounterKind::Proposals => 1,
        CounterKind::StoredBytes => 2,
    }
}

fn counter_of(c: u8) -> Option<CounterKind> {
    match c {
        0 => Some(CounterKind::ActiveAccounts),
        1 => Some(CounterKind::Proposals),
        2 => Some(CounterKind::StoredBytes),
        _ => None,
    }
}

fn reason_code(r: DegradedReason) -> u8 {
    match r {
        DegradedReason::Database => 0,
        DegradedReason::Vault => 1,
        DegradedReason::Witness => 2,
        DegradedReason::Custody => 3,
    }
}

fn reason_of(c: u8) -> Option<DegradedReason> {
    match c {
        0 => Some(DegradedReason::Database),
        1 => Some(DegradedReason::Vault),
        2 => Some(DegradedReason::Witness),
        3 => Some(DegradedReason::Custody),
        _ => None,
    }
}

fn ticket_code(k: TicketKind) -> u8 {
    match k {
        TicketKind::Recovery => 0,
        TicketKind::BreakGlass => 1,
    }
}

fn ticket_of(c: u8) -> Option<TicketKind> {
    match c {
        0 => Some(TicketKind::Recovery),
        1 => Some(TicketKind::BreakGlass),
        _ => None,
    }
}

fn scope_code(s: BreakGlassScope) -> u8 {
    match s {
        BreakGlassScope::ReadContent => 0,
        BreakGlassScope::ReadAudit => 1,
    }
}

fn scope_of(c: u8) -> Option<BreakGlassScope> {
    match c {
        0 => Some(BreakGlassScope::ReadContent),
        1 => Some(BreakGlassScope::ReadAudit),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Writing.

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new(tag: u8) -> Writer {
        Writer {
            out: vec![VERSION, tag],
        }
    }

    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    fn raw(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.raw(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.raw(&v.to_be_bytes());
    }

    /// A length-prefixed field.
    fn var(&mut self, b: &[u8], what: &'static str) -> Result<(), ProtoError> {
        let len = u16::try_from(b.len()).map_err(|_| ProtoError::Grammar(what))?;
        self.u16(len);
        self.raw(b);
        Ok(())
    }

    fn version(&mut self, v: &ProductVersion) {
        let (a, b, c) = v.parts();
        self.u16(a);
        self.u16(b);
        self.u16(c);
    }

    fn health(&mut self, h: &Health) {
        match h {
            Health::Ok => self.u8(0),
            Health::Degraded(r) => {
                self.u8(1);
                self.u8(reason_code(*r));
            }
            Health::Maintenance => self.u8(2),
        }
    }

    fn finish(self) -> Result<Vec<u8>, ProtoError> {
        if self.out.len() > MAX_FRAME_LEN {
            return Err(ProtoError::TooLong);
        }
        Ok(self.out)
    }
}

/// Whether the counters hold at most one entry per kind, in ascending
/// kind order, the one spelling of a counter set.
fn counters_canonical(counters: &[(CounterKind, u64)]) -> bool {
    counters.len() <= MAX_COUNTERS
        && counters
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.0 < b.0))
}

/// Encodes a message from a cell.
///
/// # Errors
///
/// [`ProtoError::Grammar`] when a field fails its grammar, such as an
/// `empty()` placeholder, and [`ProtoError::NonCanonical`] for counters
/// out of kind order or with a kind twice.
pub fn encode_cell_to_cp(m: &CellToCp) -> Result<Vec<u8>, ProtoError> {
    match m {
        CellToCp::Heartbeat {
            cell,
            version,
            health,
        } => {
            let mut w = Writer::new(TAG_HEARTBEAT);
            w.raw(&cell.0);
            w.version(version);
            w.health(health);
            w.finish()
        }
        CellToCp::RoleCredential {
            role,
            spki,
            pop,
            scram_verifier,
        } => {
            grammar::pop_signature(pop.as_bytes())?;
            grammar::scram_verifier(scram_verifier.as_bytes())?;
            let mut w = Writer::new(TAG_ROLE_CREDENTIAL);
            w.u8(role_code(*role));
            w.raw(&spki.0);
            w.var(pop.as_bytes(), "PopSig")?;
            w.var(scram_verifier.as_bytes(), "ScramVerifier")?;
            w.finish()
        }
        CellToCp::CertRenewal {
            component,
            spki,
            pop,
        } => {
            grammar::pop_signature(pop.as_bytes())?;
            let mut w = Writer::new(TAG_CERT_RENEWAL);
            w.u8(component_code(*component));
            w.raw(&spki.0);
            w.var(pop.as_bytes(), "PopSig")?;
            w.finish()
        }
        CellToCp::Metering {
            cell,
            period,
            counters,
        } => {
            if !counters_canonical(counters) {
                return Err(ProtoError::NonCanonical);
            }
            let count = u8::try_from(counters.len()).map_err(|_| ProtoError::NonCanonical)?;
            let mut w = Writer::new(TAG_METERING);
            w.raw(&cell.0);
            w.i64(*period);
            w.u8(count);
            for (kind, value) in counters {
                w.u8(counter_code(*kind));
                w.u64(*value);
            }
            w.finish()
        }
    }
}

/// Encodes a message from the control plane.
///
/// # Errors
///
/// [`ProtoError::Grammar`] when a field fails its grammar, such as an
/// `empty()` placeholder.
pub fn encode_cp_to_cell(m: &CpToCell) -> Result<Vec<u8>, ProtoError> {
    match m {
        CpToCell::Ack => Writer::new(TAG_ACK).finish(),
        CpToCell::Certificate(cert) => {
            grammar::certificate(cert.as_bytes())?;
            let mut w = Writer::new(TAG_CERTIFICATE);
            w.var(cert.as_bytes(), "CertDer")?;
            w.finish()
        }
        CpToCell::OperatorTicket {
            case,
            kind,
            issued_at,
            sig,
        } => {
            grammar::composite_signature(sig.as_bytes())?;
            let mut w = Writer::new(TAG_OPERATOR_TICKET);
            w.raw(&case.0);
            w.u8(ticket_code(*kind));
            w.i64(*issued_at);
            w.raw(sig.as_bytes());
            w.finish()
        }
        CpToCell::BreakGlassRequest {
            staff,
            scope,
            until,
        } => {
            let mut w = Writer::new(TAG_BREAK_GLASS);
            w.raw(&staff.0);
            w.u8(scope_code(*scope));
            w.i64(*until);
            w.finish()
        }
        CpToCell::EraseScheduled { at } => {
            let mut w = Writer::new(TAG_ERASE_SCHEDULED);
            w.i64(*at);
            w.finish()
        }
    }
}

// ---------------------------------------------------------------------------
// Reading.

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.rest.len() < n {
            return Err(ProtoError::Truncated);
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        let b = self.take(N)?;
        b.try_into().map_err(|_| ProtoError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ProtoError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn i64(&mut self) -> Result<i64, ProtoError> {
        Ok(i64::from_be_bytes(self.array::<8>()?))
    }

    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn var(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    fn enum_of<T>(&mut self, of: fn(u8) -> Option<T>) -> Result<T, ProtoError> {
        of(self.u8()?).ok_or(ProtoError::UnknownValue)
    }

    fn version(&mut self) -> Result<ProductVersion, ProtoError> {
        let a = self.u16()?;
        let b = self.u16()?;
        let c = self.u16()?;
        Ok(ProductVersion::new(a, b, c))
    }

    fn health(&mut self) -> Result<Health, ProtoError> {
        match self.u8()? {
            0 => Ok(Health::Ok),
            1 => Ok(Health::Degraded(self.enum_of(reason_of)?)),
            2 => Ok(Health::Maintenance),
            _ => Err(ProtoError::UnknownValue),
        }
    }

    fn end(&self) -> Result<(), ProtoError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::TrailingBytes)
        }
    }
}

/// The tag of a frame and a reader over its fields.
fn open(bytes: &[u8]) -> Result<(u8, Reader<'_>), ProtoError> {
    if bytes.is_empty() {
        return Err(ProtoError::Empty);
    }
    if bytes.len() > MAX_FRAME_LEN {
        return Err(ProtoError::TooLong);
    }
    let mut r = Reader { rest: bytes };
    if r.u8()? != VERSION {
        return Err(ProtoError::UnknownVersion);
    }
    let tag = r.u8()?;
    Ok((tag, r))
}

fn fields_cell_to_cp(tag: u8, r: &mut Reader<'_>) -> Result<CellToCp, ProtoError> {
    match tag {
        TAG_HEARTBEAT => Ok(CellToCp::Heartbeat {
            cell: CellId(r.array()?),
            version: r.version()?,
            health: r.health()?,
        }),
        TAG_ROLE_CREDENTIAL => Ok(CellToCp::RoleCredential {
            role: r.enum_of(role_of)?,
            spki: SpkiDigest(r.array()?),
            pop: PopSig::parse(r.var()?)?,
            scram_verifier: ScramVerifier::parse(r.var()?)?,
        }),
        TAG_CERT_RENEWAL => Ok(CellToCp::CertRenewal {
            component: r.enum_of(component_of)?,
            spki: SpkiDigest(r.array()?),
            pop: PopSig::parse(r.var()?)?,
        }),
        TAG_METERING => {
            let cell = CellId(r.array()?);
            let period = r.i64()?;
            let count = usize::from(r.u8()?);
            if count > MAX_COUNTERS {
                return Err(ProtoError::NonCanonical);
            }
            let mut counters = Vec::with_capacity(count);
            for _ in 0..count {
                let kind = r.enum_of(counter_of)?;
                counters.push((kind, r.u64()?));
            }
            if !counters_canonical(&counters) {
                return Err(ProtoError::NonCanonical);
            }
            Ok(CellToCp::Metering {
                cell,
                period,
                counters,
            })
        }
        _ => Err(ProtoError::UnknownTag),
    }
}

fn fields_cp_to_cell(tag: u8, r: &mut Reader<'_>) -> Result<CpToCell, ProtoError> {
    match tag {
        TAG_ACK => Ok(CpToCell::Ack),
        TAG_CERTIFICATE => Ok(CpToCell::Certificate(CertDer::parse(r.var()?)?)),
        TAG_OPERATOR_TICKET => Ok(CpToCell::OperatorTicket {
            case: CaseRef(r.array()?),
            kind: r.enum_of(ticket_of)?,
            issued_at: r.i64()?,
            sig: CompositeSig::parse(r.take(grammar::COMPOSITE_SIG_LEN)?)?,
        }),
        TAG_BREAK_GLASS => Ok(CpToCell::BreakGlassRequest {
            staff: StaffRef(r.array()?),
            scope: r.enum_of(scope_of)?,
            until: r.i64()?,
        }),
        TAG_ERASE_SCHEDULED => Ok(CpToCell::EraseScheduled { at: r.i64()? }),
        _ => Err(ProtoError::UnknownTag),
    }
}

/// Decodes a message from a cell. Fuzzed (`cell_to_cp_decode`).
///
/// # Errors
///
/// A [`ProtoError`] naming why the frame is refused. Any byte outside the
/// encoding of one message refuses the frame.
pub fn decode_cell_to_cp(bytes: &[u8]) -> Result<CellToCp, ProtoError> {
    let (tag, mut r) = open(bytes)?;
    let m = fields_cell_to_cp(tag, &mut r)?;
    r.end()?;
    if encode_cell_to_cp(&m)? != bytes {
        return Err(ProtoError::NonCanonical);
    }
    Ok(m)
}

/// Decodes a message from the control plane. Fuzzed (`cp_to_cell_decode`).
///
/// # Errors
///
/// A [`ProtoError`] naming why the frame is refused. Any byte outside the
/// encoding of one message refuses the frame.
pub fn decode_cp_to_cell(bytes: &[u8]) -> Result<CpToCell, ProtoError> {
    let (tag, mut r) = open(bytes)?;
    let m = fields_cp_to_cell(tag, &mut r)?;
    r.end()?;
    if encode_cp_to_cell(&m)? != bytes {
        return Err(ProtoError::NonCanonical);
    }
    Ok(m)
}
