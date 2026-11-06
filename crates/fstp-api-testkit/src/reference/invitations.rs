//! The reference of journey J2: programme role invitations, written from
//! the spec text before the production code (lane inv).
//!
//! Sources: M4 design section 2.2 J1 and J2, `roles-and-sod.md` (SoD-09
//! and "Confidentiality on binding"), `mcp-server.md` (P-75, P-77),
//! ADR-007 (`SecretDigest`) and I-86. It shares only id and role types
//! with production code.
//!
//! Readings of the test author, each interim, pending Daniel:
//!
//! - **States.** An invitation reads `invited` until an account accepts
//!   its terms, `accepted` until the vault verifies that account,
//!   `verified` until a binding of that account in the invited role is
//!   held, and `granted` from then on (`creator_ops.rs` module
//!   documentation, `web/src/people/model.ts`).
//! - **Terms.** Every Drafting and Judging binding includes the
//!   acceptance of confidentiality terms ("Confidentiality on binding").
//!   J2 reads it for every grant: `roles.grant` is composed only when a
//!   `TermsAccepted` record exists for the account and the role. The
//!   tests check it for Drafting and Judging roles only. Whether an
//!   Operations grant needs it is open: J2 names no group, and the spec
//!   text names Drafting and Judging.
//! - **SoD-09.** A Drafting or Judging grant also needs `IsVerified` for
//!   the account. Operations roles need no verified identity (NOTE 5).
//! - **Bound placeholders.** Only the terms of a Judging role state the
//!   programme's P-75 and P-77 choices (J2, `mcp-server.md`).
//! - **The link token.** The token is a random secret. The ledger holds
//!   only its digest (ADR-007 `SecretDigest`), and no store or log holds
//!   it in any common spelling.
//! - **Uniform refusal.** An unknown token, the token of a withdrawn
//!   invitation and the token of an invitation another account accepted
//!   get one refusal, equal in code, rule and detail, so no answer tells
//!   one case from another.
//! - **One acceptance.** An invitation is accepted once, by one account.

use fstp_domain::roles::{Group, Role};

/// The state of an invitation on the people pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefState {
    /// No account accepted the terms yet.
    Invited,
    /// An account accepted the terms. The vault does not verify it yet.
    Accepted,
    /// The accepting account is verified. No binding is held yet.
    Verified,
    /// A binding of the accepting account in the invited role is held.
    Granted,
}

impl RefState {
    /// The wire spelling (`web/src/people/model.ts`).
    pub const fn as_str(self) -> &'static str {
        match self {
            RefState::Invited => "invited",
            RefState::Accepted => "accepted",
            RefState::Verified => "verified",
            RefState::Granted => "granted",
        }
    }
}

/// The listed state of an invitation from what holds now.
pub const fn listed_state(accepted: bool, verified: bool, granted: bool) -> RefState {
    match (accepted, verified, granted) {
        (false, _, _) => RefState::Invited,
        (true, _, true) => RefState::Granted,
        (true, true, false) => RefState::Verified,
        (true, false, false) => RefState::Accepted,
    }
}

/// What the reference says of a role grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantVerdict {
    /// The engine composes the grant.
    Composed,
    /// No `TermsAccepted` record exists for the account and the role (J2).
    NoTermsAccepted,
    /// The account is not verified, and the role is Drafting or Judging
    /// (SoD-09).
    Sod09,
}

/// Whether SoD-09 asks for a verified identity at a binding of `role`.
pub fn needs_verified_identity(role: Role) -> bool {
    matches!(role.group(), Group::Drafting | Group::Judging)
}

/// Whether the terms of `role` state the programme's P-75 and P-77.
pub fn terms_bind_p75_p77(role: Role) -> bool {
    matches!(role.group(), Group::Judging)
}

/// The verdict on a grant of `role` to an account for which a
/// `TermsAccepted` record of that role exists or not, and which the vault
/// verifies or not. Only the J2 and SoD-09 rules are modelled. Every other
/// SoD rule applies as before.
pub fn grant_verdict(role: Role, terms_accepted: bool, verified: bool) -> GrantVerdict {
    if !terms_accepted {
        GrantVerdict::NoTermsAccepted
    } else if needs_verified_identity(role) && !verified {
        GrantVerdict::Sod09
    } else {
        GrantVerdict::Composed
    }
}

/// The members of the invitation landing (`people.get_invitation`), in
/// key order. It names no account, no inviter, no contact address and no
/// programme (`model.rs`, `sod09_invitation_landing_fits_and_names_no_account`).
pub const LANDING_MEMBERS: [&str; 5] = ["p75", "p77", "role", "state", "terms_version"];

/// The spellings of a secret that a store or a log might hold: the raw
/// bytes, lowercase and uppercase hexadecimal, and base64 with the
/// standard and the URL-safe alphabet, padded and not.
pub fn secret_spellings(secret: &[u8]) -> Vec<Vec<u8>> {
    let lower = hex(secret);
    let upper = lower.to_ascii_uppercase();
    let std = base64(secret, STD);
    let url = base64(secret, URL);
    let mut out = vec![secret.to_vec(), lower.into_bytes(), upper.into_bytes()];
    for b in [std, url] {
        out.push(b.trim_end_matches('=').as_bytes().to_vec());
        out.push(b.into_bytes());
    }
    out
}

/// Whether `haystack` holds `needle` anywhere. An empty needle is never
/// held.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The bytes of a token in its link spelling: 64 lowercase hexadecimal
/// digits. `None` for any other spelling.
pub fn token_bytes(link: &str) -> Option<Vec<u8>> {
    if link.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    link.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [h, l] => Some(digit(*h)?.wrapping_mul(16).wrapping_add(digit(*l)?)),
            _ => None,
        })
        .collect()
}

/// Whether `s` is a link token as the route takes it: 32 to 128
/// lowercase hexadecimal digits (`forms.rs` `link_token`, lane m4reg).
pub fn is_link_token(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::new();
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(c) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut s = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextets = [n >> 18, n >> 12, n >> 6, n];
        let keep = chunk.len().saturating_add(1);
        for (i, x) in sextets.iter().enumerate() {
            if i < keep {
                let idx = usize::try_from(x & 0x3f).unwrap_or(0);
                if let Some(c) = alphabet.get(idx) {
                    s.push(char::from(*c));
                }
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// J2: the listed states move invited, accepted, verified, granted.
    #[test]
    fn j2_reference_states_move_in_order() {
        assert_eq!(listed_state(false, true, true), RefState::Invited);
        assert_eq!(listed_state(true, false, false), RefState::Accepted);
        assert_eq!(listed_state(true, true, false), RefState::Verified);
        assert_eq!(listed_state(true, true, true), RefState::Granted);
    }

    /// J2, SoD-09, NOTE 5: the reference grant verdicts.
    #[test]
    fn sod09_reference_grant_verdicts() {
        assert_eq!(
            grant_verdict(Role::CommitteeMember, false, true),
            GrantVerdict::NoTermsAccepted
        );
        assert_eq!(
            grant_verdict(Role::CommitteeMember, true, false),
            GrantVerdict::Sod09
        );
        assert_eq!(
            grant_verdict(Role::ProgrammeManager, true, false),
            GrantVerdict::Sod09
        );
        assert_eq!(
            grant_verdict(Role::FinanceApprover, true, false),
            GrantVerdict::Composed
        );
        assert!(terms_bind_p75_p77(Role::IrcMember));
        assert!(!terms_bind_p75_p77(Role::ProgrammeManager));
    }

    /// ADR-007: the spellings a scan looks for, against known encodings.
    #[test]
    fn adr007_secret_spellings_match_known_encodings() {
        let s = secret_spellings(b"foob");
        assert!(s.contains(&b"666f6f62".to_vec()));
        assert!(s.contains(&b"666F6F62".to_vec()));
        assert!(s.contains(&b"Zm9vYg==".to_vec()));
        assert!(s.contains(&b"Zm9vYg".to_vec()));
        assert!(contains(b"xxZm9vYgyy", b"Zm9vYg"));
        assert!(!contains(b"abc", b""));
        let t = "00ff".repeat(16);
        assert_eq!(token_bytes(&t).map(|b| b.len()), Some(32));
        assert_eq!(token_bytes("00FF"), None);
        assert!(is_link_token(&"a".repeat(32)));
        assert!(!is_link_token(&"A".repeat(32)));
        assert!(!is_link_token(&"a".repeat(31)));
    }
}
