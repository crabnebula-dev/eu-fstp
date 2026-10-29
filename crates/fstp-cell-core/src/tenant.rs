//! Tenant commands and records: tenant admin grants, the SoD-07 self-grant
//! approval and the login policy (design section 5.1).

use fstp_domain::id::AccountId;

/// A tenant command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantCommand {
    /// Grant the tenant admin role.
    GrantTenantAdmin {
        /// The account.
        account: AccountId,
    },
    /// End the tenant admin role.
    EndTenantAdmin {
        /// The account.
        account: AccountId,
    },
    /// A second tenant admin approves a self-grant (SoD-07).
    ApproveSelfGrant {
        /// SHA-256 over the canonical grant and its command id.
        grant_digest: [u8; 32],
    },
    /// Set the login policy (P-70 to P-72).
    SetLoginPolicy {
        /// The policy, canonical.
        policy: Vec<u8>,
    },
}

/// A tenant record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantRecord {
    /// The tenant admin role was granted.
    TenantAdminGranted {
        /// The account.
        account: AccountId,
    },
    /// The tenant admin role ended.
    TenantAdminEnded {
        /// The account.
        account: AccountId,
    },
    /// A self-grant was approved.
    SelfGrantApproved {
        /// The approving admin.
        approver: AccountId,
        /// The grant digest.
        grant_digest: [u8; 32],
        /// UTC microseconds after which the approval lapses.
        expires_at: i64,
    },
    /// A self-grant approval was used by its grant.
    SelfGrantApprovalUsed {
        /// The grant digest.
        grant_digest: [u8; 32],
    },
    /// The login policy changed.
    LoginPolicySet {
        /// The policy, canonical.
        policy: Vec<u8>,
    },
}

/// P-71, the default step-up freshness: 5 minutes (proposed, Q37).
pub const P71_DEFAULT_US: i64 = 5 * 60 * 1_000_000;
/// P-72, the default idle session lifetime: 30 minutes (proposed, Q37).
pub const P72_IDLE_DEFAULT_US: i64 = 30 * 60 * 1_000_000;
/// P-72, the default absolute session lifetime: 12 hours (proposed, Q37).
pub const P72_ABSOLUTE_DEFAULT_US: i64 = 12 * 60 * 60 * 1_000_000;

/// The tenant login policy that `SetLoginPolicy` carries (P-71 and P-72,
/// design sections 5.1 and 8.4).
///
/// Its canonical form is the RFC 8785 text of an object with exactly the
/// members `p71_us`, `p72_absolute_us` and `p72_idle_us`. Each is `null`
/// for the default, or a decimal string of microseconds. A tenant value
/// may only shorten the default, so a value above it, zero or a negative
/// value is refused.
///
/// Reading, interim pending Daniel: P-70, the enabled login methods, is
/// not part of the form yet. Login method checks belong to `fstp-auth`
/// (lane W2b), and the form gains a member once that lane fixes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TenantLoginPolicy {
    /// P-71 in microseconds, or `None` for the default.
    pub p71_us: Option<i64>,
    /// The P-72 idle lifetime in microseconds, or `None` for the default.
    pub p72_idle_us: Option<i64>,
    /// The P-72 absolute lifetime in microseconds, or `None` for the
    /// default.
    pub p72_absolute_us: Option<i64>,
}

/// Why a login policy was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The bytes are not the canonical form.
    Malformed,
    /// A value would lengthen its default, or is not positive.
    NotShorter,
}

/// The members of the canonical form, in RFC 8785 order.
const POLICY_MEMBERS: [&str; 3] = ["p71_us", "p72_absolute_us", "p72_idle_us"];

impl TenantLoginPolicy {
    /// The effective P-71: the tenant value or the default, whichever is
    /// shorter. A value only shortens its default, so a stored value above
    /// this build's default is clamped where it is used (Q37).
    pub fn p71_us(&self) -> i64 {
        self.p71_us
            .map_or(P71_DEFAULT_US, |v| v.min(P71_DEFAULT_US))
    }

    /// The effective P-72 idle lifetime, clamped as [`Self::p71_us`] is.
    pub fn p72_idle_us(&self) -> i64 {
        self.p72_idle_us
            .map_or(P72_IDLE_DEFAULT_US, |v| v.min(P72_IDLE_DEFAULT_US))
    }

    /// The effective P-72 absolute lifetime, clamped as [`Self::p71_us`]
    /// is.
    pub fn p72_absolute_us(&self) -> i64 {
        self.p72_absolute_us
            .map_or(P72_ABSOLUTE_DEFAULT_US, |v| v.min(P72_ABSOLUTE_DEFAULT_US))
    }

    /// The canonical bytes of the policy, as `SetLoginPolicy` carries them.
    pub fn encode(&self) -> Vec<u8> {
        let field = |v: Option<i64>| match v {
            Some(n) => fstp_json::Value::String(n.to_string()),
            None => fstp_json::Value::Null,
        };
        let mut o = fstp_json::Object::with_capacity(3);
        o.insert("p71_us", field(self.p71_us));
        o.insert("p72_absolute_us", field(self.p72_absolute_us));
        o.insert("p72_idle_us", field(self.p72_idle_us));
        fstp_json::to_canonical(&fstp_json::Value::Object(o))
            .map(String::into_bytes)
            .unwrap_or_default()
    }

    /// Decodes the canonical form and checks that every value only
    /// shortens its default. `decide` uses it for a new `SetLoginPolicy`.
    pub fn decode(bytes: &[u8]) -> Result<TenantLoginPolicy, PolicyError> {
        let policy = TenantLoginPolicy::decode_stored(bytes)?;
        let shorter = |v: Option<i64>, default: i64| v.is_none_or(|n| n <= default);
        if !shorter(policy.p71_us, P71_DEFAULT_US)
            || !shorter(policy.p72_idle_us, P72_IDLE_DEFAULT_US)
            || !shorter(policy.p72_absolute_us, P72_ABSOLUTE_DEFAULT_US)
        {
            return Err(PolicyError::NotShorter);
        }
        Ok(policy)
    }

    /// Decodes the canonical form of a stored policy and checks its
    /// structure only: every value is a positive canonical integer. The
    /// fold uses it, so a ledger replays the same under any build's
    /// defaults (I-23, Q37). The "may only shorten" rule applies where a
    /// value is used, and to a new `SetLoginPolicy` ([`Self::decode`]).
    pub fn decode_stored(bytes: &[u8]) -> Result<TenantLoginPolicy, PolicyError> {
        let v = fstp_json::parse(bytes).map_err(|_| PolicyError::Malformed)?;
        let o = v.as_object().ok_or(PolicyError::Malformed)?;
        if o.len() != POLICY_MEMBERS.len() || POLICY_MEMBERS.iter().any(|m| !o.contains_key(m)) {
            return Err(PolicyError::Malformed);
        }
        let read = |name: &str| -> Result<Option<i64>, PolicyError> {
            match o.get(name) {
                Some(fstp_json::Value::Null) => Ok(None),
                Some(fstp_json::Value::String(s)) => {
                    let canonical = match s.as_bytes() {
                        [] | [b'0', ..] => false,
                        b => b.iter().all(u8::is_ascii_digit),
                    };
                    if !canonical {
                        return Err(PolicyError::NotShorter);
                    }
                    let n = s.parse::<i64>().map_err(|_| PolicyError::NotShorter)?;
                    if n <= 0 {
                        return Err(PolicyError::NotShorter);
                    }
                    Ok(Some(n))
                }
                _ => Err(PolicyError::Malformed),
            }
        };
        let policy = TenantLoginPolicy {
            p71_us: read("p71_us")?,
            p72_idle_us: read("p72_idle_us")?,
            p72_absolute_us: read("p72_absolute_us")?,
        };
        if policy.encode() != bytes {
            return Err(PolicyError::Malformed);
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-78, design section 8.4: a tenant login policy round-trips through
    /// its canonical form, and a value may only shorten its default.
    #[test]
    fn i78_login_policy_round_trips_and_may_only_shorten() {
        let p = TenantLoginPolicy {
            p71_us: Some(60_000_000),
            p72_idle_us: None,
            p72_absolute_us: Some(P72_ABSOLUTE_DEFAULT_US),
        };
        assert_eq!(TenantLoginPolicy::decode(&p.encode()), Ok(p));
        assert_eq!(p.p71_us(), 60_000_000);
        assert_eq!(p.p72_idle_us(), P72_IDLE_DEFAULT_US);
        for bad in [Some(P71_DEFAULT_US + 1), Some(0), Some(-1)] {
            let longer = TenantLoginPolicy {
                p71_us: bad,
                ..TenantLoginPolicy::default()
            };
            assert_eq!(
                TenantLoginPolicy::decode(&longer.encode()),
                Err(PolicyError::NotShorter),
                "{bad:?}"
            );
        }
        for malformed in [&b"{}"[..], b"{\"p71_us\":null}", b"null", b""] {
            assert_eq!(
                TenantLoginPolicy::decode(malformed),
                Err(PolicyError::Malformed)
            );
        }
    }
}
