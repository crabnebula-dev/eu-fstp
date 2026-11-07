//! The tenant's mail submission relay (M6 lane L6-EGR, ADR-018 proposed).
//!
//! A tenant admin names the relay host, the cell secret that holds the
//! submission credential, and optionally a pinned CA. The setting is
//! high-risk, so it needs a fresh step-up and never arrives through MCP
//! (R-LG-03, I-78, I-85). A CrabNebula host is never a relay (I-38).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, TextId, TextRef};
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    CellKind, DomainName, MailRelay, TenantAnswers, TenantCommand, TenantCtx, TenantKind,
    TenantRecord, TenantRefusal, TenantState, Token, decide, decode_command, decode_record,
    encode_command, encode_record,
};

const ADMIN: AccountId = AccountId::from_raw(1);
const OUTSIDER: AccountId = AccountId::from_raw(99);

fn ctx(actor: AccountId, via: Via) -> TenantCtx {
    TenantCtx {
        actor,
        via,
        at: Timestamp::from_micros(1_000_000),
    }
}

fn relay(host: &str, ca: bool) -> MailRelay {
    MailRelay {
        host: DomainName::new(host).unwrap(),
        credential: Token::new("mail-relay").unwrap(),
        ca: ca.then(|| TextRef::new(TextId::from_raw(41), ContentDigest::from_bytes([4; 32]))),
    }
}

fn set(relay: Option<MailRelay>) -> TenantCommand {
    TenantCommand::SetMailRelay { relay }
}

/// R-LG-03, I-78, I-85: the mail relay is a high-risk tenant setting. It
/// is web only, a tenant admin's alone, and refused through MCP. A tenant
/// admin on the web sets it, and the fold keeps it.
#[test]
fn r_lg_03_mail_relay_set_is_high_risk_with_step_up() {
    let k = TenantKind::SetMailRelay;
    assert!(TenantKind::ALL.contains(&k));
    assert!(k.high_risk());
    assert!(k.web_only());
    assert!(k.admin_only());
    let s = TenantState::genesis(ADMIN, CellKind::Saas);
    let cmd = set(Some(relay("smtp.relay.example", true)));
    let a = TenantAnswers::new();
    assert_eq!(
        decide(&s, &ctx(ADMIN, Via::Mcp), &cmd, &a),
        Err(TenantRefusal::HighRiskViaMcp)
    );
    assert_eq!(
        decide(&s, &ctx(OUTSIDER, Via::Web), &cmd, &a),
        Err(TenantRefusal::NotTenantAdmin)
    );
    let recs = decide(&s, &ctx(ADMIN, Via::Web), &cmd, &a).unwrap();
    assert_eq!(
        recs,
        vec![TenantRecord::MailRelaySet {
            relay: Some(relay("smtp.relay.example", true)),
            by: ADMIN,
        }]
    );
    let after = TenantState::replay(ADMIN, CellKind::Saas, &recs).unwrap();
    assert_eq!(after.mail_relay(), Some(&relay("smtp.relay.example", true)));
    let cleared = decide(&after, &ctx(ADMIN, Via::Web), &set(None), &a).unwrap();
    let mut s2 = after.clone();
    s2.apply_all(&cleared).unwrap();
    assert_eq!(s2.mail_relay(), None);
}

/// I-38, ADR-018: a CrabNebula host, a name that is not a fully qualified
/// host name and an empty credential name are refused, and a record that
/// holds one does not fold.
#[test]
fn i38_mail_relay_refuses_crabnebula_and_non_host_names() {
    let s = TenantState::genesis(ADMIN, CellKind::Saas);
    let a = TenantAnswers::new();
    for host in [
        "licences.fstp.crabnebula.dev",
        "updates.fstp.crabnebula.dev",
        "smtp.crabnebula.dev",
        "crabnebula.dev",
        "localhost",
        "10.0.0.1",
        "smtp..relay.example",
        "-smtp.relay.example",
    ] {
        let cmd = set(Some(relay(host, false)));
        assert_eq!(
            decide(&s, &ctx(ADMIN, Via::Web), &cmd, &a),
            Err(TenantRefusal::InvalidMailRelay),
            "{host}"
        );
        let rec = TenantRecord::MailRelaySet {
            relay: Some(relay(host, false)),
            by: ADMIN,
        };
        assert!(
            TenantState::replay(ADMIN, CellKind::Saas, &[rec]).is_err(),
            "{host}"
        );
    }
    let mut no_secret = relay("smtp.relay.example", false);
    no_secret.credential = Token::new("").unwrap();
    assert_eq!(
        decide(&s, &ctx(ADMIN, Via::Web), &set(Some(no_secret)), &a),
        Err(TenantRefusal::InvalidMailRelay)
    );
}

/// ADR-007: the command and the record round-trip through the canonical
/// codec, with and without a pinned CA and for a clear. The record holds
/// the host, the secret's name and a text reference, never a credential.
#[test]
fn adr007_mail_relay_codec_round_trip() {
    for r in [
        Some(relay("smtp.relay.example", true)),
        Some(relay("smtp.relay.example", false)),
        None,
    ] {
        let cmd = set(r.clone());
        let bytes = encode_command(&cmd).unwrap();
        assert_eq!(decode_command(&bytes).unwrap(), cmd);
        let rec = TenantRecord::MailRelaySet {
            relay: r,
            by: ADMIN,
        };
        let bytes = encode_record(&rec).unwrap();
        assert_eq!(decode_record(&bytes).unwrap(), rec);
    }
    let text = br#"{"kind":"SetMailRelay","relay":{"ca":null,"credential":"mail-relay","host":"smtp.relay.example"}}"#;
    assert!(decode_command(text).is_ok());
    for bad in [
        &br#"{"kind":"SetMailRelay","relay":{"ca":null,"credential":"mail-relay","host":"SMTP.relay.example"}}"#[..],
        br#"{"kind":"SetMailRelay","relay":{"ca":null,"credential":"mail relay","host":"smtp.relay.example"}}"#,
        br#"{"kind":"SetMailRelay","relay":{"ca":null,"credential":"mail-relay","host":"smtp.relay.example","port":"587"}}"#,
        br#"{"kind":"SetMailRelay","relay":{"credential":"mail-relay","host":"smtp.relay.example"}}"#,
    ] {
        assert!(decode_command(bad).is_err());
    }
}
