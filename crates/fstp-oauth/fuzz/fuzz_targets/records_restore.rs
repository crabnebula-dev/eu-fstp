//! Fuzz target `records_restore` of `fstp-oauth` (TH-26, lane L2,
//! ADR-013 amendment of 2026-11-20).
//!
//! `AuthorizationServer::restore` takes the rows a shell read back from
//! the `mcp` schema. The rows are data from storage, so the restore is
//! treated as a decoder: client metadata goes through the fuzzed
//! registration decoder again, and the input here builds arbitrary rows.
//!
//! Design checks: the restore never panics. Every record is restored or
//! counted as dropped, never both. A restored server exports records that
//! restore again with nothing dropped, and to the same records.

#![no_main]

use fstp_oauth::{
    Account, AuthorizationServer, ClientNumber, ClientRecord, Config, FamilyRecord, LoginMethod,
    Records, RefreshHash, ScopeSet,
};
use libfuzzer_sys::fuzz_target;

const ISSUER: &str = "https://cell-a.example";
const MCP: &str = "https://cell-a.example/mcp";

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }

    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = usize::from(self.byte()?);
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head.to_vec())
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from(i16::from_be_bytes([self.byte()?, self.byte()?])))
    }
}

const METHODS: [LoginMethod; 4] = [
    LoginMethod::Passkey,
    LoginMethod::MagicLink,
    LoginMethod::Opaque,
    LoginMethod::EudiWallet,
];

fn records(data: &[u8]) -> Option<Records> {
    let mut i = Input(data);
    let mut r = Records::default();
    while let Some(op) = i.byte() {
        match op % 3 {
            0 => {
                let number = ClientNumber::from_raw(u64::from(i.byte()?));
                let id = String::from_utf8_lossy(&i.bytes()?).into_owned();
                let metadata = i.bytes()?;
                r.clients.push(ClientRecord {
                    number,
                    client_id: id,
                    metadata,
                    registered: i.i64()?,
                });
            }
            1 => {
                let id = u64::from(i.byte()?);
                let client = ClientNumber::from_raw(u64::from(i.byte()?));
                let account = Account::from_raw(u128::from(i.byte()?));
                let bits = u16::from_be_bytes([i.byte()?, i.byte()?]);
                let scopes = ScopeSet::from_bits(bits).unwrap_or_default();
                let start = i.i64()?;
                let end = i.i64()?;
                let current = [i.byte()?; 32];
                let refreshes = u32::from(i.byte()?);
                let flags = i.byte()?;
                let method = METHODS
                    .get(usize::from(flags % 4))
                    .copied()
                    .unwrap_or(LoginMethod::Passkey);
                r.families.push(FamilyRecord {
                    id,
                    client,
                    account,
                    scopes,
                    start,
                    end,
                    current,
                    refreshes,
                    revoked: flags & 0x80 != 0,
                    method,
                    version: u64::from(i.byte()?),
                });
            }
            _ => r.refresh.push(RefreshHash {
                hash: [i.byte()?; 32],
                family: u64::from(i.byte()?),
            }),
        }
    }
    Some(r)
}

fuzz_target!(|data: &[u8]| {
    let Some(rec) = records(data) else {
        return;
    };
    let total = rec.clients.len() + rec.families.len() + rec.refresh.len();
    let cfg = Config::new(ISSUER, MCP, 43_200_000_000, 300_000_000);
    let Ok(restored) = AuthorizationServer::restore(cfg.clone(), rec) else {
        panic!("a valid configuration was refused");
    };
    let kept = restored.server.records();
    let held = kept.clients.len() + kept.families.len() + kept.refresh.len();
    assert_eq!(
        held + restored.dropped,
        total,
        "a record was lost or doubled"
    );
    let Ok(again) = AuthorizationServer::restore(cfg, kept.clone()) else {
        panic!("a valid configuration was refused");
    };
    assert_eq!(again.dropped, 0, "an exported record did not restore");
    let mut a = again.server.records();
    let mut b = kept;
    for r in [&mut a, &mut b] {
        r.families.sort_by_key(|f| f.id);
        r.refresh.sort_by_key(|h| (h.family, h.hash));
    }
    assert_eq!(a, b, "a restore changed a record");
});
