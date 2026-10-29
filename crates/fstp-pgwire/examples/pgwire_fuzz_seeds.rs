//! Regenerates the seed inputs of the fstp-pgwire fuzz targets.
//!
//! Seeds are built with the crate's own encoders, so they start the fuzzer
//! from well-formed server transcripts, SCRAM exchanges and binary values.
//! The layouts match the harness in `fuzz/harness.rs`.
//!
//! Usage: `cargo run -p fstp-pgwire --example pgwire_fuzz_seeds`

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: a developer tool that writes fuzz seeds and never ships"
)]

use std::error::Error;
use std::num::NonZeroU32;
use std::path::PathBuf;

use fstp_pgwire::proto::backend::{
    Authentication, BackendMessage, DataRow, ErrorFields, FieldDescription, TransactionStatus,
};
use fstp_pgwire::{Numeric, ToSql, Type, base64};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

fn write(target: &str, name: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let dir = PathBuf::from(DIR).join("fuzz/seeds").join(target);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(name), data)?;
    Ok(())
}

fn wire(msgs: &[BackendMessage]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = Vec::new();
    for m in msgs {
        m.encode(&mut out)?;
    }
    Ok(out)
}

fn col(name: &str, type_oid: u32) -> FieldDescription {
    FieldDescription {
        name: name.into(),
        table_oid: 0,
        column_id: 0,
        type_oid,
        type_size: -1,
        type_modifier: -1,
        format: 0,
    }
}

fn ready() -> BackendMessage {
    BackendMessage::ReadyForQuery(TransactionStatus::Idle)
}

fn row(values: &[Option<&[u8]>]) -> Result<BackendMessage, Box<dyn Error>> {
    Ok(BackendMessage::DataRow(DataRow::from_values(values)?))
}

fn error(code: &str) -> BackendMessage {
    BackendMessage::ErrorResponse(ErrorFields(vec![
        (b'S', b"ERROR".to_vec()),
        (b'V', b"ERROR".to_vec()),
        (b'C', code.as_bytes().to_vec()),
        (b'M', b"seed error".to_vec()),
        (b'D', b"Key (x)=(1) already exists.".to_vec()),
    ]))
}

fn startup_ok() -> Vec<BackendMessage> {
    vec![
        BackendMessage::Authentication(Authentication::Ok),
        BackendMessage::ParameterStatus {
            name: "client_encoding".into(),
            value: "UTF8".into(),
        },
        BackendMessage::ParameterStatus {
            name: "integer_datetimes".into(),
            value: "on".into(),
        },
        BackendMessage::BackendKeyData {
            process_id: 4242,
            secret_key: 77,
        },
        ready(),
    ]
}

/// The server's half of the operations in `harness::drive`, with a
/// statement cache of two.
fn transcript() -> Result<Vec<BackendMessage>, Box<dyn Error>> {
    let mut m = startup_ok();
    // SELECT $1::int4: prepare, then execute.
    m.extend([
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![23]),
        BackendMessage::RowDescription(vec![col("x", 23)]),
        ready(),
        BackendMessage::BindComplete,
        row(&[Some(&7i32.to_be_bytes())])?,
        row(&[None])?,
        BackendMessage::CommandComplete("SELECT 2".into()),
        ready(),
    ]);
    // UPDATE t SET x = $1.
    m.extend([
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![25]),
        BackendMessage::NoData,
        ready(),
        BackendMessage::BindComplete,
        BackendMessage::CommandComplete("UPDATE 3".into()),
        ready(),
    ]);
    // SELECT g FROM s: evicts the first statement, so a Close comes first.
    m.extend([
        BackendMessage::CloseComplete,
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![]),
        BackendMessage::RowDescription(vec![col("g", 23)]),
        ready(),
        BackendMessage::BindComplete,
    ]);
    for i in 0..5i32 {
        m.push(row(&[Some(&i.to_be_bytes())])?);
    }
    m.extend([BackendMessage::CommandComplete("SELECT 5".into()), ready()]);
    // SELECT 2: prepare only, evicting again.
    m.extend([
        BackendMessage::CloseComplete,
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![]),
        BackendMessage::RowDescription(vec![col("?column?", 23)]),
        ready(),
    ]);
    // SELECT 1: fails.
    m.extend([
        BackendMessage::CloseComplete,
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![]),
        BackendMessage::RowDescription(vec![col("?column?", 23)]),
        ready(),
        BackendMessage::BindComplete,
        BackendMessage::NoticeResponse(ErrorFields(vec![(b'S', b"NOTICE".to_vec())])),
        error("22012"),
        ready(),
    ]);
    Ok(m)
}

fn backend_seeds() -> Result<(), Box<dyn Error>> {
    let ctrl = [0x35u8, 7];
    let mut startup = vec![
        BackendMessage::Authentication(Authentication::Sasl {
            mechanisms: vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()],
        }),
        BackendMessage::Authentication(Authentication::SaslContinue {
            data: b"r=abcdef,s=c2FsdA==,i=4096".to_vec(),
        }),
        BackendMessage::Authentication(Authentication::SaslFinal {
            data: b"v=AAAA".to_vec(),
        }),
    ];
    startup.extend(startup_ok());
    let others = vec![
        error("23505"),
        BackendMessage::NoticeResponse(ErrorFields(vec![(b'S', b"WARNING".to_vec())])),
        BackendMessage::NotificationResponse {
            process_id: 1,
            channel: "chan".into(),
            payload: "payload".into(),
        },
        BackendMessage::NegotiateProtocolVersion {
            newest_minor: 0,
            unrecognized: vec!["_pq_.x".into()],
        },
        BackendMessage::Unsupported {
            tag: b'G',
            body: vec![0, 0, 1, 0, 0],
        },
        BackendMessage::EmptyQueryResponse,
        BackendMessage::PortalSuspended,
        BackendMessage::NoData,
        BackendMessage::CloseComplete,
        BackendMessage::Authentication(Authentication::Md5Password { salt: *b"salt" }),
        BackendMessage::Authentication(Authentication::CleartextPassword),
        BackendMessage::Authentication(Authentication::GssContinue { data: vec![1, 2] }),
    ];
    for (name, msgs) in [
        ("startup", startup),
        ("query", transcript()?),
        ("others", others),
    ] {
        let mut data = ctrl.to_vec();
        data.extend(wire(&msgs)?);
        write("pg_backend_decode", name, &data)?;
    }
    Ok(())
}

fn part(data: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    data.extend_from_slice(&u16::try_from(bytes.len())?.to_be_bytes());
    data.extend_from_slice(bytes);
    Ok(())
}

fn server_der() -> Result<Vec<u8>, Box<dyn Error>> {
    let pem = std::str::from_utf8(include_bytes!("../../fstp-tls/testdata/server.pem"))?;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    Ok(base64::decode(body.as_bytes())?)
}

fn scram_seeds() -> Result<(), Box<dyn Error>> {
    let nonce = "fuzzclientnonce";
    let der = server_der()?;
    for mode in 0u8..3 {
        let extra: Vec<u8> = if mode == 2 {
            der.clone()
        } else {
            b"Zm9vYmFy".to_vec()
        };
        let (gs2, cb): (&[u8], Vec<u8>) = match mode {
            0 => (b"n,,", Vec::new()),
            1 => (b"y,,", Vec::new()),
            _ => (
                b"p=tls-server-end-point,,",
                fstp_crypto::sha256(&extra).to_vec(),
            ),
        };
        let salt = b"seed-salt";
        let server_first = format!("r={nonce}server,s={},i=16", base64::encode(salt));
        let without_proof = format!("c={},r={nonce}server", base64::encode(&[gs2, &cb].concat()));
        let auth = format!("n=,r={nonce},{server_first},{without_proof}");
        let mut salted = [0u8; 32];
        fstp_crypto::pbkdf2_hmac_sha256(
            b"pencil",
            salt,
            NonZeroU32::new(16).ok_or("nz")?,
            &mut salted,
        );
        let server_key = fstp_crypto::hmac_sha256(&salted, b"Server Key");
        let sig = fstp_crypto::hmac_sha256(&server_key, auth.as_bytes());
        let finals: [(&str, Vec<u8>); 3] = [
            ("ok", format!("v={}", base64::encode(&sig)).into_bytes()),
            ("error", b"e=invalid-proof".to_vec()),
            (
                "wrong",
                format!("v={}", base64::encode(&[0u8; 32])).into_bytes(),
            ),
        ];
        for (name, fin) in finals {
            let mut data = vec![mode];
            part(&mut data, server_first.as_bytes())?;
            part(&mut data, &fin)?;
            data.extend_from_slice(&extra);
            write(
                "pg_scram_server_messages",
                &format!("mode{mode}-{name}"),
                &data,
            )?;
        }
    }
    let mut data = vec![0u8];
    part(&mut data, b"m=ext,r=fuzzclientnonceX,s=c2FsdA==,i=1")?;
    part(&mut data, b"v=")?;
    write("pg_scram_server_messages", "mandatory-extension", &data)?;
    // Below the harness's iteration floor of 8.
    let mut data = vec![0u8];
    part(&mut data, b"r=fuzzclientnonceserver,s=c2VlZC1zYWx0,i=7")?;
    part(&mut data, b"v=")?;
    write("pg_scram_server_messages", "too-few-iterations", &data)?;
    Ok(())
}

fn value_seeds() -> Result<(), Box<dyn Error>> {
    let mut seeds: Vec<(&str, Vec<u8>)> = vec![
        ("bool", vec![1]),
        ("int2", vec![0x80, 0]),
        ("int4", 7i32.to_be_bytes().to_vec()),
        ("int8", i64::MIN.to_be_bytes().to_vec()),
        ("float8", f64::NAN.to_bits().to_be_bytes().to_vec()),
        ("uuid", (0u8..16).collect()),
        ("text", "h\u{e9}llo \u{1F600}".as_bytes().to_vec()),
        ("timestamptz", 815_000_000_000_000i64.to_be_bytes().to_vec()),
        ("date", (-2_451_545i32).to_be_bytes().to_vec()),
        (
            "jsonb",
            b"\x01{\"a\": [1, 2.50, null, true, \"x\"]}".to_vec(),
        ),
        ("numeric-inf", vec![0, 0, 0, 0, 0xd0, 0, 0, 32]),
    ];
    for (name, text) in [
        ("numeric", "12345.678"),
        ("numeric-neg", "-0.0001"),
        ("numeric-nan", "NaN"),
    ] {
        let mut out = Vec::new();
        Numeric::parse(text)?.to_sql(Type::NUMERIC, &mut out)?;
        seeds.push((name, out));
    }
    for (name, data) in seeds {
        write("pg_value_decode", name, &data)?;
    }
    Ok(())
}

fn hostile_seeds() -> Result<(), Box<dyn Error>> {
    let script = wire(&transcript()?)?;
    let with = |head: &[u8], body: &[u8]| [head, body].concat();
    write("pg_hostile_server", "plaintext", &with(&[0, 63], &script))?;
    write(
        "pg_hostile_server",
        "plaintext-small-chunks",
        &with(&[6, 2], &script),
    )?;
    write("pg_hostile_server", "tls-session", &with(&[7, 63], &script))?;
    write(
        "pg_hostile_server",
        "scripted",
        &with(&[3, 5, 0x55, 7], &script),
    )?;
    let sasl = wire(&[
        BackendMessage::Authentication(Authentication::Sasl {
            mechanisms: vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()],
        }),
        BackendMessage::Authentication(Authentication::SaslContinue {
            data: b"r=AAAAAAAAAAAAAAAAAAAAAAAAserver,s=c2FsdA==,i=16".to_vec(),
        }),
    ])?;
    write("pg_hostile_server", "sasl-plus", &with(&[1, 63], &sasl))?;
    write(
        "pg_hostile_server",
        "default-policy",
        &with(&[2, 63], &script),
    )?;
    write(
        "pg_hostile_server",
        "ssl-injected",
        &with(&[5, 0xc0, 0, 0xc0], b"S\x16\x03\x03"),
    )?;
    write(
        "pg_hostile_server",
        "ssl-refused",
        &with(&[5, 0xc0, 0, 0xc0], b"N"),
    )?;
    // A server that asks for a cleartext password, then accepts it. Only the
    // modes with a TLS certificate may send it.
    let mut cleartext = vec![BackendMessage::Authentication(
        Authentication::CleartextPassword,
    )];
    cleartext.extend(transcript()?);
    let cleartext = wire(&cleartext)?;
    for (name, head) in [
        ("cleartext-plaintext", &[0u8, 63][..]),
        ("cleartext-fake-cert", &[1, 63]),
        ("cleartext-default-policy", &[2, 63]),
        ("cleartext-scripted", &[3, 5, 0x55, 7]),
        ("cleartext-tls-session", &[7, 63]),
    ] {
        write("pg_hostile_server", name, &with(head, &cleartext))?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    backend_seeds()?;
    scram_seeds()?;
    value_seeds()?;
    hostile_seeds()?;
    println!("wrote seeds under {DIR}/fuzz/seeds");
    Ok(())
}
