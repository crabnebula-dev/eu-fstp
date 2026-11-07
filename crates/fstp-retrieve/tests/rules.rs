//! Pure rules of the retrieval proxy (M7 design section 3.2, lane L-RETR).
//!
//! Tests named `th12_*` verify the TH-12 mitigations: the destination
//! policy, source classing, the verification rule and retrieved content
//! held as untrusted data. Tests named `t_llm_retrieval_*` verify the
//! T-LLM-RETRIEVAL pass condition at the rule level.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_prop::check;
use fstp_retrieve::{
    ApplicantSources, Basis, ClaimVerdict, DestinationPolicy, Refusal, SourceClass, SourceUrl,
    decode_body, html_to_text, th12_rule,
};

fn url(s: &str) -> SourceUrl {
    SourceUrl::parse(s).unwrap()
}

fn verdict_of(policy: &DestinationPolicy, s: &str) -> Result<(), Refusal> {
    let u = SourceUrl::parse(s)?;
    policy.check(&u)
}

/// TH-12: the destination policy refuses every forbidden destination.
#[test]
fn th12_policy_refuses_forbidden_destinations() {
    let p = DestinationPolicy::fixture();
    let cases: &[(&str, Refusal)] = &[
        ("http://127.0.0.1/", Refusal::IpLiteral),
        ("http://10.0.0.1/x", Refusal::IpLiteral),
        ("http://[::1]/", Refusal::IpLiteral),
        ("http://2130706433/", Refusal::IpLiteral),
        ("http://0x7f.0.0.1/", Refusal::IpLiteral),
        (
            "http://169.254.169.254/latest/meta-data",
            Refusal::IpLiteral,
        ),
        ("http://localhost/", Refusal::HostNotAllowed),
        ("http://foo.localhost/", Refusal::HostNotAllowed),
        ("http://intranet/", Refusal::HostNotAllowed),
        ("http://example.com/", Refusal::HostNotAllowed),
        ("http://repo.test.example.com/", Refusal::HostNotAllowed),
        ("http://eviltest/", Refusal::HostNotAllowed),
        ("http://repo.test:8080/", Refusal::PortNotAllowed),
        ("https://repo.test:22/", Refusal::PortNotAllowed),
        ("ftp://repo.test/", Refusal::MalformedUrl),
        ("file:///etc/passwd", Refusal::MalformedUrl),
        ("http://user:pw@repo.test/", Refusal::MalformedUrl),
        ("http://%31%32%37.0.0.1/", Refusal::MalformedUrl),
        ("repo.test/readme", Refusal::MalformedUrl),
        ("", Refusal::MalformedUrl),
    ];
    for (u, want) in cases {
        assert_eq!(verdict_of(&p, u), Err(*want), "{u}");
    }
    let long = format!("http://repo.test/{}", "a".repeat(4096));
    assert_eq!(verdict_of(&p, &long), Err(Refusal::UrlTooLong));
}

/// TH-12: a production policy refuses plain HTTP, and the fixture policy
/// admits the fixture hosts.
#[test]
fn th12_policy_admits_only_listed_hosts() {
    let fixture = DestinationPolicy::fixture();
    for u in [
        "http://repo.test/acme/tool",
        "https://docs.example-project.test/a?b=c#frag",
        "HTTP://Repo.TEST./x",
        "http://repo.test:80/",
    ] {
        assert_eq!(verdict_of(&fixture, u), Ok(()), "{u}");
    }
    let prod = DestinationPolicy::new(&["example.org"], false);
    assert_eq!(verdict_of(&prod, "https://www.example.org/x"), Ok(()));
    assert_eq!(
        verdict_of(&prod, "http://www.example.org/x"),
        Err(Refusal::SchemeNotAllowed)
    );
    assert_eq!(
        verdict_of(&prod, "https://example.org.evil.test/"),
        Err(Refusal::HostNotAllowed)
    );
    // A misconfigured suffix never opens a local name.
    let bad = DestinationPolicy::new(&["localhost", "internal"], true);
    assert_eq!(
        verdict_of(&bad, "http://a.localhost/"),
        Err(Refusal::HostNotAllowed)
    );
    assert_eq!(
        verdict_of(&bad, "http://metadata.internal/"),
        Err(Refusal::HostNotAllowed)
    );
}

/// TH-12: every host the policy admits is a dotted name under a listed
/// suffix, never an IP literal, whatever the input.
#[test]
fn th12_policy_accepted_hosts_are_listed_names() {
    let alphabet: Vec<char> = "ab09.-:[]%@/x".chars().collect();
    check("th12_policy_accepted_hosts_are_listed_names", |g| {
        let len = g.usize_in(0..=24);
        let host: String = (0..len).map(|_| *g.pick(&alphabet)).collect();
        let raw = format!("http://{host}/p");
        let p = DestinationPolicy::fixture();
        if let Ok(u) = SourceUrl::parse(&raw)
            && p.check(&u).is_ok()
        {
            let h = u.host();
            if !h.ends_with(".test") || h.len() <= 5 {
                return Err(format!("admitted {h:?}"));
            }
            if h.split('.').next_back().is_some_and(|l| l != "test") {
                return Err(format!("bad tld {h:?}"));
            }
            if h.starts_with('[') || h.split('.').all(|l| l.chars().all(|c| c.is_ascii_digit())) {
                return Err(format!("ip literal {h:?}"));
            }
        }
        Ok(())
    });
}

/// TH-12: a Location header is resolved against the current URL and
/// checked again, so a redirect cannot leave the policy.
#[test]
fn th12_redirect_target_is_resolved_and_rechecked() {
    let p = DestinationPolicy::fixture();
    let base = url("http://repo.test/acme/tool/readme");
    assert_eq!(base.join("/x").unwrap().as_str(), "http://repo.test/x");
    assert_eq!(
        base.join("other").unwrap().as_str(),
        "http://repo.test/acme/tool/other"
    );
    assert_eq!(
        base.join("//docs.test/y").unwrap().as_str(),
        "http://docs.test/y"
    );
    let off = base.join("http://127.0.0.1/admin").unwrap();
    assert_eq!(p.check(&off), Err(Refusal::IpLiteral));
    let off = base.join("https://example.com/").unwrap();
    assert_eq!(p.check(&off), Err(Refusal::HostNotAllowed));
    assert!(base.join("javascript:alert(1)").is_err());
}

/// TH-12, T-LLM-RETRIEVAL: a source is applicant-controlled when its host
/// and path match a URL the proposal names as its own. Matching is
/// conservative: case, `www.`, a trailing slash, `.git` and the query do
/// not make an applicant source independent.
#[test]
fn th12_classing_matches_claimed_host_and_path() {
    let mut a = ApplicantSources::new();
    a.add(&url("https://repo.test/acme/tool.git"));
    a.add(&url("https://acme-project.test/"));
    let ap = SourceClass::ApplicantControlled;
    let ind = SourceClass::Independent;
    for (u, want) in [
        ("https://repo.test/acme/tool", ap),
        ("http://repo.test/acme/tool/blob/main/README.md", ap),
        ("https://REPO.test/Acme/Tool/", ap),
        ("https://www.repo.test/acme/tool?tab=readme", ap),
        ("https://repo.test/acme/%74ool", ap),
        ("https://acme-project.test/about", ap),
        ("https://www.acme-project.test/", ap),
        ("https://repo.test/acme/tool-fork", ind),
        ("https://repo.test/acme", ind),
        ("https://repo.test/other/tool", ind),
        ("https://registry.test/package/tool", ind),
        ("https://sub.acme-project.test/", ind),
    ] {
        assert_eq!(a.classify(&url(u)), want, "{u}");
    }
    assert_eq!(
        ApplicantSources::new().classify(&url("https://repo.test/")),
        ind
    );
}

/// TH-12, T-LLM-RETRIEVAL: whatever the model says, a claim whose
/// supporting sources are all applicant-controlled is never verified, and
/// the ruling states which kind of source it used.
#[test]
fn th12_applicant_sources_alone_never_verify() {
    let verdicts = [
        ClaimVerdict::Verified,
        ClaimVerdict::Contradicted,
        ClaimVerdict::NotVerified,
    ];
    let classes = [SourceClass::ApplicantControlled, SourceClass::Independent];
    check("th12_applicant_sources_alone_never_verify", |g| {
        let model = *g.pick(&verdicts);
        let n = g.usize_in(0..=6);
        let sources: Vec<SourceClass> = (0..n).map(|_| *g.pick(&classes)).collect();
        let ruled = th12_rule(model, &sources);
        let independent = sources.contains(&SourceClass::Independent);
        if ruled.verdict == ClaimVerdict::Verified && !independent {
            return Err(format!("verified on {sources:?}"));
        }
        let want_basis = if independent {
            Basis::Independent
        } else if sources.is_empty() {
            Basis::NoSources
        } else {
            Basis::ApplicantControlledOnly
        };
        if ruled.basis != want_basis {
            return Err(format!("basis {:?} for {sources:?}", ruled.basis));
        }
        if independent && ruled.verdict != model {
            return Err("independent support changed the verdict".into());
        }
        if ruled.downgraded != (model == ClaimVerdict::Verified && !independent) {
            return Err("downgrade flag wrong".into());
        }
        Ok(())
    });
}

/// T-LLM-RETRIEVAL: a contradiction stays a contradiction, even from the
/// applicant's own source.
#[test]
fn t_llm_retrieval_contradiction_survives_applicant_sources() {
    let r = th12_rule(
        ClaimVerdict::Contradicted,
        &[SourceClass::ApplicantControlled],
    );
    assert_eq!(r.verdict, ClaimVerdict::Contradicted);
    assert_eq!(r.basis, Basis::ApplicantControlledOnly);
}

/// TH-12, TH-01: the HTML-to-text converter strips scripts, styles,
/// comments, tags and attributes and keeps the text.
#[test]
fn th12_html_to_text_strips_scripts_and_keeps_text() {
    let html = r#"<!DOCTYPE html><html><head><title>Acme &amp; Tool</title>
<style>body { color: red } .x::after { content: "STYLE-CANARY" }</style>
<script type="text/javascript">var s = "</p>SCRIPT-CANARY"; if (a < b) {}</script>
</head><body>
<!-- COMMENT-CANARY -->
<h1 class="t" title="ATTR-CANARY">Tool  maintainers</h1>
<p>Maintained by <a href="https://repo.test/acme" onclick="ATTR2">Acme</a> since&nbsp;2019.</p>
<SCRIPT>SCRIPT2-CANARY</SCRIPT >
<ul><li>one</li><li>two &lt;three&gt; &#x41;&#66;</li></ul>
<noscript>NOSCRIPT-CANARY</noscript><template>TEMPLATE-CANARY</template>
<svg><text>SVG-CANARY</text></svg>
<pre>  a
  b</pre>
</body></html>"#;
    let out = html_to_text(html, 10_000);
    assert!(!out.truncated);
    for canary in [
        "STYLE-CANARY",
        "SCRIPT-CANARY",
        "SCRIPT2-CANARY",
        "COMMENT-CANARY",
        "ATTR-CANARY",
        "ATTR2",
        "NOSCRIPT-CANARY",
        "TEMPLATE-CANARY",
        "SVG-CANARY",
        "repo.test",
        "<p>",
        "var s",
    ] {
        assert!(!out.text.contains(canary), "{canary} in {:?}", out.text);
    }
    for kept in [
        "Acme & Tool",
        "Tool maintainers",
        "Maintained by Acme since 2019.",
        "two <three> AB",
        "  a\n  b",
    ] {
        assert!(
            out.text.contains(kept),
            "{kept} missing from {:?}",
            out.text
        );
    }
    assert!(out.text.lines().any(|l| l == "one"));
}

/// TH-12: removing a script element from a document never changes its
/// text, whatever the text around it and the script content.
#[test]
fn th12_html_to_text_script_removal_is_invisible() {
    check("th12_html_to_text_script_removal_is_invisible", |g| {
        let a: String = g
            .string(0..=24)
            .chars()
            .filter(|c| *c != '<' && *c != '&')
            .collect();
        let b: String = g.string(0..=24).chars().filter(|c| *c != '<').collect();
        let c: String = g
            .string(0..=24)
            .chars()
            .filter(|c| *c != '<' && *c != '&')
            .collect();
        let tag = *g.pick(&["script", "style", "SCRIPT", "template", "noscript"]);
        let with = format!("<div>{a}<{tag} x=\">\">{b}</{tag}>{c}</div>");
        let without = format!("<div>{a}{c}</div>");
        let w = html_to_text(&with, 4096);
        let wo = html_to_text(&without, 4096);
        if w != wo {
            return Err(format!("{:?} != {:?}", w.text, wo.text));
        }
        Ok(())
    });
}

/// TH-12: text without markup comes out with whitespace collapsed and
/// control characters removed, and never above the byte limit.
#[test]
fn th12_html_to_text_keeps_plain_text_within_limit() {
    check("th12_html_to_text_keeps_plain_text_within_limit", |g| {
        let s: String = g
            .string(0..=40)
            .chars()
            .filter(|c| *c != '<' && *c != '&')
            .collect();
        let max = g.usize_in(0..=64);
        let out = html_to_text(&s, max);
        if out.text.len() > max {
            return Err("over limit".into());
        }
        let ws = |c: char| c.is_whitespace() || c == '\u{a0}';
        let want: String = s
            .split(ws)
            .map(|w| w.chars().filter(|c| !c.is_control()).collect::<String>())
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !out.truncated && out.text != want {
            return Err(format!("{:?} != {want:?}", out.text));
        }
        if out.truncated && !want.starts_with(&out.text) {
            return Err(format!("{:?} is no prefix of {want:?}", out.text));
        }
        Ok(())
    });
}

/// TH-12: the body decoder accepts only text media types and known
/// charsets, and bounds the text it returns.
#[test]
fn th12_body_decoder_refuses_unsupported_types() {
    let html = b"<p>caf\xc3\xa9</p>";
    let ok = decode_body(Some(b"text/html; charset=UTF-8"), html, 100).unwrap();
    assert_eq!(ok.text, "caf\u{e9}");
    let latin = decode_body(Some(b"text/plain;charset=\"iso-8859-1\""), b"caf\xe9", 100).unwrap();
    assert_eq!(latin.text, "caf\u{e9}");
    let plain = decode_body(None, b"line one\r\nline\x00 two\x1b[0m", 100).unwrap();
    assert_eq!(plain.text, "line one\nline two[0m");
    let md = decode_body(Some(b"text/markdown"), b"# Title", 100).unwrap();
    assert_eq!(md.text, "# Title");
    let cut = decode_body(Some(b"text/plain"), "x\u{e9}".repeat(10).as_bytes(), 7).unwrap();
    assert!(cut.truncated);
    assert!(cut.text.len() <= 7);
    for ct in [
        &b"application/octet-stream"[..],
        b"application/pdf",
        b"image/svg+xml",
        b"text/javascript",
        b"text",
        b"text/html/x",
        b"",
    ] {
        assert_eq!(
            decode_body(Some(ct), b"x", 100),
            Err(Refusal::UnsupportedMediaType),
            "{}",
            String::from_utf8_lossy(ct)
        );
    }
    assert_eq!(
        decode_body(Some(b"text/html; charset=shift_jis"), b"x", 100),
        Err(Refusal::UnsupportedCharset)
    );
}
