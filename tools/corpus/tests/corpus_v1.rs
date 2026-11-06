//! Tests of the synthetic corpus generator (M7 design section 5,
//! `SPEC/07-test-plan/synthetic-corpus.md`, `SPEC/07-test-plan/test-plan.md`).
//!
//! Lane L-CORPUS, written before the generator. Each test reads the
//! generated files the way a consumer does: `manifest.json` first, then
//! the item and fixture files it names, parsed with `fstp-json`.
//!
//! IDs: T-PRIV-CANARY (TH-07) for the canaries, the synthetic-data rule
//! of `test-plan.md` for the scan, and T-LLM-COMPLETE, T-LLM-ACCURACY,
//! T-LLM-INJ, T-LLM-RETRIEVAL and T-LLM-FLUENCY for the variant labels the
//! evaluation reads.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};

use corpus::{Corpus, GENERATOR, PII_CLASSES, RUBRIC_ELEMENTS, SYLLABLES, V1_SEED, generate};
use fstp_json::Value;

fn manifest(c: &Corpus) -> Value {
    fstp_json::parse(c.file("manifest.json").expect("manifest.json")).unwrap()
}

fn items(m: &Value) -> Vec<&Value> {
    m.get("items").unwrap().as_array().unwrap().iter().collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("member {k} missing in {v}"))
}

fn item_file(c: &Corpus, entry: &Value) -> Value {
    fstp_json::parse(c.file(s(entry, "file")).expect("item file")).unwrap()
}

fn narrative(item: &Value) -> &str {
    s(item.get("proposal").unwrap(), "narrative")
}

/// The narrative before its contact section, where every canary sits.
fn rubric_part(item: &Value) -> &str {
    let n = narrative(item);
    n.split_once("\n\nContact\n").expect("contact section").0
}

fn web(c: &Corpus, url: &str) -> String {
    let rest = url.strip_prefix("http://").expect("http url");
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = if path.is_empty() || path.ends_with('/') {
        format!("{path}index.html")
    } else {
        path.to_owned()
    };
    let f = format!("web/{host}/{path}");
    String::from_utf8(
        c.file(&f)
            .unwrap_or_else(|| panic!("no fixture {f}"))
            .to_vec(),
    )
    .unwrap()
}

fn by_id(m: &Value) -> BTreeMap<String, &Value> {
    items(m)
        .into_iter()
        .map(|e| (s(e, "id").to_owned(), e))
        .collect()
}

fn variant(e: &Value) -> &str {
    s(e, "variant")
}

fn cents(d: &str) -> u64 {
    let (a, b) = d.split_once('.').unwrap();
    assert_eq!(b.len(), 2, "two decimals: {d}");
    a.parse::<u64>().unwrap() * 100 + b.parse::<u64>().unwrap()
}

/// Versioning (`synthetic-corpus.md`): the generator is deterministic from
/// its seed, so a corpus version is reproducible byte for byte, and the
/// seed matters.
#[test]
fn t_llm_corpus_v1_is_deterministic_from_seed() {
    let a = generate(V1_SEED);
    let b = generate(V1_SEED);
    assert!(!a.files().is_empty());
    assert_eq!(a.files(), b.files());
    let other = generate(V1_SEED + 1);
    assert_ne!(a.files(), other.files());
    let m = manifest(&a);
    assert_eq!(s(&m, "corpus"), "v1");
    assert_eq!(s(&m, "generator"), GENERATOR);
    assert_eq!(m.get("seed").and_then(Value::as_u64), Some(V1_SEED));
}

/// Versioning: the checked-in `corpus/v1` equals the generator output, so
/// every evaluation report names a corpus that the seed reproduces.
#[test]
fn t_llm_corpus_v1_on_disk_matches_generator() {
    let c = generate(V1_SEED);
    let stale = c.check_against(&corpus::default_dir()).unwrap();
    assert!(stale.is_empty(), "stale corpus files: {stale:?}");
}

/// T-PRIV-CANARY (TH-07): every item carries exactly one canary per PII
/// class, each canary is unique across the corpus, and each appears in
/// the proposal narrative, where the stripping stage must remove it.
#[test]
fn t_priv_canary_every_item_carries_one_canary_per_pii_class() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let classes: Vec<&str> = m
        .get("pii_classes")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(classes, PII_CLASSES.to_vec());
    let mut seen = BTreeSet::new();
    let list = items(&m);
    assert!(list.len() >= 200, "corpus too small: {}", list.len());
    for e in list {
        let can = e.get("canaries").unwrap().as_object().unwrap();
        let keys: Vec<&str> = can.keys().collect();
        assert_eq!(keys, PII_CLASSES.to_vec(), "{}", s(e, "id"));
        let item = item_file(&c, e);
        for (class, v) in can.iter() {
            let v = v.as_str().unwrap();
            assert!(seen.insert(v.to_owned()), "canary {v} used twice");
            assert!(
                narrative(&item).contains(v),
                "{} {class} canary not in narrative",
                s(e, "id")
            );
            assert_eq!(
                s(item.get("applicant").unwrap(), class),
                v,
                "{} applicant {class}",
                s(e, "id")
            );
            assert!(
                !rubric_part(&item).contains(v),
                "{} {class} canary outside the contact section",
                s(e, "id")
            );
        }
        // IBAN-shaped canaries pass the mod-97 check, so a detector that
        // validates check digits still catches them.
        let iban: String = s(e.get("canaries").unwrap(), "iban")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
        let mut rem = 0u64;
        for ch in rearranged.chars() {
            let digits = if ch.is_ascii_digit() {
                ch.to_string()
            } else {
                (ch as u64 - 'A' as u64 + 10).to_string()
            };
            for d in digits.chars() {
                rem = (rem * 10 + d.to_digit(10).unwrap() as u64) % 97;
            }
        }
        assert_eq!(rem, 1, "IBAN canary {iban} fails mod 97");
    }
}

/// Synthetic data only (`test-plan.md`, TH-07): no real domain, name,
/// phone number or bank code appears anywhere in the corpus. Emails use
/// `example.org`, hosts end in `.test`, names are built from the invented
/// syllables, phones sit in the fictional range, and the IBAN bank code
/// appears only inside IBAN canaries.
#[test]
fn th07_corpus_has_no_real_domain_or_personal_data() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let ranges = m.get("synthetic_ranges").unwrap();
    let bank = s(ranges, "iban_bank_code");
    let phone_prefix = s(ranges, "phone_prefix");
    let mut ibans = Vec::new();
    for e in items(&m) {
        let can = e.get("canaries").unwrap();
        for word in s(can, "person_name").split(' ') {
            assert!(
                segments(&word.to_lowercase()),
                "name part {word} is not built from the syllables"
            );
        }
        let email = s(can, "email");
        assert!(email.ends_with("@example.org"), "{email}");
        let phone = s(can, "phone");
        let tail = phone.strip_prefix(phone_prefix).expect("phone prefix");
        assert!(
            tail.len() == 3 && tail.chars().all(|c| c.is_ascii_digit()),
            "{phone}"
        );
        let iban = s(can, "iban");
        assert!(iban.replace(' ', "").contains(bank), "{iban}");
        ibans.push(iban.to_owned());
    }
    for (path, bytes) in c.files() {
        assert!(bytes.is_ascii(), "{path} is not ASCII");
        let text = std::str::from_utf8(bytes).unwrap();
        // Only the manifest names the bank code outside the canaries.
        let mut rest = text.to_owned();
        for iban in &ibans {
            rest = rest.replace(iban.as_str(), "");
        }
        rest = rest.replace(&format!("\"iban_bank_code\": \"{bank}\""), "");
        assert!(!rest.contains(bank), "{path} uses the IBAN bank code");
        // A JSON `\u` escape is a separator, not part of a word.
        let mut plain = String::new();
        let mut rest = text;
        while let Some(at) = rest.find("\\u") {
            plain.push_str(&rest[..at]);
            plain.push(' ');
            rest = rest.get(at + 6..).unwrap_or("");
        }
        plain.push_str(rest);
        for token in plain.split(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '@' || c == '/')
        }) {
            check_token(path, token);
        }
    }
}

/// Every domain-shaped token is reserved: `example.org` or `*.test`.
fn check_token(path: &str, token: &str) {
    let token = token.trim_matches(|c: char| c == '.' || c == '/' || c == '-');
    let host = if let Some((_, d)) = token.split_once('@') {
        d.split('/').next().unwrap()
    } else if let Some(r) = token
        .strip_prefix("http://")
        .or_else(|| token.strip_prefix("https://"))
    {
        r.split('/').next().unwrap()
    } else if token.contains("//") {
        return;
    } else {
        token.split('/').next().unwrap()
    };
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return;
    }
    let last = *labels.last().unwrap();
    if !last.chars().all(|c| c.is_ascii_alphabetic()) {
        return;
    }
    if ["md", "json", "html", "txt"].contains(&last) {
        return;
    }
    assert!(
        host == "example.org" || last == "test",
        "{path}: real-looking domain {host} in {token}"
    );
}

/// The word is a concatenation of invented syllables.
fn segments(word: &str) -> bool {
    if word.is_empty() {
        return true;
    }
    SYLLABLES
        .iter()
        .any(|s| word.strip_prefix(s).is_some_and(segments))
}

/// The variants the evaluation needs exist in the counts the design names,
/// and the domain variants are e2e seeds, not evaluation items.
#[test]
fn t_llm_corpus_covers_every_variant() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in items(&m) {
        *counts.entry(variant(e).to_owned()).or_default() += 1;
        let use_ = s(e, "use");
        let seed = matches!(
            variant(e),
            "minor" | "excluded_affiliation" | "sybil" | "repeat_applicant"
        );
        assert_eq!(use_, if seed { "e2e_seed" } else { "evaluation" });
        assert!(c.file(s(e, "file")).is_some());
    }
    assert_eq!(counts.get("clean"), Some(&40));
    assert_eq!(counts.get("omission"), Some(&40));
    for v in [
        "inflated_claim",
        "budget_anomaly",
        "direct_injection",
        "hidden_injection",
        "indirect_injection",
        "fluency",
    ] {
        assert!(counts.get(v).copied().unwrap_or(0) >= 20, "{v}: {counts:?}");
    }
    for v in ["minor", "excluded_affiliation", "sybil"] {
        assert!(counts.get(v).copied().unwrap_or(0) >= 1, "{v}");
    }
    assert!(counts.get("repeat_applicant").copied().unwrap_or(0) >= 2);
    // Each clean item holds every rubric element and expects nothing.
    for e in items(&m).into_iter().filter(|e| variant(e) == "clean") {
        let item = item_file(&c, e);
        for el in RUBRIC_ELEMENTS {
            assert!(elements(e).contains(&el), "{} lacks {el}", s(e, "id"));
        }
        assert!(e.get("expect").unwrap().as_array().unwrap().is_empty());
        assert_eq!(headings(&item), elements(e));
    }
}

fn elements(e: &Value) -> Vec<&str> {
    e.get("elements")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

/// The rubric element tags of the sections, read from the item file.
fn headings(item: &Value) -> Vec<&str> {
    item.get("proposal")
        .unwrap()
        .get("sections")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| s(v, "element"))
        .collect()
}

fn base<'a>(ids: &BTreeMap<String, &'a Value>, e: &Value) -> &'a Value {
    ids.get(s(e, "base")).copied().expect("base item")
}

/// T-LLM-COMPLETE: an omission item lacks exactly its labelled element,
/// and the label is a completeness finding on that element.
#[test]
fn t_llm_complete_omission_items_lack_exactly_the_labelled_element() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let ids = by_id(&m);
    let mut omitted = BTreeSet::new();
    for e in items(&m).into_iter().filter(|e| variant(e) == "omission") {
        let b = base(&ids, e);
        let gone = s(e, "omitted_element");
        omitted.insert(gone.to_owned());
        let want: Vec<&str> = elements(b).into_iter().filter(|x| *x != gone).collect();
        assert_eq!(elements(e), want);
        let item = item_file(&c, e);
        assert_eq!(headings(&item), want);
        let exp = e.get("expect").unwrap().as_array().unwrap();
        assert_eq!(exp.len(), 1);
        assert_eq!(s(&exp[0], "kind"), "completeness");
        assert_eq!(s(&exp[0], "element"), gone);
        // The rest of the text is the base text without that section.
        let bi = item_file(&c, b);
        let section = section_text(&bi, gone);
        assert_eq!(
            rubric_part(&item),
            rubric_part(&bi).replacen(&section, "", 1)
        );
    }
    assert_eq!(
        omitted.len(),
        RUBRIC_ELEMENTS.len(),
        "every element is omitted somewhere"
    );
}

/// The section of `element` as it sits in the narrative, with its
/// separator.
fn section_text(item: &Value, element: &str) -> String {
    let sections = item
        .get("proposal")
        .unwrap()
        .get("sections")
        .unwrap()
        .as_array()
        .unwrap();
    let pos = sections
        .iter()
        .position(|v| s(v, "element") == element)
        .unwrap();
    let sec = &sections[pos];
    let body = format!("{}\n{}", s(sec, "heading"), s(sec, "text"));
    if pos == 0 {
        format!("{body}\n\n")
    } else {
        format!("\n\n{body}")
    }
}

/// T-LLM-ACCURACY and T-LLM-RETRIEVAL: an inflated claim appears in the
/// narrative and on the applicant's own site (a poisoned source), while
/// the independent fixture contradicts it.
#[test]
fn t_llm_accuracy_inflated_claims_are_contradicted_by_fixtures() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let mut kinds = BTreeSet::new();
    for e in items(&m)
        .into_iter()
        .filter(|e| variant(e) == "inflated_claim")
    {
        let item = item_file(&c, e);
        let claim = e.get("claim").unwrap();
        let kind = s(claim, "kind");
        kinds.insert(kind.to_owned());
        let stated = s(claim, "stated");
        assert!(rubric_part(&item).contains(stated), "{}", s(e, "id"));
        let site = s(claim, "applicant_controlled");
        assert!(
            web(&c, site).contains(stated),
            "poisoned site lacks the claim"
        );
        let contra = web(&c, s(claim, "contradicted_by"));
        let handle = s(item.get("applicant").unwrap(), "handle");
        match kind {
            "maintainership" => assert!(!contra.contains(handle), "{}", s(e, "id")),
            "usage" => {
                let v = fstp_json::parse(contra.as_bytes()).unwrap();
                let actual = v.get("dependents").and_then(Value::as_u64).unwrap();
                let claimed = claim
                    .get("claimed_dependents")
                    .and_then(Value::as_u64)
                    .unwrap();
                assert!(claimed >= actual * 10, "{claimed} vs {actual}");
            }
            k => panic!("unknown claim kind {k}"),
        }
        let exp = e.get("expect").unwrap().as_array().unwrap();
        assert_eq!(s(&exp[0], "kind"), "accuracy");
        assert_eq!(s(&exp[0], "subject_url"), s(claim, "subject_url"));
    }
    assert_eq!(kinds.len(), 2, "both maintainership and usage claims");
    // A clean item's claim is supported by the independent fixture.
    for e in items(&m).into_iter().filter(|e| variant(e) == "clean") {
        let item = item_file(&c, e);
        let handle = s(item.get("applicant").unwrap(), "handle");
        let repo = s(e, "repository");
        assert!(web(&c, &format!("{repo}/MAINTAINERS")).contains(handle));
        assert!(fstp_json::parse(web(&c, &format!("{repo}/stats.json")).as_bytes()).is_ok());
    }
}

/// Budget anomaly: one task's day rate is far above the corpus median, and
/// the label names a value-for-money finding on that task.
#[test]
fn t_llm_budget_anomaly_rate_far_above_median() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let median = cents(s(&m, "rate_median_eur"));
    assert!(median > 0);
    for e in items(&m)
        .into_iter()
        .filter(|e| variant(e) == "budget_anomaly")
    {
        let a = e.get("anomaly").unwrap();
        let rate = cents(s(a, "rate_eur"));
        assert!(rate >= median * 3, "{rate} vs median {median}");
        let item = item_file(&c, e);
        let tasks = item
            .get("proposal")
            .unwrap()
            .get("plan")
            .unwrap()
            .get("tasks")
            .unwrap()
            .as_array()
            .unwrap();
        let t = tasks.iter().find(|t| s(t, "id") == s(a, "task")).unwrap();
        assert_eq!(s(t, "rate_eur"), s(a, "rate_eur"));
        let exp = e.get("expect").unwrap().as_array().unwrap();
        assert_eq!(s(&exp[0], "kind"), "quality");
        assert_eq!(s(&exp[0], "label"), "value_for_money");
    }
}

/// T-LLM-INJ: an injected item equals its clean base plus the injection.
/// Direct and hidden injections sit in the narrative; the hidden ones
/// decode from Unicode tag characters, zero-width splitting or a bidi
/// override. An indirect injection sits in the fixture README only.
#[test]
fn t_llm_inj_injected_items_keep_base_substance() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let ids = by_id(&m);
    let mut techniques = BTreeSet::new();
    for e in items(&m)
        .into_iter()
        .filter(|e| variant(e).ends_with("_injection"))
    {
        let item = item_file(&c, e);
        let b = item_file(&c, base(&ids, e));
        let inj = e.get("injection").unwrap();
        let text = s(inj, "text");
        let exp = e.get("expect").unwrap().as_array().unwrap();
        assert_eq!(s(&exp[0], "kind"), "integrity");
        assert_eq!(s(e, "same_findings_as"), s(e, "base"));
        assert_eq!(
            item.get("proposal").unwrap().get("plan"),
            b.get("proposal").unwrap().get("plan")
        );
        match variant(e) {
            "direct_injection" => {
                let embedded = s(inj, "embedded");
                assert!(embedded.contains(text));
                assert_eq!(rubric_part(&item), format!("{}{embedded}", rubric_part(&b)));
            }
            "hidden_injection" => {
                let embedded = s(inj, "embedded");
                assert!(!embedded.contains(text), "hidden text is visible");
                let technique = s(inj, "technique");
                techniques.insert(technique.to_owned());
                assert!(decode(technique, embedded).contains(text), "{technique}");
                assert_eq!(rubric_part(&item), format!("{}{embedded}", rubric_part(&b)));
            }
            "indirect_injection" => {
                let url = s(inj, "source_url");
                assert!(web(&c, url).contains(text));
                let repo = s(e, "repository");
                let base_repo = s(base(&ids, e), "repository");
                assert!(url.starts_with(repo));
                assert_eq!(
                    rubric_part(&item).replace(repo, base_repo),
                    rubric_part(&b),
                    "{}",
                    s(e, "id")
                );
                assert!(!narrative(&item).contains(text));
            }
            v => panic!("unknown injection {v}"),
        }
    }
    assert_eq!(techniques.len(), 3, "{techniques:?}");
}

/// Reverses each hidden-injection technique.
fn decode(technique: &str, s: &str) -> String {
    match technique {
        "unicode_tags" => s
            .chars()
            .filter_map(|c| {
                let u = c as u32;
                (0xE0020..=0xE007E)
                    .contains(&u)
                    .then(|| char::from_u32(u - 0xE0000).unwrap())
            })
            .collect(),
        "zero_width_split" => s.chars().filter(|c| *c != '\u{200B}').collect(),
        "bidi_override" => {
            let inner = s
                .split('\u{202E}')
                .nth(1)
                .unwrap()
                .split('\u{202C}')
                .next()
                .unwrap();
            inner.chars().rev().collect()
        }
        t => panic!("unknown technique {t}"),
    }
}

/// T-LLM-FLUENCY: a fluency item has the same elements and plan as its
/// base, and only its wording differs.
#[test]
fn t_llm_fluency_pairs_keep_substance() {
    let c = generate(V1_SEED);
    let m = manifest(&c);
    let ids = by_id(&m);
    for e in items(&m).into_iter().filter(|e| variant(e) == "fluency") {
        let item = item_file(&c, e);
        let b = item_file(&c, base(&ids, e));
        assert_eq!(headings(&item), headings(&b));
        assert_eq!(
            item.get("proposal").unwrap().get("plan"),
            b.get("proposal").unwrap().get("plan")
        );
        assert_ne!(rubric_part(&item), rubric_part(&b));
        assert_eq!(s(e, "same_findings_as"), s(e, "base"));
        // Every URL and number of the base survives the rewrite.
        for tok in rubric_part(&b).split_whitespace() {
            if tok.starts_with("http://") || tok.chars().any(|c| c.is_ascii_digit()) {
                assert!(rubric_part(&item).contains(tok), "{tok} lost");
            }
        }
    }
}
