//! Fuzz target `guide_scan` of `fstp-creator` (I-51, I-52, M4 design
//! section 9).
//!
//! Design checks: the Guide scan is total over any template text, any
//! required text and any set of gaps. Every missing section is a heading
//! of the required text and not of the template, and every unresolved
//! placeholder occurs in the template.

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (head, rest) = data.split_at(data.len().min(2));
    let cut = head.first().map_or(0, |b| usize::from(*b)).min(rest.len());
    let (template, required) = rest.split_at(cut);
    let template = String::from_utf8_lossy(template);
    let required = String::from_utf8_lossy(required);
    let gaps = head.get(1).copied().unwrap_or(0);
    let unset: BTreeSet<fstp_programme::FieldId> = fstp_programme::FieldId::ALL
        .iter()
        .enumerate()
        .filter(|(i, _)| (usize::from(gaps) >> (i % 8)) & 1 == 1)
        .map(|(_, f)| *f)
        .collect();
    let scan = fstp_creator::guide_scan(&template, &required, &unset);
    for s in &scan.sections_missing {
        assert!(required.lines().any(|l| l.trim_end() == s));
        assert!(!template.lines().any(|l| l.trim_end() == s));
    }
    for p in &scan.unresolved {
        assert!(
            template.contains(p.as_str()),
            "{p:?} is not in the template"
        );
    }
});
