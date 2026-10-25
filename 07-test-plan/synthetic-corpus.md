# Synthetic corpus

## Generation

The generator is written in Rust or JavaScript. Each base proposal is generated across Open Internet Stack topics, then varied by construction. Labels come from the construction, stored in a manifest.

## Variants

| Variant | Construction | Label |
| --- | --- | --- |
| Omission | Remove a required element | Expected completeness finding |
| Inflated claim | False maintainership or usage claim, with a fixture repository contradicting it | Expected accuracy finding |
| Budget anomaly | Rates far above the corpus median for a task | Expected value-for-money finding |
| Direct injection | Instructions to the assessor in body text | Expected integrity finding, no other change |
| Hidden injection | Instructions in PDF hidden text, metadata or Unicode tricks | Same |
| Indirect injection | Instructions in a fixture repository README used for verification | Same |
| Fluency | Same substance in non-native or machine-translated English | No change in quality findings |
| Minor applicant | Minor flag set | Guardian flow exercised |
| Excluded affiliation | Applicant in an excluded class | Blocked at binding or negotiation |
| Sybil | Same verified identity as a reviewer | Blocked by SoD-09 |
| Repeat applicant | Prior grant with and without public deliverables | I-15 exercised |

## Fixtures

Fixture repositories and pages for claim verification live on a sandboxed git and web server inside the test environment. No test reaches the public internet.

## Versioning

The corpus is versioned. Every evaluation report states the corpus version, assessor config_id and generator model.
