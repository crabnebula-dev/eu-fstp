//! Support shared by the `fstp-html` integration tests (lane W1d, test
//! author).
//!
//! Every module here is an independent reference, written from the spec
//! text and the M4 design before the production code exists:
//!
//! - `chars`: the character rules every context shares, and hostile
//!   string generators.
//! - `reference`: a parser for the writer's HTML subset. It is the oracle
//!   for escaping, well-formedness and the render trace.
//! - `serial`: a serializer into that subset, with random but valid
//!   spelling choices. It feeds the well-formedness checker.
//! - `message`: the catalogue message grammar, a reference formatter and
//!   the catalogue fixtures (R-NF-04, I-72).
//! - `lang`: the `Accept-Language` grammar and locale negotiation.
//! - `spec`: the page model, its generators, and the expected tree and
//!   trace of a page.
//! - `bind`: the one seam to the writer, catalogue and sink API, which
//!   the design does not name yet.
//! - `cases`: fixed documents on both sides of the subset's boundary.
//! - `corpus`: the reader of the shared corpora in `testdata/`.
//! - `route`: the route map of the voyager design as a reference, with
//!   route generators (lane j3, ADR-015).

#![allow(dead_code)]

pub(crate) mod bind;
pub(crate) mod cases;
pub(crate) mod chars;
pub(crate) mod corpus;
pub(crate) mod lang;
pub(crate) mod message;
pub(crate) mod reference;
pub(crate) mod route;
pub(crate) mod serial;
pub(crate) mod spec;
