//! I-84 `i84_principal_has_no_public_fields`: compile-fail twins for
//! [`Principal`](crate::Principal) (M4 design sections 3.6 and 8.4).
//!
//! This module holds doc comments only. It is compiled under
//! `cfg(doctest)` alone, so it adds nothing to the library.
//!
//! Only the checked constructors build a `Principal`, and only
//! `fstp-api-core` calls them. So no code outside this crate may set a
//! field, whether through a struct literal, a struct update or an
//! assignment. Each forbidden line gets a `compile_fail` doctest and a
//! `no_run` twin that differs only in that line and must compile. The
//! pinned rustdoc ignores error codes, so the twin keeps each pair from
//! passing on a typo.
//!
//! A struct update keeps every other field from `Principal::anonymous()`.
//! So each `compile_fail` block fails only because the named field is
//! private, never because another field is missing.
//!
//! # No struct update sets `tenant_admin`
//!
//! ```compile_fail
//! use fstp_access::Principal;
//! let p = Principal { tenant_admin: true, ..Principal::anonymous() };
//! let _ = p.tenant_admin();
//! ```
//!
//! ```no_run
//! use fstp_access::Principal;
//! let p = Principal::anonymous();
//! let _ = p.tenant_admin();
//! ```
//!
//! # No struct update sets `account`
//!
//! ```compile_fail
//! use fstp_access::Principal;
//! use fstp_domain::id::AccountId;
//! let p = Principal { account: Some(AccountId::from_raw(7)), ..Principal::anonymous() };
//! let _ = p.account();
//! ```
//!
//! ```no_run
//! use fstp_access::Principal;
//! use fstp_domain::id::AccountId;
//! let _ = AccountId::from_raw(7);
//! let p = Principal::anonymous();
//! let _ = p.account();
//! ```
//!
//! # No struct update sets `via`
//!
//! ```compile_fail
//! use fstp_access::Principal;
//! use fstp_domain::Via;
//! let p = Principal { via: Via::Mcp, ..Principal::anonymous() };
//! let _ = p.via();
//! ```
//!
//! ```no_run
//! use fstp_access::Principal;
//! use fstp_domain::Via;
//! let _ = Via::Mcp;
//! let p = Principal::anonymous();
//! let _ = p.via();
//! ```
//!
//! # No assignment changes `tenant_admin`
//!
//! ```compile_fail
//! use fstp_access::Principal;
//! let mut p = Principal::anonymous();
//! p.tenant_admin = true;
//! let _ = p.tenant_admin();
//! ```
//!
//! ```no_run
//! use fstp_access::Principal;
//! let mut p = Principal::anonymous();
//! let _ = &mut p;
//! let _ = p.tenant_admin();
//! ```
//!
//! # No assignment changes `via`
//!
//! ```compile_fail
//! use fstp_access::Principal;
//! use fstp_domain::Via;
//! let mut p = Principal::anonymous();
//! p.via = Via::Mcp;
//! let _ = p.via();
//! ```
//!
//! ```no_run
//! use fstp_access::Principal;
//! use fstp_domain::Via;
//! let mut p = Principal::anonymous();
//! let _ = (&mut p, Via::Mcp);
//! let _ = p.via();
//! ```
