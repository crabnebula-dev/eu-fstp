//! Identifiers supplied by the shell, and content digests (design section 2.1).
//!
//! - The shell draws every entity id and passes it inside the command. M3
//!   draws them with `fstp_crypto::random_array`. Tests use small fixed pools.
//! - `decide` refuses an id that is already taken, so two orders of the same
//!   creations give the same state.
//! - No id carries identity data. The vault alone links accounts to people.
//! - In JSON, every `u128` id is a decimal string, because RFC 8785 numbers
//!   are exact only up to 2^53 (lane L-CODEC).

use std::num::NonZeroU32;

macro_rules! id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

id!(
    /// A programme of one tenant (R-PC-01).
    ProgrammeId,
    /// A call of a programme.
    CallId,
    /// One immutable version of a programme's policy (I-12, I-23).
    PolicyVersionId,
    /// A tenant account. A "person" in the spec means a tenant account (`SPEC/00-scope.md`).
    AccountId,
    /// One role binding.
    BindingId,
    /// A proposal.
    ProposalId,
    /// One plan version of a proposal.
    PlanVersionId,
    /// A milestone of a plan.
    MilestoneId,
    /// A deliverable of a milestone.
    DeliverableId,
    /// One reviewer, IRC or amendment assignment.
    AssignmentId,
    /// A recorded decision.
    DecisionId,
    /// An amendment of a grant.
    AmendmentId,
    /// A payment request.
    RequestId,
    /// A line of a payment request.
    LineId,
    /// An organisation, as recorded on a committee binding (I-34).
    OrganisationId,
    /// A pinned LLM configuration: model, prompt and rubric (I-11, R-LA-05).
    LlmConfigId,
    /// A free-text item held outside ledger bodies.
    TextId,
    /// A scoring criterion of P-01.
    CriterionId,
    /// A knock-out criterion of P-09.
    KnockOutCriterionId,
    /// An excluded affiliation class of P-13, matched by the vault.
    ClassId,
    /// A proximity list of P-38, held by the vault.
    ProximityListId,
    /// An activity type of the closed list in P-55.
    ActivityTypeId,
    /// A contract, as reported by the M5 contract port.
    ContractId,
);

/// Idempotency key of one command, from the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandId([u8; 16]);

impl CommandId {
    /// The key with these bytes.
    pub const fn from_bytes(b: [u8; 16]) -> CommandId {
        CommandId(b)
    }

    /// The raw bytes.
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A reviewer handle under P-11 anonymous. It is never derived from an
/// account id and never reused across proposals or calls (R-AN-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle([u8; 16]);

impl Handle {
    /// The handle with these bytes, drawn by the shell.
    pub const fn from_bytes(b: [u8; 16]) -> Handle {
        Handle(b)
    }

    /// The raw bytes.
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A vault epoch. Every vault answer carries one (`SPEC/03-architecture/overview.md` NOTE 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultEpoch(u64);

impl VaultEpoch {
    /// The epoch before any vault fact.
    pub const GENESIS: VaultEpoch = VaultEpoch(0);

    /// The epoch with raw value `r`.
    pub const fn from_raw(r: u64) -> VaultEpoch {
        VaultEpoch(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Publication order of a call within its programme, from 1.
/// Cooling-off bars compare these numbers (`SPEC/02-domain/roles-and-sod.md` Cooling-off).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallSeq(NonZeroU32);

impl CallSeq {
    /// The first call published in a programme.
    pub const FIRST: CallSeq = CallSeq(NonZeroU32::MIN);

    /// The sequence number `n`.
    pub const fn new(n: NonZeroU32) -> CallSeq {
        CallSeq(n)
    }

    /// The number as an integer.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The next sequence number, or `None` on overflow.
    pub const fn next(self) -> Option<CallSeq> {
        match self.0.checked_add(1) {
            Some(n) => Some(CallSeq(n)),
            None => None,
        }
    }
}

/// A content digest, computed outside the core. M3 uses `fstp-crypto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// The digest with these bytes.
    pub const fn from_bytes(b: [u8; 32]) -> ContentDigest {
        ContentDigest(b)
    }

    /// The raw bytes.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Free text held outside ledger bodies (design section 5.2).
/// Reasons, rationale, concerns and plan text travel only as references.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRef {
    id: TextId,
    digest: ContentDigest,
}

impl TextRef {
    /// A reference to the text `id` with content digest `digest`.
    pub const fn new(id: TextId, digest: ContentDigest) -> TextRef {
        TextRef { id, digest }
    }

    /// The text id.
    pub const fn id(self) -> TextId {
        self.id
    }

    /// The content digest.
    pub const fn digest(self) -> ContentDigest {
        self.digest
    }
}
