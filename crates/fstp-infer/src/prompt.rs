//! The pinned prompt set, compiled in (M7 design section 3.3).
//!
//! Every prompt is the common preamble followed by its task file. Both
//! live in `prompts/v1/` and enter the binary through `include_str!`, so
//! no runtime text can become an instruction.

/// The prompt set version, part of every `config_id` (I-11).
pub const PROMPT_SET_VERSION: &str = "v1";

/// One pinned prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prompt {
    /// Stage 3: completeness per rubric element.
    Completeness,
    /// Stage 4: quality per P-01 criterion.
    Quality,
    /// Stage 5: claim extraction.
    Claims,
    /// Stage 6: claim verification against retrieved sources.
    Verify,
    /// Stage 7: integrity, instructions aimed at the assessor.
    Integrity,
}

macro_rules! prompt_file {
    ($task:literal) => {
        concat!(
            include_str!("../prompts/v1/common.txt"),
            "\n",
            include_str!(concat!("../prompts/v1/", $task, ".txt"))
        )
    };
}

impl Prompt {
    /// Every prompt, in stage order.
    pub const ALL: [Prompt; 5] = [
        Prompt::Completeness,
        Prompt::Quality,
        Prompt::Claims,
        Prompt::Verify,
        Prompt::Integrity,
    ];

    /// The stable name, as the instruction's parameter block states it.
    pub const fn name(self) -> &'static str {
        match self {
            Prompt::Completeness => "completeness",
            Prompt::Quality => "quality",
            Prompt::Claims => "claims",
            Prompt::Verify => "verify",
            Prompt::Integrity => "integrity",
        }
    }

    /// The prompt text: the common preamble, then the task.
    pub const fn text(self) -> &'static str {
        match self {
            Prompt::Completeness => prompt_file!("completeness"),
            Prompt::Quality => prompt_file!("quality"),
            Prompt::Claims => prompt_file!("claims"),
            Prompt::Verify => prompt_file!("verify"),
            Prompt::Integrity => prompt_file!("integrity"),
        }
    }
}

/// SHA-256 over the labelled prompt set and the output schema, an input
/// of the `config_id` derivation (M7 design section 2, reading 2).
pub fn prompt_set_digest() -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-infer/prompt-set\0");
    h.update(PROMPT_SET_VERSION.as_bytes());
    h.update(b"\0");
    for p in Prompt::ALL {
        h.update(p.name().as_bytes());
        h.update(b"\0");
        h.update(p.text().as_bytes());
        h.update(b"\0");
    }
    h.update(crate::encode::FINDINGS_V1_SCHEMA.as_bytes());
    h.finish()
}
