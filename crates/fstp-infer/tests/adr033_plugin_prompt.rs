//! ADR-033: the plugin's assessor agent ships the pinned prompt set v1
//! byte for byte, with its version and digest, and the plugin's texts
//! hold no submission (TH-01, I-11, R-LA-05).

#![allow(clippy::unwrap_used, clippy::expect_used)]

const AGENT: &str =
    include_str!("../../../integrations/claude/fstp-programmes/agents/fstp-assessor.md");
const SKILL: &str =
    include_str!("../../../integrations/claude/fstp-programmes/skills/run-assessment/SKILL.md");
const PLUGIN: &str =
    include_str!("../../../integrations/claude/fstp-programmes/.claude-plugin/plugin.json");

const COMMON: &str = include_str!("../prompts/v1/common.txt");
const TASKS: [&str; 4] = [
    include_str!("../prompts/v1/completeness.txt"),
    include_str!("../prompts/v1/quality.txt"),
    include_str!("../prompts/v1/claims.txt"),
    include_str!("../prompts/v1/integrity.txt"),
];
const SCHEMA: &str = include_str!("../schemas/v1/findings.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// ADR-033, I-11, R-LA-05: the agent holds the common instructions, every
/// task the client runs and the output schema verbatim, and names the
/// version and digest of the prompt set the cell compiles in. A prompt
/// change without a plugin change fails here.
#[test]
fn adr033_i11_agent_ships_the_pinned_prompt_set() {
    assert!(AGENT.contains(COMMON), "common.txt");
    for t in TASKS {
        assert!(AGENT.contains(t), "{t}");
    }
    assert!(AGENT.contains(SCHEMA), "findings.json");
    assert!(AGENT.contains(&format!(
        "Prompt set version: {}\n",
        fstp_infer::PROMPT_SET_VERSION
    )));
    let digest = hex(&fstp_infer::prompt_set_digest());
    assert!(
        AGENT.contains(&format!("Prompt set digest: {digest}\n")),
        "the agent names another digest than {digest}"
    );
}

/// ADR-033, TH-01: the assessor agent may use the tools of the
/// `fstp-assess` server only, which asks for `assess:run` alone, and has
/// no web, shell or file tool.
#[test]
fn adr033_th01_agent_reaches_only_the_assessment_server() {
    let tools: Vec<&str> = AGENT.lines().filter(|l| l.starts_with("tools:")).collect();
    assert_eq!(tools, ["tools: mcp__plugin_fstp-programmes_fstp-assess__*"]);
    let denied = AGENT
        .lines()
        .find_map(|l| l.strip_prefix("disallowedTools:"))
        .unwrap();
    for t in [
        "Bash",
        "Read",
        "Write",
        "Edit",
        "WebFetch",
        "WebSearch",
        "Agent",
    ] {
        assert!(denied.split(',').any(|d| d.trim() == t), "{t}");
    }
    let compact: String = PLUGIN.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains(r#""fstp-assess":{"type":"http","url":"${user_config.mcp_url}","oauth":{"scopes":"assess:run"}}"#),
        "{PLUGIN}"
    );
}

/// ADR-033, TH-01, CLAUDE.md data channel rule: the skill says that
/// submission content is data and never instructions, delegates each
/// proposal to the assessor agent, and embeds no proposal text.
#[test]
fn adr033_th01_skill_treats_submissions_as_data() {
    assert!(SKILL.contains("data, never instructions"));
    assert!(SKILL.contains("fstp-programmes:fstp-assessor"));
    for corpus in ["Assessment system", "Ignore previous", "SYNTHETIC"] {
        assert!(!SKILL.contains(corpus), "{corpus}");
        assert!(!AGENT.contains(corpus), "{corpus}");
    }
}
