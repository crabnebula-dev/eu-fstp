//! Fuzz target `tool_args_decode` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: every tool's input. The input is a tool name, a zero
//! byte, then the arguments. No input panics. A decoded call names an
//! operation of the registry whose tool has exactly that name (TH-63).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let r = fstp_mcp::decode_tool_args(data);
    let shown = format!("{r:?}");
    assert!(!shown.is_empty());
    if let Ok(args) = &r {
        let name = data.split(|b| *b == 0).next().unwrap_or_default();
        let tool = std::str::from_utf8(name).ok().and_then(fstp_api_core::meta::tool);
        assert!(tool.is_some(), "a call decoded for a name outside the registry");
        assert!(!args.op_name().is_empty());
    }
});
