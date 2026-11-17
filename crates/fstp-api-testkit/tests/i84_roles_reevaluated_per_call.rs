//! I-84, M4 design section 3.6: an MCP call is judged by the roles the
//! caller holds at that call, from the bindings active then. A token
//! carries no roles. So ending a role binding between two MCP calls
//! refuses the second.
//!
//! The cell is the I-85 world behind one `ApiCore` of fake ports, with an
//! `fstp_mcp::McpServer` over it (`mcp_support`). The owner is the
//! programme manager of P1 and P2, and its agent holds a token with the
//! calls-read scope. Every call is a real `tools/call` of
//! `fstp_get_call_board` through the MCP server: call 1 of P1, or call 4
//! of P2. A tenant admin ends the owner's programme manager binding of a
//! programme through the engine port, as the roster does.
//!
//! Every account and text is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod mcp_support;

use fstp_api_core::Credential;
use fstp_api_core::meta::Scope;
use fstp_api_testkit::fake::fixture::{
    self, ADMIN, AGENT, CALL_ALLOWED, CALL_PUBLISH, OWNER, World,
};
use fstp_api_testkit::matrix::Observed;
use fstp_domain::Via;
use fstp_domain_testkit::r#gen::roster::{self, staff_bindings};
use fstp_engine::Command;
use fstp_mcp::{McpServer, Surface};
use fstp_prop::{StateMachine, check_machine};
use mcp_support::{McpCell, call, dec, obj, observed};

/// The tool every call sends.
const TOOL: &str = "fstp_get_call_board";

/// A programme of the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prog {
    /// P1, whose call 1 the board shows.
    P1,
    /// P2, whose call 4 the board shows.
    P2,
}

impl Prog {
    const fn index(self) -> usize {
        match self {
            Prog::P1 => 0,
            Prog::P2 => 1,
        }
    }

    const fn id(self) -> fstp_domain::id::ProgrammeId {
        match self {
            Prog::P1 => fixture::P1,
            Prog::P2 => fixture::P2,
        }
    }

    const fn call(self) -> fstp_domain::id::CallId {
        match self {
            Prog::P1 => CALL_PUBLISH,
            Prog::P2 => CALL_ALLOWED,
        }
    }
}

/// The cell, its MCP server and the agent's token.
struct Sut {
    cell: McpCell,
    server: McpServer,
    token: Vec<u8>,
    ends: u128,
}

impl Sut {
    fn over(world: &World) -> Sut {
        let cell = McpCell::over(world);
        let server = cell.server();
        let token = cell.token(OWNER, AGENT, [Scope::CallsRead]);
        Sut {
            cell,
            server,
            token,
            ends: 0,
        }
    }

    /// One `tools/call` of the board of `p`'s call through the MCP server.
    fn board(&self, p: Prog) -> Result<Observed, String> {
        let args = obj(vec![("call", dec(p.call().raw()))]);
        let r = call(
            &self.server,
            Surface::Mcp,
            Credential::Bearer(self.token.clone()),
            TOOL,
            &args,
        );
        observed(&r).map_err(|e| format!("{TOOL}: {e:?}"))
    }

    /// A tenant admin ends the owner's programme manager binding of `p`.
    fn end(&mut self, p: Prog) -> Result<(), String> {
        self.ends = self.ends.saturating_add(1);
        let now = self.cell.ports.clock.read();
        let binding = staff_bindings(p.id())[0];
        let end = roster::end(binding, now).cmd;
        let ctx = fixture::ctx(ADMIN, Via::Web, now, 84_000u128.saturating_add(self.ends));
        self.cell
            .ports
            .engine
            .environment(Command::Core(end), ctx)
            .map(|_| ())
            .map_err(|e| format!("ending the owner's binding of {p:?}: {e}"))
    }
}

/// Whether `o` is a refusal of the call itself, not a channel denial.
fn refused(o: &Observed) -> bool {
    matches!(o, Observed::Refused(_) | Observed::NotFound(_))
}

/// I-84, design section 3.6: two real MCP calls with the same token. The
/// first reads the board of P1's call. A tenant admin then ends the
/// owner's programme manager binding of P1, and the second call is
/// refused. The token still reads P2's board, so the refusal comes from
/// the roles judged at the call, not from the token.
#[test]
fn i84_roles_reevaluated_per_call_two_calls() {
    let world = fixture::pending_world().unwrap();
    let mut s = Sut::over(&world);
    assert_eq!(s.board(Prog::P1), Ok(Observed::Completed), "first call");
    s.end(Prog::P1).unwrap();
    let second = s.board(Prog::P1).unwrap();
    assert!(
        refused(&second),
        "the second call after the binding ended: {second:?}"
    );
    assert_eq!(s.board(Prog::P2), Ok(Observed::Completed), "P2 still");
}

/// The command of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    /// One MCP call of the board of the programme's call.
    Board(Prog),
    /// A tenant admin ends the owner's binding of the programme.
    End(Prog),
}

const CMDS: [Cmd; 4] = [
    Cmd::Board(Prog::P1),
    Cmd::Board(Prog::P2),
    Cmd::End(Prog::P1),
    Cmd::End(Prog::P2),
];

/// The machine: random MCP calls and binding ends on one cell, one token.
struct Roles {
    world: World,
}

impl StateMachine for Roles {
    /// Which of the owner's bindings ended, by [`Prog::index`].
    type Model = [bool; 2];
    type Sut = Sut;
    type Command = Cmd;
    type Output = Result<Option<Observed>, String>;

    fn init_model(&self) -> [bool; 2] {
        [false, false]
    }

    fn init_sut(&self) -> Sut {
        Sut::over(&self.world)
    }

    fn command(&self, g: &mut fstp_prop::Gen, _: &[bool; 2]) -> Cmd {
        *g.pick(&CMDS)
    }

    fn precondition(&self, model: &[bool; 2], cmd: &Cmd) -> bool {
        match cmd {
            Cmd::Board(_) => true,
            Cmd::End(p) => !model[p.index()],
        }
    }

    fn run(&self, sut: &mut Sut, cmd: &Cmd) -> Result<Option<Observed>, String> {
        match cmd {
            Cmd::Board(p) => sut.board(*p).map(Some),
            Cmd::End(p) => sut.end(*p).map(|()| None),
        }
    }

    fn next_state(&self, model: &mut [bool; 2], cmd: &Cmd) {
        if let Cmd::End(p) = cmd {
            model[p.index()] = true;
        }
    }

    fn postcondition(
        &self,
        model: &[bool; 2],
        cmd: &Cmd,
        output: &Result<Option<Observed>, String>,
    ) -> Result<(), String> {
        let o = output.as_ref().map_err(|e| format!("I-84: {e}"))?;
        let Cmd::Board(p) = cmd else {
            return Ok(());
        };
        let Some(o) = o else {
            return Err("I-84: a call gave no outcome".to_owned());
        };
        let ended = model[p.index()];
        match (ended, o) {
            (false, Observed::Completed) => Ok(()),
            (true, o) if refused(o) => Ok(()),
            (_, o) => Err(format!(
                "I-84: the board of {p:?} with the binding {} gave {o:?}",
                if ended { "ended" } else { "active" }
            )),
        }
    }

    fn max_commands(&self) -> usize {
        12
    }
}

/// I-84, design section 3.6: random sequences of MCP calls and binding
/// ends on one cell with one token. Every call through the MCP server is
/// judged by the bindings active at that call: the board of a programme
/// reads while the owner's binding there is active, and is refused once
/// it ended, while the other programme's board still reads.
#[test]
fn i84_roles_reevaluated_per_call() {
    let world = fixture::pending_world().unwrap();
    check_machine("i84_roles_reevaluated_per_call", &Roles { world });
}
