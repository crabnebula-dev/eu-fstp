//! Running one case: catching panics and silencing the panic hook.
//!
//! The panic hook is process-global and tests run on many threads. Swapping
//! the hook per run would race between threads. Instead the harness installs a
//! delegating hook once. It stays quiet only on threads that are inside a
//! property run, where it captures the message and location instead. On every
//! other thread it calls the hook that was installed before it. A [`Silence`]
//! guard marks the current thread and restores normal output when dropped.
//!
//! The hook is thread-local in effect. A thread that a property spawns is not
//! silenced, so its panic prints through the previous hook, and its message
//! stays on that thread. [`std::thread::scope`] then panics on the property
//! thread with "a scoped thread panicked", and the report explains this.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use crate::generator::{Gen, Invalid, Stop};

/// The panic message of std::thread::scope when a scoped thread panicked.
const SCOPED_THREAD_PANIC: &str = "a scoped thread panicked";

/// What the hook captured about the last panic on a silenced thread.
struct Captured {
    /// The panic message, when the payload is a string.
    message: Option<String>,
    /// Where the panic happened.
    location: Option<String>,
}

thread_local! {
    static SILENT: Cell<bool> = const { Cell::new(false) };
    static CAPTURED: RefCell<Option<Captured>> = const { RefCell::new(None) };
}

static HOOK: Once = Once::new();

/// Installs the delegating panic hook, once per process.
pub(crate) fn install_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if SILENT.try_with(Cell::get).unwrap_or(false) {
                let captured = Captured {
                    message: info.payload_as_str().map(str::to_owned),
                    location: info.location().map(ToString::to_string),
                };
                let _ = CAPTURED.try_with(|slot| {
                    if let Ok(mut slot) = slot.try_borrow_mut() {
                        *slot = Some(captured);
                    }
                });
            } else {
                previous(info);
            }
        }));
    });
}

/// Silences the panic hook on this thread until dropped.
pub(crate) struct Silence {
    previous: bool,
}

impl Silence {
    /// Starts silencing this thread. Installs the hook if needed.
    pub(crate) fn begin() -> Silence {
        install_hook();
        let previous = SILENT.try_with(|s| s.replace(true)).unwrap_or(false);
        Silence { previous }
    }
}

impl Drop for Silence {
    fn drop(&mut self) {
        let previous = self.previous;
        let _ = SILENT.try_with(|s| s.set(previous));
    }
}

/// Returns whether the panic hook is silenced on this thread.
#[cfg(test)]
pub(crate) fn is_silenced() -> bool {
    SILENT.try_with(Cell::get).unwrap_or(false)
}

/// Result of running one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// The property returned `Ok(())`.
    Pass,
    /// The case was discarded.
    Invalid(Invalid),
    /// The property returned an error or panicked.
    Fail(String),
}

/// Runs `prop` once against `g`, catching panics.
pub(crate) fn execute<F>(prop: &F, g: &mut Gen) -> Status
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    let _ = CAPTURED.try_with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = None;
        }
    });
    let result = catch_unwind(AssertUnwindSafe(|| prop(g)));
    if let Some(why) = g.invalid() {
        return Status::Invalid(why);
    }
    if let Some(message) = g.forced_failure() {
        return Status::Fail(message.to_owned());
    }
    match result {
        Ok(Ok(())) => Status::Pass,
        Ok(Err(message)) => Status::Fail(message),
        Err(payload) => match payload.downcast::<Stop>() {
            Ok(stop) => match *stop {
                Stop::Invalid(why) => Status::Invalid(why),
                Stop::Fail(message) => Status::Fail(message),
            },
            Err(other) => Status::Fail(panic_text(other.as_ref())),
        },
    }
}

/// Builds the failure message for a panic.
///
/// The payload decides the message. The hook's capture adds the location only
/// when its message matches the payload. A capture can be stale: a property
/// may catch one panic and then re-raise another with `resume_unwind`, which
/// does not call the hook.
fn panic_text(payload: &(dyn Any + Send)) -> String {
    let captured = CAPTURED
        .try_with(|slot| slot.try_borrow_mut().ok().and_then(|mut s| s.take()))
        .ok()
        .flatten();
    let message = if let Some(s) = payload.downcast_ref::<&str>() {
        Some(*s)
    } else {
        payload.downcast_ref::<String>().map(String::as_str)
    };
    let location = captured
        .filter(|c| c.message.as_deref() == message)
        .and_then(|c| c.location);
    let text = message.unwrap_or("non-string panic payload");
    let mut out = match location {
        Some(loc) => format!("panicked: {text} (at {loc})"),
        None => format!("panicked: {text}"),
    };
    if message == Some(SCOPED_THREAD_PANIC) {
        out.push_str(
            "\nA thread that the property spawned panicked. Its message went to standard \
             error, because the harness captures panics only on the thread that runs the \
             property.",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_guard_restores_state() {
        assert!(!is_silenced());
        {
            let _outer = Silence::begin();
            assert!(is_silenced());
            {
                let _inner = Silence::begin();
                assert!(is_silenced());
            }
            assert!(is_silenced());
        }
        assert!(!is_silenced());
    }

    #[test]
    fn execute_classifies_outcomes() {
        let _quiet = Silence::begin();
        let mut g = Gen::replay(Vec::new(), 10);
        assert_eq!(execute(&|_: &mut Gen| Ok(()), &mut g), Status::Pass);
        let mut g = Gen::replay(Vec::new(), 10);
        assert_eq!(
            execute(&|_: &mut Gen| Err("no".to_owned()), &mut g),
            Status::Fail("no".to_owned())
        );
        let mut g = Gen::replay(Vec::new(), 10);
        assert_eq!(
            execute(
                &|g: &mut Gen| {
                    g.assume(false);
                    Ok(())
                },
                &mut g
            ),
            Status::Invalid(Invalid::Assume)
        );
        let mut g = Gen::replay(Vec::new(), 2);
        let status = execute(
            &|g: &mut Gen| {
                let _ = g.vec(5..=5, Gen::u8);
                Ok(())
            },
            &mut g,
        );
        assert_eq!(status, Status::Invalid(Invalid::Overrun));
        let mut g = Gen::replay(Vec::new(), 10);
        let status = execute(&|_: &mut Gen| panic!("boom {}", 7), &mut g);
        match status {
            Status::Fail(m) => {
                assert!(m.contains("boom 7"), "{m}");
                assert!(m.contains("exec.rs"), "{m}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A stale capture never replaces the payload of a re-raised panic, and
    /// a non-string payload is reported as such (review finding
    /// prop-panic-message-misattributed).
    #[test]
    fn panic_text_prefers_the_payload() {
        let _quiet = Silence::begin();
        let mut g = Gen::replay(Vec::new(), 10);
        let status = execute(
            &|_: &mut Gen| {
                let _ = catch_unwind(|| panic!("stale"));
                std::panic::resume_unwind(Box::new("fresh".to_owned()))
            },
            &mut g,
        );
        assert_eq!(status, Status::Fail("panicked: fresh".to_owned()));
        let mut g = Gen::replay(Vec::new(), 10);
        let status = execute(&|_: &mut Gen| std::panic::panic_any(7u8), &mut g);
        match status {
            Status::Fail(m) => {
                assert!(m.starts_with("panicked: non-string panic payload"), "{m}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
