//! A small async mutex over the internal runtime traits. The witness
//! service holds its database client and its chain states under one, and
//! the cell's witness link holds its connection under one, so a lock is
//! held across the awaits of one exchange and never blocks a runtime
//! thread.
//!
//! The guard owns the value while it is held, so the guard is `Send`
//! whenever the value is. Waiters are woken in arrival order. A dropped
//! lock future gives up its place, and a dropped guard puts the value
//! back and wakes the next waiter.

use std::collections::VecDeque;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

struct State<T> {
    locked: bool,
    next_ticket: u64,
    waiters: VecDeque<(u64, Waker)>,
    value: T,
}

/// An async mutex.
pub struct AsyncMutex<T> {
    state: Mutex<State<T>>,
}

impl<T> std::fmt::Debug for AsyncMutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncMutex").finish_non_exhaustive()
    }
}

fn locked<S>(m: &Mutex<S>) -> MutexGuard<'_, S> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<T: Default + Send> AsyncMutex<T> {
    /// A mutex holding `value`.
    pub fn new(value: T) -> AsyncMutex<T> {
        AsyncMutex {
            state: Mutex::new(State {
                locked: false,
                next_ticket: 0,
                waiters: VecDeque::new(),
                value,
            }),
        }
    }

    /// Waits for the lock.
    pub fn lock(&self) -> Lock<'_, T> {
        Lock {
            mutex: self,
            ticket: None,
        }
    }
}

/// The future of [`AsyncMutex::lock`].
pub struct Lock<'a, T: Default + Send> {
    mutex: &'a AsyncMutex<T>,
    ticket: Option<u64>,
}

impl<'a, T: Default + Send> Future for Lock<'a, T> {
    type Output = Guard<'a, T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Guard<'a, T>> {
        let mutex = self.mutex;
        let mut st = locked(&mutex.state);
        let ticket = match self.ticket {
            Some(t) => t,
            None => {
                let t = st.next_ticket;
                st.next_ticket = st.next_ticket.wrapping_add(1);
                st.waiters.push_back((t, cx.waker().clone()));
                t
            }
        };
        self.ticket = Some(ticket);
        let first = st.waiters.front().map(|(t, _)| *t) == Some(ticket);
        if !st.locked && first {
            st.locked = true;
            st.waiters.pop_front();
            let value = std::mem::take(&mut st.value);
            drop(st);
            self.ticket = None;
            return Poll::Ready(Guard { mutex, value });
        }
        if let Some(slot) = st.waiters.iter_mut().find(|(t, _)| *t == ticket) {
            slot.1 = cx.waker().clone();
        }
        Poll::Pending
    }
}

impl<T: Default + Send> Drop for Lock<'_, T> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket {
            let next = {
                let mut st = locked(&self.mutex.state);
                st.waiters.retain(|(t, _)| *t != ticket);
                if st.locked {
                    None
                } else {
                    st.waiters.front().map(|(_, w)| w.clone())
                }
            };
            if let Some(w) = next {
                w.wake();
            }
        }
    }
}

/// The held lock. The value goes back into the mutex when it drops.
pub struct Guard<'a, T: Default + Send> {
    mutex: &'a AsyncMutex<T>,
    value: T,
}

impl<T: Default + Send> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Default + Send> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Default + Send> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        let next = {
            let mut st = locked(&self.mutex.state);
            st.value = std::mem::take(&mut self.value);
            st.locked = false;
            st.waiters.front().map(|(_, w)| w.clone())
        };
        if let Some(w) = next {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A second lock waits for the first guard and then sees its write.
    #[test]
    fn lock_is_exclusive_and_keeps_writes() {
        let m = AsyncMutex::new(0u32);
        fstp_rt::future::block_on(async {
            let mut g = m.lock().await;
            *g += 1;
            let second = m.lock();
            assert!(fstp_rt::future::poll_bounded(second, 4).is_none());
            drop(g);
            assert_eq!(*m.lock().await, 1);
        });
    }
}
