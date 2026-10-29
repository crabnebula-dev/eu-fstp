//! A bounded multi-producer channel and a one-shot reply slot for the
//! engine task (design section 5.2 "Single writer").
//!
//! `fstp-rt` has no channel, and no third-party crate may be added, so
//! this is in-house. Both halves use only `std::sync::Mutex` and wakers.
//! The channel is closed when the receiver is dropped or [`Receiver::close`]
//! runs, and when every sender is dropped. A closed channel refuses every
//! send and gives back the item.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

struct State<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
    senders: usize,
    recv_waker: Option<Waker>,
    send_wakers: Vec<Waker>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The sending half. Cloning it gives another sender.
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// The receiving half. There is exactly one.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

/// A bounded channel holding at most `capacity` items, at least one.
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            closed: false,
            senders: 1,
            recv_waker: None,
            send_wakers: Vec::new(),
        }),
    });
    (
        Sender {
            shared: Arc::clone(&shared),
        },
        Receiver { shared },
    )
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        {
            let mut st = self.shared.lock();
            st.senders = st.senders.saturating_add(1);
        }
        Sender {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut st = self.shared.lock();
            st.senders = st.senders.saturating_sub(1);
            if st.senders == 0 {
                st.recv_waker.take()
            } else {
                None
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl<T> Sender<T> {
    /// Sends `item`, waiting while the channel is full. Gives the item
    /// back when the channel is closed.
    pub fn send(&self, item: T) -> impl Future<Output = Result<(), T>> + '_ {
        let mut item = Some(item);
        poll_fn(move |cx: &mut Context<'_>| {
            let mut st = self.shared.lock();
            let Some(it) = item.take() else {
                return Poll::Ready(Ok(()));
            };
            if st.closed {
                return Poll::Ready(Err(it));
            }
            if st.queue.len() >= st.capacity {
                item = Some(it);
                st.send_wakers.push(cx.waker().clone());
                return Poll::Pending;
            }
            st.queue.push_back(it);
            let w = st.recv_waker.take();
            drop(st);
            if let Some(w) = w {
                w.wake();
            }
            Poll::Ready(Ok(()))
        })
    }

    /// Whether the receiver closed the channel.
    pub fn is_closed(&self) -> bool {
        self.shared.lock().closed
    }
}

impl<T> Receiver<T> {
    /// The next item, or `None` once the channel is closed and empty, or
    /// every sender is gone and the queue is empty.
    pub fn recv(&mut self) -> impl Future<Output = Option<T>> + '_ {
        poll_fn(move |cx: &mut Context<'_>| {
            let mut st = self.shared.lock();
            if let Some(item) = st.queue.pop_front() {
                let wakers = std::mem::take(&mut st.send_wakers);
                drop(st);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Some(item));
            }
            if st.closed || st.senders == 0 {
                return Poll::Ready(None);
            }
            st.recv_waker = Some(cx.waker().clone());
            Poll::Pending
        })
    }

    /// Closes the channel: every later send is refused. Items already
    /// queued stay, and [`Receiver::drain`] takes them.
    pub fn close(&mut self) {
        let wakers = {
            let mut st = self.shared.lock();
            st.closed = true;
            std::mem::take(&mut st.send_wakers)
        };
        for w in wakers {
            w.wake();
        }
    }

    /// Takes every queued item.
    pub fn drain(&mut self) -> Vec<T> {
        let mut st = self.shared.lock();
        st.queue.drain(..).collect()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.close();
    }
}

struct Slot<T> {
    value: Option<T>,
    waker: Option<Waker>,
    dropped: bool,
}

/// The sending side of a one-shot reply.
pub struct ReplyTx<T> {
    slot: Arc<Mutex<Slot<T>>>,
}

/// The receiving side of a one-shot reply.
pub struct ReplyRx<T> {
    slot: Arc<Mutex<Slot<T>>>,
}

/// A one-shot reply slot.
pub fn reply<T>() -> (ReplyTx<T>, ReplyRx<T>) {
    let slot = Arc::new(Mutex::new(Slot {
        value: None,
        waker: None,
        dropped: false,
    }));
    (
        ReplyTx {
            slot: Arc::clone(&slot),
        },
        ReplyRx { slot },
    )
}

fn lock_slot<T>(m: &Mutex<Slot<T>>) -> MutexGuard<'_, Slot<T>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<T> ReplyTx<T> {
    /// Delivers the reply.
    pub fn send(self, value: T) {
        let w = {
            let mut s = lock_slot(&self.slot);
            s.value = Some(value);
            s.waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

impl<T> Drop for ReplyTx<T> {
    fn drop(&mut self) {
        let w = {
            let mut s = lock_slot(&self.slot);
            s.dropped = true;
            s.waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

impl<T> ReplyRx<T> {
    /// The reply, or `None` when the sender was dropped without one.
    pub fn recv(self) -> impl Future<Output = Option<T>> {
        poll_fn(move |cx: &mut Context<'_>| {
            let mut s = lock_slot(&self.slot);
            if let Some(v) = s.value.take() {
                return Poll::Ready(Some(v));
            }
            if s.dropped {
                return Poll::Ready(None);
            }
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_rt::future::block_on;

    /// Design section 5.2 ("Single writer"): items arrive in send order,
    /// and a closed channel refuses later sends and gives the item back.
    #[test]
    fn adr007_engine_channel_keeps_order_and_refuses_after_close() {
        let (tx, mut rx) = channel::<u8>(2);
        let got = block_on(async {
            let a = tx.send(1).await;
            let b = tx.send(2).await;
            let first = rx.recv().await;
            rx.close();
            let late = tx.send(3).await;
            let second = rx.recv().await;
            let end = rx.recv().await;
            (a, b, first, late, second, end)
        });
        assert_eq!(got, (Ok(()), Ok(()), Some(1), Err(3), Some(2), None));
    }

    /// A reply dropped without a value reports `None`, so a caller never
    /// waits for a reply that cannot come.
    #[test]
    fn adr007_engine_reply_reports_a_dropped_sender() {
        let (tx, rx) = reply::<u8>();
        drop(tx);
        assert_eq!(block_on(rx.recv()), None);
        let (tx, rx) = reply::<u8>();
        tx.send(7);
        assert_eq!(block_on(rx.recv()), Some(7));
    }
}
