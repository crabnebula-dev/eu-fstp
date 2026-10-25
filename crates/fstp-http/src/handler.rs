//! The request handler trait.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::message::{Request, Response};

/// Turns a request into a response.
///
/// The server driver calls `handle` once per request, with the body fully
/// buffered. Implementations can be written with `async fn`:
///
/// ```
/// use fstp_http::{Handler, Request, Response, StatusCode};
///
/// struct Hello;
///
/// impl Handler for Hello {
///     async fn handle(&self, _req: Request) -> Response {
///         Response::text(StatusCode::OK, "hello")
///     }
/// }
/// ```
pub trait Handler: Send + Sync + 'static {
    /// Handles one request.
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send;
}

impl<H: Handler> Handler for Arc<H> {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        (**self).handle(req)
    }
}

/// A [`Handler`] made from a closure. Created by [`handler_fn`].
#[derive(Clone)]
pub struct HandlerFn<F> {
    f: F,
}

impl<F> std::fmt::Debug for HandlerFn<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerFn").finish_non_exhaustive()
    }
}

/// Wraps a closure that returns a future as a [`Handler`].
///
/// ```
/// use fstp_http::{handler_fn, Request, Response, StatusCode};
///
/// let h = handler_fn(|req: Request| async move {
///     Response::text(StatusCode::OK, format!("{} bytes", req.body.len()))
/// });
/// # let _ = h;
/// ```
pub fn handler_fn<F, Fut>(f: F) -> HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    HandlerFn { f }
}

impl<F, Fut> Handler for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        (self.f)(req)
    }
}

/// A boxed response future borrowing its handler.
pub(crate) type BoxFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

/// Object-safe form of [`Handler`], for storing different handlers
/// together.
pub(crate) trait DynHandler: Send + Sync + 'static {
    fn call(&self, req: Request) -> BoxFuture<'_>;
}

impl<H: Handler> DynHandler for H {
    fn call(&self, req: Request) -> BoxFuture<'_> {
        Box::pin(self.handle(req))
    }
}
