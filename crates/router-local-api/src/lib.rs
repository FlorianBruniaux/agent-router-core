#![forbid(unsafe_code)]
//! Route-only HTTP/1 API on an owner-private Unix socket.
//!
//! The crate owns transport, authentication and request framing. It never
//! interprets routing inputs: a caller-supplied [`RouteHandler`] receives the
//! three inline JSON documents as byte slices. No other operation is exposed.
#![cfg(unix)]

mod error;
mod http;
mod json;
mod server;
mod state;

pub use error::Error;
pub use server::{HandlerError, Limits, RouteHandler, RouteInput, Server};

/// Maximum size of the request line and headers, terminator included.
pub const MAX_HEADER_BYTES: usize = http::MAX_HEADER_BYTES;
/// File name of the bearer token inside the state directory.
pub const TOKEN_FILE: &str = state::TOKEN_FILE;
/// File name of the Unix socket inside the state directory.
pub const SOCKET_FILE: &str = state::SOCKET_FILE;
