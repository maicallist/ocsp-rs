//! ocsp-rs provides de/serialization for ocsp request and response in asn.1 der

#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod common;
pub mod err;
pub mod oid;
pub mod request;
pub mod response;

#[cfg(test)]
mod tests {}
