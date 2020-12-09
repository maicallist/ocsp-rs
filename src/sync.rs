//! this module provides same functions in root module without async
//! accessing this module requires feature 'sync'

#[cfg(feature = "sync")]
pub mod asn1_common;
