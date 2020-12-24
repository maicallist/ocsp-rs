//! ocsp-rs provides de/serialization for ocsp request and response in asn.1 der

#![deny(
    bad_style,
    const_err,
//    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
//    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    // following are default allowed lint
//    //missing_debug_implementations, //disabled cuz asn1_der does not impl Debug
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

pub mod asn1_common;
pub mod common;
pub mod err;
pub mod sync;
pub mod request;

#[cfg(test)]
mod tests {}
