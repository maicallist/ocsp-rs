[![docs.rs](https://docs.rs/serde_asn1_der/badge.svg)](https://docs.rs/serde_asn1_der)
[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/serde_asn1_der.svg)](https://crates.io/crates/serde_asn1_der)
[![Download numbers](https://img.shields.io/crates/d/serde_asn1_der.svg)](https://crates.io/crates/serde_asn1_der)
[![Travis CI](https://travis-ci.org/KizzyCode/serde_asn1_der-rust.svg?branch=master)](https://travis-ci.org/KizzyCode/serde_asn1_der-rust)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/serde_asn1_der-rust?svg=true)](https://ci.appveyor.com/project/KizzyCode/serde-asn1-der-rust)
[![dependency status](https://deps.rs/crate/serde_asn1_der/0.7.0/status.svg)](https://deps.rs/crate/serde_asn1_der/0.7.0)


# serde_asn1_der
Welcome to `serde_asn1_der` 🎉

This crate implements an ASN.1-DER subset for serde based upon
[`asn1_der`](https://crates.io/crates/asn1_der).

The following types are supported:
 - `bool`: The ASN.1-BOOLEAN-type
 - `u8`, `u16`, `u32`, `u64`, `u128`, `usize`: The ASN.1-INTEGER-type
 - `()`, `Option`: The ASN.1-NULL-type
 - `&[u8]`, `Vec<u8>`: The ASN.1-OctetString-type
 - `&str`, `String`: The ASN.1-UTF8String-type
 - And everything sequence-like combined out of this types

With the `serde_derive`-crate you can derive `Serialize` and `Deserialize` for all non-primitive
elements:
```rust
use serde_derive::{ Serialize, Deserialize };

#[derive(Serialize, Deserialize)] // Now our struct supports all DER-conversion-traits
struct Address {
	street: String,
	house_number: u128,
	postal_code: u128,
	state: String,
	country: String
}

#[derive(Serialize, Deserialize)] // Now our struct supports all DER-conversion-traits too
struct Customer {
	name: String,
	e_mail_address: String,
	postal_address: Address
}
```


# Example
```rust
use serde_asn1_der::{ to_vec, from_bytes };
use serde_derive::{ Serialize, Deserialize };

#[derive(Serialize, Deserialize)]
struct TestStruct {
	number: u8,
	#[serde(with = "serde_bytes")]
	vec: Vec<u8>,
	tuple: (usize, ())
}

fn main() {
	let plain = TestStruct{ number: 7, vec: b"Testolope".to_vec(), tuple: (4, ()) };
	let serialized = to_vec(&plain).unwrap();
	let deserialized: TestStruct = from_bytes(&serialized).unwrap();
}
```


# `AnyObject`
This crate also offers a type-erased `AnyObject`-trait, that allows you to use `Box<dyn AnyObject>`
instead of a specific type. To enable `AnyObject`, use the `"any"`-feature.