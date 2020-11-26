#![forbid(warnings)]

#[macro_use] extern crate serde_derive;
use serde_asn1_der::{ SerdeAsn1DerError::Asn1DerError as Error, to_vec, from_bytes };
use asn1_der::{
	Asn1DerError,
	Asn1DerErrorVariant::{ InOutError, InvalidData }
};


#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TestStruct {
	number: u8,
	#[serde(with = "serde_bytes")]
	vec: Vec<u8>,
	tuple: (usize, ()),
	option: Option<String>
}


#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct NewtypeTestStruct(TestStruct);


#[test]
fn test() {
	// Nested tuple
	let plain = (7u8, "Testolope".to_string(), (4usize, ()));
	let der = b"\x30\x15\x02\x01\x07\x0c\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00";
	
	let encoded = to_vec(&plain).unwrap();
	assert_eq!(encoded, der.as_ref());
	
	let decoded: (u8, String, (usize, ())) = from_bytes(&encoded).unwrap();
	assert_eq!(decoded, plain);
	
	
	// Test struct with `None`
	let plain = TestStruct{ number: 7, vec: b"Testolope".to_vec(), tuple: (4, ()), option: None };
	let der = b"\x30\x17\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00\x05\x00";
	
	let encoded = to_vec(&plain).unwrap();
	assert_eq!(encoded, der.as_ref());
	
	let decoded: TestStruct = from_bytes(&encoded).unwrap();
	assert_eq!(decoded, plain);
	
	
	// Test struct with `Some`
	let plain = TestStruct {
		number: 7, vec: b"Testolope".to_vec(),
		tuple: (4, ()), option: Some("Testolope".to_string())
	};
	let der = b"\x30\x20\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00\x0c\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65";
	
	let encoded = to_vec(&plain).unwrap();
	assert_eq!(encoded, der.as_ref());
	
	let decoded: TestStruct = from_bytes(&encoded).unwrap();
	assert_eq!(decoded, plain);


	// Newtype test struct with `Some`
	let plain = NewtypeTestStruct(TestStruct {
		number: 7, vec: b"Testolope".to_vec(),
		tuple: (4, ()), option: Some("Testolope".to_string())
	});
	let der = b"\x30\x20\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00\x0c\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65";

	let encoded = to_vec(&plain).unwrap();
	assert_eq!(encoded, der.as_ref());

	let decoded: NewtypeTestStruct = from_bytes(&encoded).unwrap();
	assert_eq!(decoded, plain);
}


#[test]
fn test_err() {
	// Invalid tag
	let der = b"\x31\x15\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00";
	match from_bytes::<TestStruct>(der) {
		Err(Error(Asn1DerError{ error: InvalidData(_), .. })) => (),
		_ => panic!("Invalid result")
	}
	
	// Truncated data
	let der = b"\x30\x15\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05";
	match from_bytes::<TestStruct>(der) {
		Err(Error(Asn1DerError{ error: InOutError(_), .. })) => (),
		_ => panic!("Invalid result")
	}
}