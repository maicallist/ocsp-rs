#![cfg(feature = "any")]

#[macro_use] extern crate serde_derive;
use serde_asn1_der::AnyObject;


/// A test vector
#[derive(Deserialize)]
struct TestVector {
	bytes: Vec<u8>,
	r#type: String,
	value_bool: Option<bool>,
	value_string: Option<String>,
	value_bytes: Option<Vec<u8>>
}
impl TestVector {
	/// Loads the test vectors
	pub fn load() -> Vec<Self> {
		serde_json::from_str(include_str!("any_object.json"))
			.expect("Failed to load test vectors")
	}
}


/// A type-erased test struct
#[derive(Serialize, Deserialize)]
struct TestStruct {
	r#type: String,
	erased: Box<dyn AnyObject>
}


#[test]
pub fn test() {
	for test in TestVector::load() {
		// Deserialize test struct
		let test_struct: TestStruct = serde_asn1_der::from_bytes(&test.bytes).unwrap();
		assert_eq!(test_struct.r#type, test.r#type);
		match test_struct.r#type.as_ref() {
			"bool" => assert_eq! {
				test_struct.erased.as_ref().as_any().downcast_ref::<bool>().unwrap(),
				test.value_bool.as_ref().unwrap()
			},
			"string" => assert_eq! {
				test_struct.erased.as_ref().as_any().downcast_ref::<String>().unwrap(),
				test.value_string.as_ref().unwrap()
			},
			"bytes" => assert_eq! {
				test_struct.erased.as_ref().as_any().downcast_ref::<Vec<u8>>().unwrap(),
				test.value_bytes.as_ref().unwrap()
			},
			_ => unreachable!("Invalid type annotation")
		}
	}
}