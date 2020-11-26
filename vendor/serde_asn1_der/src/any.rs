use serde::{
	ser::{ Serialize, Serializer },
	de::{ Deserialize, DeserializeOwned, Deserializer, Error, SeqAccess, Visitor }
};
use std::{
	any::Any,
	fmt::{ self, Formatter }
};


struct AnyVisitor;
impl<'de> Visitor<'de> for AnyVisitor {
	type Value = Box<dyn AnyObject>;
	
	fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
		write!(formatter, "a valid DER object")
	}
	
	fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	
	fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	//noinspection RsTraitImplementation
	fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	
	fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error {
		self.visit_string(v.to_string())
	}
	fn visit_string<E>(self, v: String) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	
	fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: Error {
		self.visit_byte_buf(v.to_vec())
	}
	fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(v))
	}
	
	fn visit_none<E>(self) -> Result<Self::Value, E> where E: Error {
		self.visit_unit()
	}
	fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
		where D: Deserializer<'de>
	{
		deserializer.deserialize_any(Self)
	}
	fn visit_unit<E>(self) -> Result<Self::Value, E> where E: Error {
		Ok(Box::new(()))
	}
	
	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
		let mut elements = Vec::new();
		while let Some(next) = seq.next_element::<Box<dyn AnyObject>>()? {
			elements.push(next)
		}
		Ok(Box::new(elements))
	}
}


/// An umbrella-trait for any type that implements `Serialize` and `DeserializeOwned`
///
/// Wrapped in a `Box`, this trait can be used as type-erased placeholder object; e.g.
/// ```rust
/// # use serde_asn1_der::AnyObject;
/// # use serde_derive::{ Serialize, Deserialize };
/// #[derive(Serialize, Deserialize)]
/// struct Entry {
///     r#type: String,
///     payload: Box<dyn AnyObject>
/// }
/// ```
///
/// If you deserialize to `Box<dyn AnyObject>`, the following mapping applies:
///  - `bool` to `Box<bool>`
///  - `u8`/`u16`/`u32`/`u64`/`u128` to `Box<u8>`/`Box<u16>`/`Box<u32>`/`Box<u64>`/`Box<u128>`
///  - `str` and `String` to `Box<String>`
///  - `&[u8]` and `Vec<u8>` to `Box<Vec<u8>>`
///  - `None` and `()` to `Box<()>`
///  - `Some(T)` to `Box<T>` where `T` is mapped according to this list
///  - `Vec<T>` to `Box<Vec<Box<dyn AnyObject>>>` where `T` is mapped according to this list
pub trait AnyObject {
	/// Returns `self` as serializable object
	#[doc(hidden)]
	fn serializable(&self) -> &dyn erased_serde::Serialize;
	/// Returns `self` as `&dyn Any`
	///
	/// _Important: do not call this method directly on the box, but only on the inner object using
	/// `my_box.as_ref().as_any()`, or else the downcasts to the native types will fail_
	fn as_any(&self) -> &dyn Any;
}
impl<T: Serialize + DeserializeOwned + Any> AnyObject for T {
	fn serializable(&self) -> &dyn erased_serde::Serialize {
		self
	}
	fn as_any(&self) -> &dyn Any {
		self
	}
}
impl<'de> Deserialize<'de> for Box<dyn AnyObject> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
		deserializer.deserialize_any(AnyVisitor)
	}
}
impl Serialize for Box<dyn AnyObject> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		erased_serde::serialize(self.serializable(), serializer)
	}
}

