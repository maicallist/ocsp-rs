use crate::{ Result, SerdeAsn1DerError, misc::ReaderSource };
use serde::{
	Deserialize,
	de::{ DeserializeSeed, Visitor, SeqAccess }
};
use asn1_der::{
	Source, Sink, DerObject, ErrorChain,
	typed::{ DerTypeView, DerDecodable, Boolean, Integer, Null, OctetString, Sequence, Utf8String },
};
use std::io::Read;


/// A sequence walker
struct SequenceReader<'a> {
	sequence: Sequence<'a>,
	pos: usize
}
impl<'a> SeqAccess<'a> for SequenceReader<'a> {
	type Error = SerdeAsn1DerError;
	
	fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
		where T: DeserializeSeed<'a>
	{
		// Load the next object
		let object = match self.sequence.get(self.pos) {
			Ok(object) => object,
			Err(_) => return Ok(None)
		};
		self.pos += 1;
		
		// Deserialize the next object
		let mut deserializer = Deserializer{ object };
		let next = seed.deserialize(&mut deserializer)?;
		Ok(Some(next))
	}
}


/// An ASN.1-DER deserializer over a `slice`
struct Deserializer<'a> {
	object: DerObject<'a>
}
impl<'a, 'r> serde::de::Deserializer<'a> for &'r mut Deserializer<'a> {
	type Error = SerdeAsn1DerError;
	
	fn deserialize_any<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		match self.object.tag() {
			Boolean::TAG => self.deserialize_bool(visitor),
			Integer::TAG => {
				let integer = Integer::load(self.object).propagate(e!("Failed to load integer"))?;
				match integer.is_negative() {
					true => self.deserialize_i128(visitor),
					false => self.deserialize_u128(visitor)
				}
			},
			Null::TAG => self.deserialize_option(visitor),
			OctetString::TAG => self.deserialize_byte_buf(visitor),
			Sequence::TAG => self.deserialize_seq(visitor),
			Utf8String::TAG => self.deserialize_string(visitor),
			_ => Err(eunsupported!("The object type is not supported by this implementation"))?
		}
	}
	
	fn deserialize_bool<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let bool = bool::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_bool(bool)
	}
	
	fn deserialize_i8<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn deserialize_i16<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn deserialize_i32<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn deserialize_i64<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	//noinspection RsTraitImplementation
	fn deserialize_i128<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	fn deserialize_u8<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let u8 = u8::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_u8(u8)
	}
	fn deserialize_u16<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let u16 = u16::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_u16(u16)
	}
	fn deserialize_u32<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let u32 = u32::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_u32(u32)
	}
	fn deserialize_u64<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let u64 = u64::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_u64(u64)
	}
	//noinspection RsTraitImplementation
	fn deserialize_u128<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let u128 = u128::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_u128(u128)
	}
	
	fn deserialize_f32<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn deserialize_f64<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	fn deserialize_char<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let s = Utf8String::load(self.object).propagate(e!("Failed to load object"))?;
		let c = s.get().chars().next().ok_or(einval!("Cannot read char from empty string object"))?;
		visitor.visit_char(c)
	}
	fn deserialize_str<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let s = Utf8String::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_str(s.get())
	}
	fn deserialize_string<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let string = String::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_string(string)
	}
	
	fn deserialize_bytes<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let bytes = OctetString::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_bytes(bytes.get())
	}
	fn deserialize_byte_buf<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let bytes = Vec::<u8>::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_byte_buf(bytes)
	}
	
	fn deserialize_option<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		match self.object.tag() {
			Null::TAG => visitor.visit_none(),
			_ => visitor.visit_some(self)
		}
	}
	
	fn deserialize_unit<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		Null::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_unit()
	}
	//noinspection RsUnresolvedReference
	fn deserialize_unit_struct<V: Visitor<'a>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		self.deserialize_unit(visitor)
	}
	
	//noinspection RsUnresolvedReference
	// As is done here, serializers are encouraged to treat newtype structs as
	// insignificant wrappers around the data they contain. That means not
	// parsing anything other than the contained value.
	fn deserialize_newtype_struct<V: Visitor<'a>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		visitor.visit_newtype_struct(self)
	}
	
	fn deserialize_seq<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		let sequence = Sequence::load(self.object).propagate(e!("Failed to load object"))?;
		visitor.visit_seq(SequenceReader { sequence, pos: 0 })
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple<V: Visitor<'a>>(self, _len: usize, visitor: V) -> Result<V::Value> {
		self.deserialize_seq(visitor)
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple_struct<V: Visitor<'a>>(self, _name: &'static str, _len: usize, visitor: V)
		-> Result<V::Value>
	{
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_map<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	//noinspection RsUnresolvedReference
	fn deserialize_struct<V: Visitor<'a>>(self, _name: &'static str,
		_fields: &'static [&'static str], visitor: V) -> Result<V::Value>
	{
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_enum<V: Visitor<'a>>(self, _name: &'static str,
		_variants: &'static [&'static str], _visitor: V) -> Result<V::Value>
	{
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	fn deserialize_identifier<V: Visitor<'a>>(self, _visitor: V) -> Result<V::Value> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	// Like `deserialize_any` but indicates to the `Deserializer` that it makes
	// no difference which `Visitor` method is called because the data is
	// ignored.
	//
	// Some deserializers are able to implement this more efficiently than
	// `deserialize_any`, for example by rapidly skipping over matched
	// delimiters without paying close attention to the data in between.
	//
	// Some formats are not able to implement this at all. Formats that can
	// implement `deserialize_any` and `deserialize_ignored_any` are known as
	// self-describing.
	fn deserialize_ignored_any<V: Visitor<'a>>(self, visitor: V) -> Result<V::Value> {
		visitor.visit_unit()
	}
}


/// Deserializes `T` from `bytes`
pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &'a[u8]) -> Result<T> {
	let object = DerObject::decode(bytes).propagate(e!("Failed to decode DER object"))?;
	T::deserialize(&mut Deserializer{ object })
}
/// Copies the first top-level object from `reader` into `backing` and deserializes it from there
pub fn from_reader<'a, T: Deserialize<'a>>(reader: impl Read, backing: impl Sink + Into<&'a[u8]>)
	-> Result<T>
{
	from_source(ReaderSource(reader), backing)
}
/// Copies the first top-level object from `source` into `backing` and deserializes it from there
pub fn from_source<'a, T: Deserialize<'a>>(mut source: impl Source,
	backing: impl Sink + Into<&'a[u8]>) -> Result<T>
{
	let object = DerObject::decode_from_source(&mut source, backing)
		.propagate(e!("Failed to decode DER object"))?;
	T::deserialize(&mut Deserializer{ object })
}