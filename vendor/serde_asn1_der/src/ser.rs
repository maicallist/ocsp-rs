use crate::{ Result, SerdeAsn1DerError, misc::WriterSink };
use serde::{
	Serialize,
	ser::{
		SerializeSeq, SerializeStruct, SerializeTuple, SerializeTupleStruct,
		SerializeTupleVariant, SerializeMap, SerializeStructVariant
	}
};
use asn1_der::{
	Sink, DerObject, ErrorChain,
	typed::{ DerEncodable, Null, OctetString, Sequence, Utf8String },
};
use std::io::Write;


pub struct SequenceWriter<'a, 'r, S: Sink> {
	serializer: &'r mut Serializer<'a, S>,
	objects: Vec<Vec<u8>>
}
impl<'a, 'r, S: Sink> SequenceWriter<'a, 'r, S> {
	/// Writes the next `value` to the internal buffer
	fn write_object<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		let object = to_vec(value)?;
		Ok(self.objects.push(object))
	}
	/// Finalizes the sequence
	fn finalize(self) -> Result<()> {
		// Collect a list of DER objects
		let objects: Result<_> = self.objects.iter().try_fold(Vec::new(), |mut vec, o| {
			let object = DerObject::decode(o).propagate(e!("Failed to load constructed object"))?;
			vec.push(object);
			Ok(vec)
		});
		
		// Write sequence
		let objects = objects?;
		Sequence::write(&objects, self.serializer.sink).propagate(e!("Failed to write sequence"))?;
		Ok(())
	}
}
impl<'a, 'r, S: Sink> SerializeSeq for SequenceWriter<'a, 'r, S> {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'r, S: Sink> SerializeTuple for SequenceWriter<'a, 'r, S> {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'r, S: Sink> SerializeStruct for SequenceWriter<'a, 'r, S> {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, value: &T)
		-> Result<()>
	{
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'r, S: Sink> SerializeTupleStruct for SequenceWriter<'a, 'r, S> {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}


/// A no-op struct for elements that require a key-value serialization
struct KeyValueWriter;
impl SerializeTupleVariant for KeyValueWriter {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
		Err(eunsupported!("Tuple variants are not supported by this implementation"))?
	}
	fn end(self) -> Result<Self::Ok> {
		Err(eunsupported!("Tuple variants are not supported by this implementation"))?
	}
}
impl SerializeMap for KeyValueWriter {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_key<T: ?Sized + Serialize>(&mut self, _key: &T) -> Result<()> {
		Err(eunsupported!("Map variants are not supported by this implementation"))?
	}
	fn serialize_value<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
		Err(eunsupported!("Map variants are not supported by this implementation"))?
	}
	fn end(self) -> Result<Self::Ok> {
		Err(eunsupported!("Map variants are not supported by this implementation"))?
	}
}
impl SerializeStructVariant for KeyValueWriter {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, _value: &T)
		-> Result<()>
	{
		Err(eunsupported!("Struct variants are not supported by this implementation"))?
	}
	fn end(self) -> Result<Self::Ok> {
		Err(eunsupported!("Struct variants are not supported by this implementation"))?
	}
}


/// An ASN.1-DER serializer for `serde`
struct Serializer<'a, S: Sink> {
	sink: &'a mut S
}
//noinspection RsTraitImplementation
impl<'a, 'r, S: Sink> serde::ser::Serializer for &'r mut Serializer<'a, S> {
	type Ok = ();
	type Error = SerdeAsn1DerError;
	
	type SerializeSeq = SequenceWriter<'a, 'r, S>;
	type SerializeTuple = SequenceWriter<'a, 'r, S>;
	type SerializeTupleStruct = SequenceWriter<'a, 'r, S>;
	type SerializeTupleVariant = KeyValueWriter;
	type SerializeMap = KeyValueWriter;
	type SerializeStruct = SequenceWriter<'a, 'r, S>;
	type SerializeStructVariant = KeyValueWriter;
	
	fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write boolean"))?)
	}
	
	fn serialize_i8(self, _v: i8) -> Result<Self::Ok> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn serialize_i16(self, _v: i16) -> Result<Self::Ok> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn serialize_i32(self, _v: i32) -> Result<Self::Ok> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	fn serialize_i64(self, _v: i64) -> Result<Self::Ok> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	//noinspection RsTraitImplementation
	fn serialize_i128(self, _v: i128) -> Result<Self::Ok> {
		Err(eunsupported!("The object type is not supported by this implementation"))?
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write integer"))?)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write integer"))?)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write integer"))?)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write integer"))?)
	}
	//noinspection RsTraitImplementation
	fn serialize_u128(self, v: u128) -> Result<Self::Ok> {
		Ok(v.encode(&mut self.sink).propagate(e!("Failed to write integer"))?)
	}
	
	fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
		Err(eunsupported!("`f32`s are not supported by this implementation"))?
	}
	fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
		Err(eunsupported!("`f64`s are not supported by this implementation"))?
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_char(self, v: char) -> Result<Self::Ok> {
		let mut buf = [0; 4];
		let v = v.encode_utf8(&mut buf);
		Ok(Utf8String::write(v, &mut self.sink).propagate(e!("Failed to write UTF-8 string"))?)
	}
	fn serialize_str(self, v: &str) -> Result<Self::Ok> {
		Ok(Utf8String::write(v, &mut self.sink).propagate(e!("Failed to write UTF-8 string"))?)
	}
	
	fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
		Ok(OctetString::write(v, &mut self.sink).propagate(e!("Failed to write octet string"))?)
	}
	
	fn serialize_none(self) -> Result<Self::Ok> {
		Ok(Null::write(&mut self.sink).propagate(e!("Failed to write null object"))?)
	}
	fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<Self::Ok> {
		v.serialize(self)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_unit(self) -> Result<Self::Ok> {
		Ok(Null::write(&mut self.sink).propagate(e!("Failed to write null object"))?)
	}
	//noinspection RsUnresolvedReference
	fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
		Ok(Null::write(&mut self.sink).propagate(e!("Failed to write null object"))?)
	}
	
	fn serialize_unit_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str) -> Result<Self::Ok>
	{
		Err(eunsupported!("Unit variants are not supported by this implementation"))?
	}
	
	fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T)
		-> Result<Self::Ok>
	{
		value.serialize(self)
	}
	
	fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str,
		_variant_index: u32, _variant: &'static str, _value: &T) -> Result<Self::Ok>
	{
		Err(eunsupported!("Newtype variants are not supported by this implementation"))?
	}
	
	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
		Ok(SequenceWriter{ serializer: self, objects: Vec::new() })
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
		self.serialize_seq(Some(len))
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple_struct(self, _name: &'static str, len: usize)
		-> Result<Self::SerializeTupleStruct>
	{
		self.serialize_seq(Some(len))
	}
	
	fn serialize_tuple_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeTupleVariant>
	{
		Err(eunsupported!("Tuple variants are not supported by this implementation"))?
	}
	
	fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
		Err(eunsupported!("Maps variants are not supported by this implementation"))?
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
		self.serialize_seq(Some(len))
	}
	
	fn serialize_struct_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeStructVariant>
	{
		Err(eunsupported!("Struct variants are not supported by this implementation"))?
	}
}


/// Serializes `value`
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
	let mut sink = Vec::new();
	to_sink(value, &mut sink)?;
	Ok(sink)
}
/// Serializes `value` to `writer` and returns the amount of serialized bytes
pub fn to_writer<T: ?Sized + Serialize>(value: &T, writer: impl Write) -> Result<()> {
	to_sink(value, &mut WriterSink(writer))
}
/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_sink<T: ?Sized + Serialize>(value: &T, mut sink: impl Sink) -> Result<()> {
	value.serialize(&mut Serializer{ sink: &mut sink })
}