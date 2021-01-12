//! common components in asn1

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use chrono::{Datelike, Timelike};

use crate::err::OcspError;

/// asn1 explicit tag 0
pub(crate) const ASN1_EXPLICIT_0: u8 = 0xa0;
/// asn1 explicit tag 1
pub(crate) const ASN1_EXPLICIT_1: u8 = 0xa1;
/// asn1 explicit tag 1
pub(crate) const ASN1_EXPLICIT_2: u8 = 0xa2;
/// asn1 null
pub(crate) const ASN1_NULL: u8 = 0x05;
/// asn1 oid
pub(crate) const ASN1_OID: u8 = 0x06;
/// asn1 sequence
pub(crate) const ASN1_SEQUENCE: u8 = 0x30;
/// asn1 octet
pub(crate) const ASN1_OCTET: u8 = 0x04;
/// asn1 integer
pub(crate) const ASN1_INTEGER: u8 = 0x02;
/// asn1 ia5string
pub(crate) const ASN1_IA5STRING: u8 = 0x16;

/// allowing data to be converted to [Sequence](https://docs.rs/asn1_der/0.7.2/asn1_der/typed/struct.Sequence.html)
pub trait TryIntoSequence<'d> {
    /// converting asn1_der::err
    type Error;
    /// try converting to Sequence
    fn try_into(&'d self) -> Result<Sequence, Self::Error>;
}

impl<'d> TryIntoSequence<'d> for DerObject<'d> {
    type Error = OcspError;
    fn try_into(&self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self.raw()).map_err(OcspError::Asn1DecodingError)
    }
}

impl<'d> TryIntoSequence<'d> for Vec<u8> {
    type Error = OcspError;
    fn try_into(&'d self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self).map_err(OcspError::Asn1DecodingError)
    }
}

impl<'d> TryIntoSequence<'d> for &[u8] {
    type Error = OcspError;
    fn try_into(&'d self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self).map_err(OcspError::Asn1DecodingError)
    }
}

/// represent a ASN1
#[derive(Debug)]
pub struct GeneralizedTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    millis: u32,
}

impl GeneralizedTime {
    /// return UTC time from raw
    pub async fn new(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
        millis: u32,
    ) -> Self {
        GeneralizedTime {
            year: year,
            month: month,
            day: day,
            hour: hour,
            min: min,
            sec: sec,
            millis: millis,
        }
    }

    /// return **now** in UTC
    async fn now() -> Self {
        let now = chrono::offset::Utc::now();
        // nano to millis
        let mi = now.nanosecond().checked_div(1_000_000).unwrap_or(0);

        GeneralizedTime::new(
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            mi,
        )
        .await
    }
}
