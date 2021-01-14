//! common components in asn1
//! For ASN.1 universal tags list, see [here](https://www.obj-sys.com/asn1tutorial/node124.html)

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
/// asn1 generalized time
pub(crate) const ASN1_GENERALIZED_TIME: u8 = 0x18;
/// asn1 enumerated
pub(crate) const ASN1_ENUMERATED: u8 = 0x0a;
/// asn1 bit string
pub(crate) const ASN1_BIT_STRING: u8 = 0x03;

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

/// represents a ASN1 GeneralizedTime
#[derive(Debug)]
pub struct GeneralizedTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    //millis: u32,
}

impl GeneralizedTime {
    /// return **now** in UTC
    pub async fn now() -> Self {
        let now = chrono::offset::Utc::now();
        // nano to millis
        //let mi = now.nanosecond().checked_div(1_000_000).unwrap_or(0);

        GeneralizedTime {
            year: now.year(),
            month: now.month(),
            day: now.day(),
            hour: now.hour(),
            min: now.minute(),
            sec: now.second(),
            //millis: mi,
        }
    }

    /// serialize to DER encoding  
    /// see [html](https://www.obj-sys.com/asn1tutorial/node14.html)
    pub async fn to_der() -> Vec<u8> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    #[tokio::test]
    async fn num2hex() {
        let num: u32 = 2021;
        let hex = num.to_string();
        let hex = hex.as_bytes();
        assert_eq!(vec![0x32, 0x30, 0x32, 0x31], hex);
    }

    #[tokio::test]
    async fn hex2time() {
        let hex = "32303231303131333033303932355a";
        let hex = Vec::from_hex(hex).unwrap();
        let time = std::str::from_utf8(&hex).unwrap();
        assert_eq!("20210113030925Z", time);
    }
}
