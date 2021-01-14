//! common components in asn1
//! For ASN.1 universal tags list, see [here](https://www.obj-sys.com/asn1tutorial/node124.html)

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use chrono::{Datelike, Timelike};

use crate::{err::OcspError, err_at};

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

/// determine asn1 length
pub(crate) async fn asn1_encode_length(len: usize) -> Result<Vec<u8>, OcspError> {
    match len {
        0..=127 => Ok(vec![len as u8]),
        _ => {
            let mut v = len.to_be_bytes().to_vec();
            // removing leading zero in usize
            v.retain(|e| *e != 0);

            // safety check
            if v.len() > 126 {
                return Err(OcspError::Asn1LengthOverflow(v.len(), err_at!()));
            }
            let l = 0x80 + v.len() as u8;
            let l = vec![l];
            Ok(l.into_iter().chain(v.into_iter()).collect())
        }
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
    pub async fn to_der_utc(&self) -> Result<Vec<u8>, OcspError> {
        let v = format!(
            "{}{:02}{:02}{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.min, self.sec
        )
        .as_bytes()
        .to_vec();
        let l = asn1_encode_length(v.len()).await?;
        let mut t = vec![ASN1_GENERALIZED_TIME];
        t.extend(l);
        t.extend(v);
        Ok(t)
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::{asn1_encode_length, GeneralizedTime, ASN1_GENERALIZED_TIME};

    /// test generalized time to der
    #[tokio::test]
    async fn generalized_time_to_der_utc() {
        let gt = GeneralizedTime {
            year: 2021,
            month: 1,
            day: 13,
            hour: 3,
            min: 9,
            sec: 25,
        };

        let der = gt.to_der_utc().await.unwrap();
        assert_eq!(
            vec![
                ASN1_GENERALIZED_TIME,
                0x0f,
                0x32,
                0x30,
                0x32,
                0x31,
                0x30,
                0x31,
                0x31,
                0x33,
                0x30,
                0x33,
                0x30,
                0x39,
                0x32,
                0x35,
                0x5a
            ],
            der
        );
    }

    /// test asn1 encoding with length requires more than one byte
    #[tokio::test]
    async fn asn1_length_4934() {
        let v = asn1_encode_length(4934).await.unwrap();
        assert_eq!(vec![0x82, 0x13, 0x46], v);
    }

    /// test asn1 encoding with one byte length
    #[tokio::test]
    async fn asn1_length_127() {
        let v = asn1_encode_length(52).await.unwrap();
        assert_eq!(vec![0x34], v)
    }

    /// generalized time conversion
    #[tokio::test]
    async fn num2hex() {
        let num: u32 = 2021;
        let hex = num.to_string();
        let hex = hex.as_bytes();
        assert_eq!(vec![0x32, 0x30, 0x32, 0x31], hex);
    }

    // generalized time conversion
    #[tokio::test]
    async fn hex2time() {
        let hex = "32303231303131333033303932355a";
        let hex = Vec::from_hex(hex).unwrap();
        let time = std::str::from_utf8(&hex).unwrap();
        assert_eq!("20210113030925Z", time);
    }
}
