//! common components in asn1
//! For ASN.1 universal tags list, see [here](https://www.obj-sys.com/asn1tutorial/node124.html)

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use chrono::{Datelike, Timelike};
use tracing::{debug, error, trace};

use crate::oid::b2i_oid;
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
/// only support UTC
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
    /// create generalized time at specified time
    pub async fn new(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Result<Self, OcspError> {
        // lazy check if date time is valid
        // turn it into chrono
        let dt = chrono::NaiveDate::from_ymd_opt(year, month, day)
            .ok_or(OcspError::GenInvalidDate(year, month, day, err_at!()))?;
        let _ = dt
            .and_hms_opt(hour, min, sec)
            .ok_or(OcspError::GenInvalidTime(hour, min, sec, err_at!()))?;

        Ok(GeneralizedTime {
            year: year,
            month: month,
            day: day,
            hour: hour,
            min: min,
            sec: sec,
        })
    }

    /// create time **now** in UTC
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

/// Oid represents a 0x06 OID type in ASN.1  
/// In OpenSSL ocsp request, OID is followed by NULL 0x05  
/// REVIEW 0x05
#[derive(Debug)]
pub struct Oid {
    // an oid in bytes
    //pub id: Vec<u8>,
    pub(crate) index: usize,
    //null: Vec<u8>,
}

impl Oid {
    /// get oid from raw sequence
    pub async fn parse(oid: &[u8]) -> Result<Self, OcspError> {
        debug!("Start decoding OID");
        trace!("Parsing OID {:02X?}", oid);
        debug!("Converting OID data into asn1 sequence");
        let s = oid.try_into()?;

        debug!("Checking OID sequence length");
        if s.len() != 2 {
            error!(
                "Provided OID contains {} items in sequence, expecting 2",
                s.len()
            );
            return Err(OcspError::Asn1LengthError("OID", err_at!()));
        }

        let id = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        let nil = s.get(1).map_err(OcspError::Asn1DecodingError)?;
        debug!("Checking OID tags");
        if id.tag() != ASN1_OID || nil.tag() != ASN1_NULL {
            error!(
                "Provided OID sequence tags are {} and {}, expecting 0x06 and 0x05",
                id.tag(),
                nil.tag()
            );
            return Err(OcspError::Asn1MismatchError("OID", err_at!()));
        }

        let u = match b2i_oid(id.value()).await {
            None => return Err(OcspError::Asn1OidUnknown(err_at!())),
            Some(u) => u,
        };

        debug!("Good OID decoded");
        Ok(Oid {
            //id: id.value().to_vec(),
            index: u,
        })
    }

    /// return new oid
    pub async fn new() -> Result<Self, OcspError> {
        unimplemented!()
    }

    /// encode to ASN.1 DER
    pub async fn to_der(&self) -> Result<Vec<u8>, OcspError> {
        unimplemented!()
    }
}
/// RFC 6960 CertID
#[derive(Debug)]
pub struct CertId {
    /// hash algo oid
    pub hash_algo: Oid,
    /// issuer name hash in byte
    pub issuer_name_hash: Vec<u8>,
    /// issuer key hash in byte
    pub issuer_key_hash: Vec<u8>,
    /// certificate serial number in byte
    pub serial_num: Vec<u8>,
}

impl CertId {
    /// get certid from raw bytes
    pub async fn parse(certid: &[u8]) -> Result<Self, OcspError> {
        debug!("Start decoding CertID");
        trace!("Parsing CERTID {:02X?}", certid);
        debug!("Converting CERTID data into asn1 sequence");
        let s = certid.try_into()?;

        debug!("Checking CERTID sequence length");
        if s.len() != 4 {
            error!(
                "Provided CERTID contains {} items in sequence, expecting 4",
                s.len()
            );
            return Err(OcspError::Asn1LengthError("CertID", err_at!()));
        }

        let oid = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        let name_hash = s.get(1).map_err(OcspError::Asn1DecodingError)?;
        let key_hash = s.get(2).map_err(OcspError::Asn1DecodingError)?;
        let sn = s.get(3).map_err(OcspError::Asn1DecodingError)?;

        debug!("Checking CERTID tags");
        if oid.tag() != ASN1_SEQUENCE
            || name_hash.tag() != ASN1_OCTET
            || key_hash.tag() != ASN1_OCTET
            || sn.tag() != ASN1_INTEGER
        {
            error!(
                "Provided CERTID sequence tags are {}, {}, {} and {}, expecting 0x30, 0x04, 0x04, 0x02", 
                oid.tag(),
                name_hash.tag(),
                key_hash.tag(),
                sn.tag()
            );
            return Err(OcspError::Asn1MismatchError("CertId", err_at!()));
        }

        let oid = Oid::parse(oid.raw()).await?;
        let name_hash = name_hash.value().to_vec();
        let key_hash = key_hash.value().to_vec();
        let sn = sn.value().to_vec();

        debug!("Good CERTID decoded");
        Ok(CertId {
            hash_algo: oid,
            issuer_name_hash: name_hash,
            issuer_key_hash: key_hash,
            serial_num: sn,
        })
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
