//! Common components in ASN.1  
//! For ASN.1 universal tags list, see [here](https://www.obj-sys.com/asn1tutorial/node124.html)

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use chrono::{Datelike, Timelike};
use tracing::{error, trace};

use crate::err::OcspError;
use crate::oid::{b2i_oid, d2i_oid, i2b_oid};

/// Aliasing Vec<u8> with Bytes
pub type Bytes = Vec<u8>;

/// ASN.1 explicit tag 0
pub(crate) const ASN1_EXPLICIT_0: u8 = 0xa0;
/// ASN.1 explicit tag 1
pub(crate) const ASN1_EXPLICIT_1: u8 = 0xa1;
/// ASN.1 explicit tag 1
pub(crate) const ASN1_EXPLICIT_2: u8 = 0xa2;
/// ASN.1 null
pub(crate) const ASN1_NULL: u8 = 0x05;
/// ASN.1 oid
pub(crate) const ASN1_OID: u8 = 0x06;
/// ASN.1 oid followed by NULL
pub(crate) const ASN1_OID_PADDING: [u8; 2] = [0x05, 0x00];
/// ASN.1 sequence
pub(crate) const ASN1_SEQUENCE: u8 = 0x30;
/// ASN.1 octet
pub(crate) const ASN1_OCTET: u8 = 0x04;
/// ASN.1 integer
pub(crate) const ASN1_INTEGER: u8 = 0x02;
/// ASN.1 ia5string
pub(crate) const ASN1_IA5STRING: u8 = 0x16;
/// ASN.1 generalized time
pub(crate) const ASN1_GENERALIZED_TIME: u8 = 0x18;
/// ASN.1 enumerated
pub(crate) const ASN1_ENUMERATED: u8 = 0x0a;
/// ASN.1 bit string
pub(crate) const ASN1_BIT_STRING: u8 = 0x03;

/// Allowing byte data to be converted to [Sequence](https://docs.rs/asn1_der/0.7.2/asn1_der/typed/struct.Sequence.html)
pub trait TryIntoSequence<'d> {
    /// Converting asn1_der::err
    type Error;
    /// Try converting to Sequence
    fn try_into(&'d self) -> Result<Sequence<'d>, Self::Error>;
}

impl<'d> TryIntoSequence<'d> for DerObject<'d> {
    type Error = OcspError;
    fn try_into(&self) -> Result<Sequence<'d>, Self::Error> {
        Sequence::decode(self.raw()).map_err(OcspError::Asn1DecodingError)
    }
}

impl<'d> TryIntoSequence<'d> for Bytes {
    type Error = OcspError;
    fn try_into(&'d self) -> Result<Sequence<'d>, Self::Error> {
        Sequence::decode(self).map_err(OcspError::Asn1DecodingError)
    }
}

impl<'d> TryIntoSequence<'d> for &[u8] {
    type Error = OcspError;
    fn try_into(&'d self) -> Result<Sequence<'d>, Self::Error> {
        Sequence::decode(self).map_err(OcspError::Asn1DecodingError)
    }
}

/// Determining ASN.1 length  
/// For details, check ASN.1 encoding rules at [here](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes)
pub(crate) async fn asn1_encode_length(len: usize) -> Result<Bytes, OcspError> {
    match len {
        0..=127 => Ok(vec![len as u8]),
        _ => {
            let v = len.to_be_bytes().to_vec();
            // removing leading zero in usize
            let v: Bytes = v.into_iter().skip_while(|n| *n == 0).collect();

            // safety check
            if v.len() > 127 {
                return Err(OcspError::Asn1LengthOverflow(v.len()));
            }
            let l = 0x80 + v.len() as u8;
            let l = vec![l];
            Ok(l.into_iter().chain(v.into_iter()).collect())
        }
    }
}

/// Packing octet into ASN.1 DER
pub(crate) async fn asn1_encode_octet(data: &[u8]) -> Result<Bytes, OcspError> {
    let mut tlv = vec![ASN1_OCTET];
    let len = asn1_encode_length(data.len()).await?;
    tlv.extend(len);
    tlv.extend(data);
    Ok(tlv)
}

/// Packing integer into ASN.1 DER
pub(crate) async fn asn1_encode_integer(data: &[u8]) -> Result<Bytes, OcspError> {
    let mut tlv = vec![ASN1_INTEGER];
    let len = asn1_encode_length(data.len()).await?;
    tlv.extend(len);
    tlv.extend(data);
    Ok(tlv)
}

/// Packing bit string into ASN.1 DER
pub(crate) async fn asn1_encode_bit_string(data: &[u8]) -> Result<Bytes, OcspError> {
    let mut tlv = vec![ASN1_BIT_STRING];
    let len = asn1_encode_length(data.len()).await?;
    tlv.extend(len);
    tlv.extend(data);
    Ok(tlv)
}

/// Represents a ASN.1 GeneralizedTime  
/// Only support UTC
#[derive(Debug, Copy, Clone)]
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
    /// Create a generalized time at specified time
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
            .ok_or(OcspError::GenInvalidDate(year, month, day))?;
        let _ = dt
            .and_hms_opt(hour, min, sec)
            .ok_or(OcspError::GenInvalidTime(hour, min, sec))?;

        Ok(GeneralizedTime {
            year,
            month,
            day,
            hour,
            min,
            sec,
        })
    }

    /// Create a generalized time **now** in UTC
    pub async fn now() -> Self {
        let now = chrono::offset::Utc::now();

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

    /// Serialize to DER encoding  
    /// see [html](https://www.obj-sys.com/asn1tutorial/node14.html)
    pub async fn to_der_utc(&self) -> Result<Bytes, OcspError> {
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid {
    pub(crate) index: usize,
}

impl Oid {
    /// get oid from raw bytes
    pub async fn parse(oid: &[u8]) -> Result<Self, OcspError> {
        let oid_hex = hex::encode(oid);
        trace!("Parsing oid {}", oid_hex);
        let s = oid.try_into()?;

        if s.len() != 2 {
            error!(
                "Provided oid contains {} items in sequence, expecting 2",
                s.len()
            );
            return Err(OcspError::Asn1LengthError("OID"));
        }

        let id = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        let nil = s.get(1).map_err(OcspError::Asn1DecodingError)?;
        if id.tag() != ASN1_OID || nil.tag() != ASN1_NULL {
            error!(
                "Provided oid sequence tags are {} and {}, expecting 0x06 and 0x05",
                id.tag(),
                nil.tag()
            );
            return Err(OcspError::Asn1MismatchError("OID"));
        }

        let u = match b2i_oid(id.value()).await {
            None => return Err(OcspError::Asn1OidUnknown),
            Some(u) => u,
        };

        trace!("Oid {} successfully decoded to internal {}", oid_hex, u);
        Ok(Oid { index: u })
    }

    /// return new oid from dot notation
    pub async fn new_from_dot(name_dot_notation: &str) -> Result<Self, OcspError> {
        // ignoring logging here, trace if logged in d2i_oid
        d2i_oid(name_dot_notation)
            .await
            .ok_or(OcspError::Asn1OidUnknown)
    }

    /// encode to ASN.1 DER with tailing NULL
    pub async fn to_der_with_null(&self) -> Result<Bytes, OcspError> {
        trace!("Encoding oid index {}", self.index);
        let val_oid = i2b_oid(self).await?;
        let len_oid = asn1_encode_length(val_oid.len()).await?;
        let mut tlv_oid = vec![ASN1_OID];
        tlv_oid.extend(len_oid);
        tlv_oid.extend(val_oid);
        tlv_oid.extend(&ASN1_OID_PADDING);
        let len_seq = asn1_encode_length(tlv_oid.len()).await?;
        let mut tlv_seq_oid = vec![ASN1_SEQUENCE];
        tlv_seq_oid.extend(len_seq);
        tlv_seq_oid.extend(tlv_oid);

        trace!("Internal oid {} successfully encoded", self.index);
        Ok(tlv_seq_oid)
    }

    /// encode to ASN.1 DER
    /// - without sequence header
    /// - without tailing NULL
    pub async fn to_der_raw(&self) -> Result<Bytes, OcspError> {
        trace!("Encoding oid without sequence index {}", self.index);
        let val_oid = i2b_oid(self).await?;
        let len_oid = asn1_encode_length(val_oid.len()).await?;
        let mut tlv_oid = vec![ASN1_OID];
        tlv_oid.extend(len_oid);
        tlv_oid.extend(val_oid);

        trace!(
            "Internal oid {} successfully encoded without padding",
            self.index
        );
        Ok(tlv_oid)
    }
}

/// RFC 6960 CertID or abbv cid
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertId {
    /// hash algo oid
    pub hash_algo: Oid,
    /// issuer name hash in byte
    pub issuer_name_hash: Bytes,
    /// issuer key hash in byte
    pub issuer_key_hash: Bytes,
    /// certificate serial number in byte
    pub serial_num: Bytes,
}

impl CertId {
    /// get certid from raw bytes
    pub async fn parse(cid: &[u8]) -> Result<Self, OcspError> {
        let cid_hex = hex::encode(cid);
        trace!("Parsing cid {}", cid_hex);
        let s = cid.try_into()?;

        if s.len() != 4 {
            error!(
                "Provided cid contains {} items in sequence, expecting 4",
                s.len()
            );
            return Err(OcspError::Asn1LengthError("CID"));
        }

        let oid = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        let name_hash = s.get(1).map_err(OcspError::Asn1DecodingError)?;
        let key_hash = s.get(2).map_err(OcspError::Asn1DecodingError)?;
        let sn = s.get(3).map_err(OcspError::Asn1DecodingError)?;

        if oid.tag() != ASN1_SEQUENCE
            || name_hash.tag() != ASN1_OCTET
            || key_hash.tag() != ASN1_OCTET
            || sn.tag() != ASN1_INTEGER
        {
            error!(
                "Provided cid sequence tags are {}, {}, {} and {}, expecting 0x30, 0x04, 0x04, 0x02", 
                oid.tag(),
                name_hash.tag(),
                key_hash.tag(),
                sn.tag()
            );
            return Err(OcspError::Asn1MismatchError("CID"));
        }

        let oid = Oid::parse(oid.raw()).await?;
        let name_hash = name_hash.value().to_vec();
        let key_hash = key_hash.value().to_vec();
        let sn = sn.value().to_vec();

        trace!("Cid {} successfully decoded", cid_hex);
        Ok(CertId {
            hash_algo: oid,
            issuer_name_hash: name_hash,
            issuer_key_hash: key_hash,
            serial_num: sn,
        })
    }

    /// return new cid
    pub async fn new(oid: Oid, name_hash: &[u8], key_hash: &[u8], sn: &[u8]) -> Self {
        CertId {
            hash_algo: oid,
            issuer_name_hash: name_hash.to_vec(),
            issuer_key_hash: key_hash.to_vec(),
            serial_num: sn.to_vec(),
        }
    }

    /// encode CertID to ASN.1 DER
    pub async fn to_der(&self) -> Result<Bytes, OcspError> {
        trace!("Encoding cid with sn {}", hex::encode(&self.serial_num));

        let mut oid = self.hash_algo.to_der_with_null().await?;
        let name = asn1_encode_octet(&self.issuer_name_hash).await?;
        let key = asn1_encode_octet(&self.issuer_key_hash).await?;
        let sn = asn1_encode_integer(&self.serial_num).await?;
        oid.extend(name);
        oid.extend(key);
        oid.extend(sn);
        let len = asn1_encode_length(oid.len()).await?;
        let mut tlv = vec![ASN1_SEQUENCE];
        tlv.extend(len);
        tlv.extend(oid);

        trace!("Cid {:?} successfully encoded", self);
        Ok(tlv)
    }
}
#[cfg(test)]
mod test {
    use hex::FromHex;

    use crate::oid::{ALGO_SHA1_DOT, OCSP_EXT_CRL_REASON_DOT, OCSP_EXT_CRL_REASON_ID};

    use super::*;

    // test encoding length
    #[tokio::test]
    async fn encoding_length_over128() {
        let v = asn1_encode_length(4934).await.unwrap();
        let c = vec![0x82, 0x13, 0x46u8];
        assert_eq!(c, v);

        let v = asn1_encode_length(256).await.unwrap();
        let c = vec![0x82, 0x01, 0x00u8];
        assert_eq!(c, v);
    }

    // test encoding length
    #[tokio::test]
    async fn encoding_length_under128() {
        let v = asn1_encode_length(52).await.unwrap();
        let c = vec![0x34u8];
        assert_eq!(c, v);

        let v = asn1_encode_length(127).await.unwrap();
        let c = vec![0x7fu8];
        assert_eq!(c, v);
    }

    // test encoding signature
    #[tokio::test]
    async fn encode_bit_string() {
        let sign = vec![
            0x6du8, 0xdb, 0x51, 0x4f, 0x2c, 0x6a, 0x35, 0x49, 0x80, 0x1e, 0x40, 0x1e, 0x31, 0x45,
            0xdd, 0x88, 0x4a, 0x6a, 0x47, 0x2c, 0x8a, 0x09, 0xa6, 0xf9, 0xa3, 0x18, 0x79, 0x85,
            0xa3, 0x4e, 0xcb, 0x59, 0xa2, 0xbb, 0x49, 0x15, 0x40, 0x9b, 0x8d, 0x89, 0x25, 0x05,
            0x5d, 0xa0, 0x6a, 0xb3, 0xb1, 0x07, 0x57, 0xde, 0x46, 0x43, 0x37, 0xd7, 0x0b, 0x29,
            0x56, 0x67, 0xf9, 0x7a, 0xbb, 0x33, 0x78, 0x3d, 0x5f, 0x38, 0x5a, 0xb8, 0x77, 0x38,
            0x1b, 0xac, 0x7c, 0x15, 0xdb, 0xcf, 0x85, 0xe9, 0x38, 0x51, 0x94, 0x39, 0x7d, 0x05,
            0x34, 0x2e, 0x32, 0x64, 0xb7, 0x72, 0x49, 0x51, 0xbd, 0x61, 0xf6, 0x8c, 0x0b, 0x7f,
            0xa1, 0x02, 0x97, 0xa2, 0xe0, 0x41, 0x35, 0xdc, 0xe5, 0x5c, 0x55, 0x74, 0xab, 0x02,
            0xcf, 0x63, 0x76, 0x96, 0x98, 0xa6, 0xec, 0x0d, 0x94, 0xa3, 0xa2, 0xf5, 0xbe, 0xee,
            0x0a, 0xdd, 0x0f, 0x5d, 0x9e, 0x96, 0x7a, 0x73, 0x6d, 0xb7, 0x45, 0xbd, 0xda, 0xa7,
            0x90, 0xf7, 0x49, 0x16, 0x0f, 0x42, 0xf1, 0x03, 0x70, 0x3f, 0xec, 0xb4, 0xa8, 0x09,
            0x55, 0xa0, 0x5c, 0x7a, 0x7a, 0x29, 0xac, 0xf6, 0x13, 0xd8, 0xac, 0x08, 0x15, 0x5c,
            0xab, 0x2f, 0x59, 0xc0, 0xc3, 0xe3, 0x3d, 0x2d, 0x1b, 0xb0, 0x56, 0x0a, 0xde, 0x03,
            0x94, 0x30, 0x86, 0xdf, 0x7d, 0xa7, 0x48, 0x4a, 0x8c, 0x7b, 0x6d, 0xca, 0x10, 0x79,
            0x6d, 0x42, 0x69, 0x79, 0xbd, 0x02, 0x1d, 0x22, 0x00, 0x94, 0x98, 0x5f, 0x94, 0x89,
            0x0b, 0xca, 0xdc, 0x03, 0x54, 0xb2, 0x89, 0x93, 0x1f, 0xf4, 0x56, 0x4c, 0x98, 0xdf,
            0xf8, 0xe5, 0x32, 0x69, 0x5d, 0x21, 0xc8, 0x2f, 0x46, 0x18, 0xfd, 0x60, 0x98, 0x7d,
            0x98, 0xee, 0x04, 0x09, 0xfb, 0xa4, 0x8a, 0xe4, 0x46, 0xdf, 0xfe, 0xc7, 0x1d, 0xb9,
            0x57, 0x40, 0x69, 0xb4,
        ];

        let bit = asn1_encode_bit_string(&sign).await.unwrap();
        let c = vec![
            0x03, 0x82, 0x01, 0x00, 0x6d, 0xdb, 0x51, 0x4f, 0x2c, 0x6a, 0x35, 0x49, 0x80, 0x1e,
            0x40, 0x1e, 0x31, 0x45, 0xdd, 0x88, 0x4a, 0x6a, 0x47, 0x2c, 0x8a, 0x09, 0xa6, 0xf9,
            0xa3, 0x18, 0x79, 0x85, 0xa3, 0x4e, 0xcb, 0x59, 0xa2, 0xbb, 0x49, 0x15, 0x40, 0x9b,
            0x8d, 0x89, 0x25, 0x05, 0x5d, 0xa0, 0x6a, 0xb3, 0xb1, 0x07, 0x57, 0xde, 0x46, 0x43,
            0x37, 0xd7, 0x0b, 0x29, 0x56, 0x67, 0xf9, 0x7a, 0xbb, 0x33, 0x78, 0x3d, 0x5f, 0x38,
            0x5a, 0xb8, 0x77, 0x38, 0x1b, 0xac, 0x7c, 0x15, 0xdb, 0xcf, 0x85, 0xe9, 0x38, 0x51,
            0x94, 0x39, 0x7d, 0x05, 0x34, 0x2e, 0x32, 0x64, 0xb7, 0x72, 0x49, 0x51, 0xbd, 0x61,
            0xf6, 0x8c, 0x0b, 0x7f, 0xa1, 0x02, 0x97, 0xa2, 0xe0, 0x41, 0x35, 0xdc, 0xe5, 0x5c,
            0x55, 0x74, 0xab, 0x02, 0xcf, 0x63, 0x76, 0x96, 0x98, 0xa6, 0xec, 0x0d, 0x94, 0xa3,
            0xa2, 0xf5, 0xbe, 0xee, 0x0a, 0xdd, 0x0f, 0x5d, 0x9e, 0x96, 0x7a, 0x73, 0x6d, 0xb7,
            0x45, 0xbd, 0xda, 0xa7, 0x90, 0xf7, 0x49, 0x16, 0x0f, 0x42, 0xf1, 0x03, 0x70, 0x3f,
            0xec, 0xb4, 0xa8, 0x09, 0x55, 0xa0, 0x5c, 0x7a, 0x7a, 0x29, 0xac, 0xf6, 0x13, 0xd8,
            0xac, 0x08, 0x15, 0x5c, 0xab, 0x2f, 0x59, 0xc0, 0xc3, 0xe3, 0x3d, 0x2d, 0x1b, 0xb0,
            0x56, 0x0a, 0xde, 0x03, 0x94, 0x30, 0x86, 0xdf, 0x7d, 0xa7, 0x48, 0x4a, 0x8c, 0x7b,
            0x6d, 0xca, 0x10, 0x79, 0x6d, 0x42, 0x69, 0x79, 0xbd, 0x02, 0x1d, 0x22, 0x00, 0x94,
            0x98, 0x5f, 0x94, 0x89, 0x0b, 0xca, 0xdc, 0x03, 0x54, 0xb2, 0x89, 0x93, 0x1f, 0xf4,
            0x56, 0x4c, 0x98, 0xdf, 0xf8, 0xe5, 0x32, 0x69, 0x5d, 0x21, 0xc8, 0x2f, 0x46, 0x18,
            0xfd, 0x60, 0x98, 0x7d, 0x98, 0xee, 0x04, 0x09, 0xfb, 0xa4, 0x8a, 0xe4, 0x46, 0xdf,
            0xfe, 0xc7, 0x1d, 0xb9, 0x57, 0x40, 0x69, 0xb4,
        ];

        assert_eq!(c, bit);
    }

    /// test certid to ASN.1 DER
    #[tokio::test]
    async fn certid_to_der() {
        let oid = Oid::new_from_dot(ALGO_SHA1_DOT).await.unwrap();
        let name = vec![
            0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23,
            0x60, 0x14, 0x78, 0xb7, 0x88, 0x20,
        ];
        let key = vec![
            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a,
            0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55,
        ];
        let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
        let certid = CertId::new(oid, &name, &key, &sn).await;
        let v = certid.to_der().await.unwrap();
        let c = vec![
            0x30, 0x41, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14, 0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
            0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20, 0x04, 0x14, 0x39, 0x7b, 0xe0, 0x02, 0xa2,
            0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7,
            0x55, 0x02, 0x08, 0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f,
        ];

        assert_eq!(c, v);
    }

    /// test oid to ASN.1 DER
    #[tokio::test]
    async fn oid_to_der() {
        let oid = Oid::new_from_dot(ALGO_SHA1_DOT).await.unwrap();
        let v = oid.to_der_with_null().await.unwrap();
        assert_eq!(
            vec![0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00],
            v
        );
    }

    /// test oid dot notation to internal
    #[tokio::test]
    async fn oid_dot_new() {
        let dot = OCSP_EXT_CRL_REASON_DOT;
        let d = Oid::new_from_dot(dot).await.unwrap().index;
        assert_eq!(d, OCSP_EXT_CRL_REASON_ID);
    }

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
                0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x33, 0x30, 0x33, 0x30, 0x39,
                0x32, 0x35, 0x5a
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
