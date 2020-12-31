//! common traits and const

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use crate::oid::*;
use crate::{err::OcspError, oid::ConstOid};
use crate::{err_at, oid::OID_LIST};

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

/// RFC 6960 4.4 OCSP extensions
#[derive(Debug)]
pub enum OcspExt {
    /// 4.4.1
    Nonce {
        ///id-pkix-ocsp 2
        oid: &'static ConstOid,
        /// nonce value
        nonce: Vec<u8>,
    },
    /// 4.4.2  
    /// REVIEW: untested
    CrlRef {
        /// id-pkix-ocsp 3
        oid: &'static ConstOid,
        /// EXPLICIT 0 IA5String OPTIONAL
        url: Option<Vec<u8>>,
        /// EXPLICIT 1 INTEGER OPTIONAL
        num: Option<Vec<u8>>,
        /// EXPLICIT 2 GeneralizedTime OPTIONAL
        time: Option<Vec<u8>>,
    },
}

impl OcspExt {
    /// parse ocsp extension  
    /// raw is sequence of list extensions  
    /// remove explicit and implicit tags first
    pub async fn parse<'d>(raw: &[u8]) -> Result<Vec<Self>, OcspError> {
        let mut r: Vec<OcspExt> = Vec::new();
        let list = raw.try_into()?;
        for i in 0..list.len() {
            let ext: Sequence = list.get_as(i).map_err(OcspError::Asn1DecodingError)?;
            r.push(OcspExt::parse_oneext(ext).await?);
        }
        Ok(r)
    }

    /// pass in each sequence of extension, return OcspExt
    async fn parse_oneext<'d>(oneext: Sequence<'d>) -> Result<Self, OcspError> {
        let oid = oneext.get(0).map_err(OcspError::Asn1DecodingError)?;
        if oid.tag() != ASN1_OID {
            return Err(OcspError::Asn1MismatchError("OID", err_at!()));
        }
        let val = oid.value();
        // translate oid
        let ext = match OID_LIST.get(val) {
            None => return Err(OcspError::Asn1OidUnknown(err_at!())),
            Some(v) => v,
        };

        let r = match ext.id {
            OCSP_EXT_NONCE_ID => OcspExt::Nonce {
                oid: ext,
                nonce: oneext
                    .get(1)
                    .map_err(OcspError::Asn1DecodingError)?
                    .value()
                    .to_vec(),
            },
            OCSP_EXT_CRLREF_ID => {
                let mut url = None;
                let mut num = None;
                let mut time = None;
                for i in 1..oneext.len() {
                    let tmp = oneext.get(i).map_err(OcspError::Asn1DecodingError)?;
                    let val = match tmp.tag() {
                        ASN1_EXPLICIT_0..=ASN1_EXPLICIT_2 => tmp.value(),
                        _ => return Err(OcspError::Asn1MismatchError("Ext CrlRef", err_at!())),
                    };
                    match tmp.tag() {
                        ASN1_EXPLICIT_0 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            url = Some(val.value().to_vec());
                        }
                        ASN1_EXPLICIT_1 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            num = Some(val.value().to_vec());
                        }
                        ASN1_EXPLICIT_2 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            time = Some(val.value().to_vec());
                        }
                        _ => {
                            return Err(OcspError::Asn1MismatchError(
                                "Ext CrlRef EXP tag",
                                err_at!(),
                            ))
                        }
                    }
                }

                OcspExt::CrlRef {
                    oid: ext,
                    url: url,
                    num: num,
                    time: time,
                }
            }
            _ => unimplemented!(),
        };

        Ok(r)
    }
}
