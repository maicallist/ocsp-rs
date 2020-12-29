//! common traits and const

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use futures::future::{BoxFuture, FutureExt};

use crate::oid::*;
use crate::{err::OcspError, oid::ConstOid};
use crate::{err_at, oid::OID_LIST};

/// asn1 context-specific explicit tag 0
pub(crate) const ASN1_EXPLICIT_0: u8 = 0xa0;
pub(crate) const ASN1_NULL: u8 = 0x05;
pub(crate) const ASN1_OID: u8 = 0x06;
pub(crate) const ASN1_SEQUENCE: u8 = 0x30;
pub(crate) const ASN1_OCTET: u8 = 0x04;
pub(crate) const ASN1_INTEGER: u8 = 0x02;

/// allowing data to be converted to asn1_der::typed::Sequence
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

/// RFC 6960 4.4
pub enum OcspExt {
    /// 4.4.1
    Nonce {
        ///id-pkix-ocsp 2
        oid: &'static ConstOid,
        /// nonce value
        nonce: Vec<u8>,
    },
    /// 4.4.2
    CrlRef {
        /// id-pkix-ocsp 3
        oid: &'static ConstOid,
        /// EXPLICIT IA5String OPTIONAL
        url: Option<Vec<u8>>,
        /// EXPLICIT INTEGER OPTIONAL
        num: Option<Vec<u8>>,
        /// EXPLICIT GeneralizedTime OPTIONAL
        time: Option<Vec<u8>>,
    },
}

impl OcspExt {
    /// parse ocsp extension  
    /// raw is sequence of list extensions  
    /// remove explicit and implicit tags first
    pub fn parse<'d>(raw: Vec<u8>) -> BoxFuture<'d, Result<Vec<Self>, OcspError>> {
        async move {
            let mut r: Vec<OcspExt> = Vec::new();
            let list = raw.try_into()?;
            for i in 0..list.len() {
                let ext: Sequence = list.get_as(i).map_err(OcspError::Asn1DecodingError)?;
                r.push(OcspExt::parse_oneext(ext).await?);
            }
            Ok(r)
        }
        .boxed()
    }

    /// pass in each sequence of extension, return OcspExt
    fn parse_oneext<'d>(oneext: Sequence<'d>) -> BoxFuture<'d, Result<Self, OcspError>> {
        async move {
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
                //2u8 => OcspExt::CrlRef { oid: ext },
                _ => unimplemented!(),
            };

            Ok(r)
        }
        .boxed()
    }
}
