//! common traits and const

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use crate::err::OcspError;

/// asn1 context-specific explicit tag 0
pub(crate) const ASN1_EXPLICIT_0: u8 = 0xa0;

/// CertID asn1 sequence
/// see [ocsp_rs::asn1_common::OcspAsn1Der::extract_id]
pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

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
