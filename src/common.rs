use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use crate::err::OcspError;

pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

/// allow convert to asn1_der::typed::Sequence
pub trait TryIntoSequence {
    /// converting asn1_der::err
    type Error;
    /// try converting to Sequence
    fn try_into(&self) -> Result<Sequence, Self::Error>;
}

impl TryIntoSequence for DerObject<'_> {
    type Error = OcspError;
    fn try_into(&self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self.raw()).map_err(OcspError::Asn1DecodingError)
    }
}
