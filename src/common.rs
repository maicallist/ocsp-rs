use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use crate::err::OcspError;

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
