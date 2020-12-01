use super::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
/// see [ocsp_rs::asn1_req::OcspRequestAsn1::extract_certid()]
pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

/// count number of matching tag to a sequence
/// - **target** target tag sequence
/// - **tbm** tag sequence to be examined
pub(crate) fn count_match_tags(target: &Vec<u8>, tbm: &Vec<u8>) -> usize {
    if tbm.len() > target.len() {
        return 0;
    }

    let partial = &target[0..tbm.len()];
    tbm.iter().zip(partial).filter(|(t, p)| t == p).count()
}

pub trait TryIntoSequence {
    type Error;
    fn try_into(&self) -> Result<Sequence, Self::Error>;
}

impl TryIntoSequence for DerObject<'_> {
    type Error = OcspError;
    fn try_into(&self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self.raw()).map_err(OcspError::Asn1DecodingError)
    }
}

/// common asn1 value extractions
pub trait DecodeAsn1 {
    /// extract CERTID sequence
    /// - &self request or response with field 'seq' containing the sequence data
    /// - tag extracted tag sequence
    /// - value corresponding value of 'tag'
    fn extract_certid(&self, tag: &mut Vec<u8>, value: &mut Vec<u8>) -> Result<u8, OcspError>;
}
