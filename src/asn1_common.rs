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
    /// Extracting CertId Sequence from ASN1 DER data.  
    /// tags must match following hex order:  
    /// 30(6, 5), 4, 4, 2  
    ///
    /// - **self.seq** A sequence to be examined
    /// - **tag** CertId tag array  
    /// per rfc 6960 CERTID matches sequence of OID, OCTET, OCTET, INTEGER,  
    /// thus tag should contain 0x06, 0x05, 0x04, 0x04, 0x02 as result.  
    /// In practice, openssl has 0x05 after OID 0x06.  
    /// - **value** corresponding value of @tag array  
    fn extract_certid(&self, tag: &mut Vec<u8>, value: &mut Vec<Vec<u8>>) -> Result<u8, OcspError>;
}
