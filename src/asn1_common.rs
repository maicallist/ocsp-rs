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
