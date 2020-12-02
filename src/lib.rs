//! ocsp-rs provides de/serialization for ocsp request and response in asn.1 der

//#![deny(
//    bad_style,
//    const_err,
//    dead_code,
//    improper_ctypes,
//    non_shorthand_field_patterns,
//    no_mangle_generic_items,
//    overflowing_literals,
//    path_statements,
//    patterns_in_fns_without_body,
//    private_in_public,
//    unconditional_recursion,
//    unused,
//    unused_allocation,
//    unused_comparisons,
//    unused_parens,
//    while_true,
//    // following are default allowed lint
//    //missing_debug_implementations, //disabled cuz asn1_der does not impl Debug
//    missing_docs,
//    trivial_casts,
//    trivial_numeric_casts,
//    unused_extern_crates,
//    unused_import_braces,
//    unused_qualifications,
//    unused_results
//)]

pub mod asn1_common;
pub mod err;
//pub struct OcspRequest {}

#[cfg(test)]
mod tests {
    use asn1_der::{
        //Boolean, DerDecodable, DerEncodable, DerTypeView, Integer, Null, OctetString, Sequence,
        //SequenceVec, Utf8String
        typed::{DerDecodable, Sequence},
        DerObject, //SliceSink,
    };
    use hex;

    use super::asn1_common::*;
    /// test data produces an ocsp request generated by openssl.
    #[test]
    fn ocsp_req_from_der() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
03021a05000414694d18a9be42f78026\
14d4844f23601478b788200414397be0\
02a2f571fd80dceb52a17a7f8b632be7\
5502086378e51d448ff46da223302130\
1f06092b060105050730010204120410\
1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let seq = Sequence::decode(asn1.raw()).unwrap();
        let first_item = seq.get(0).unwrap();
        let seq = Sequence::decode(first_item.raw()).unwrap();
        let _second_item = seq.get(1).unwrap();
    }

    #[test]
    fn ocsp_req_get_certid() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
03021a05000414694d18a9be42f78026\
14d4844f23601478b788200414397be0\
02a2f571fd80dceb52a17a7f8b632be7\
5502086378e51d448ff46da223302130\
1f06092b060105050730010204120410\
1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let asn1 = OcspAsn1Der::parse(&asn1).unwrap();
        let mut res = Vec::new();
        let mut val: Vec<Vec<u8>> = Vec::new();
        let _ = asn1.extract_certid(&mut res, &mut val);
        println!("-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----", res, val);
    }
}
