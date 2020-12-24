//! OCSP request

/// RFC 6960 CertID
pub struct CertId {
    hash_algo: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_num: Vec<u8>,
}

/// RFC 6960 OCSPRequest
pub struct OcspRequest {
    raw: Vec<u8>,
    tbs_request: Vec<u8>,
    optional_signature: Option<Vec<u8>>,
}

impl OcspRequest {
    fn get_tbs_req(raw: &Vec<u8>) -> Vec<u8> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use asn1_der::{
        typed::{DerDecodable, Sequence, SequenceVec},
        DerObject,
    };
    use hex;

    // test confirms context specific tag cannot be recognized
    #[test]
    #[should_panic(expected = "sequence cannot recognize context specific tag")]
    fn context_specific_sequence() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46da223302130\
    1f06092b060105050730010204120410\
    1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req = hex::decode(ocsp_req_hex).unwrap();
        let der = DerObject::decode(&ocsp_req[..]).unwrap();
        //println!("tag {:02X?}\nvalue {:02X?}", der.header(), der.value());

        let tbs = DerObject::decode(der.value()).unwrap();
        //println!("tag {:02X?}\nvalue {:02X?}", tbs.header(), tbs.value());

        let reqlist = DerObject::decode(tbs.value()).unwrap();
        //println!(
        //    "tag {:02X?}\nvalue {:02X?}",
        //    reqlist.header(),
        //    reqlist.value()
        //);

        let ocspseq = Sequence::decode(der.value()).unwrap();
        let t = ocspseq.get(1).unwrap().header();
        let v = ocspseq.get(1).unwrap().value();
        let mut t = t.to_vec();
        t.extend(v);
        //println!("context specific exp tag 2{:02X?}", t);
        let _ = Sequence::decode(&t[..]).unwrap();
    }
}
