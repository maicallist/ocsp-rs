use super::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

pub struct OcspDer {
    der: Vec<u8>,
}

async fn count_matching_tags(target: &[u8], tbm: &[u8]) -> usize {
    let mut tt = target.to_vec();
    while tt.len() < tbm.len() {
        tt.extend(target);
    }
    let tt = &tt[..tbm.len()];
    tbm.iter().zip(tt).filter(|(m, t)| m == t).count()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ocsp_req_get_certid() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46da223302130\
    1f06092b060105050730010204120410\
    1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req = hex::decode(ocsp_req_hex).unwrap();
        let ocsp_der = OcspDer { der: ocsp_req };
        //let mut tag = Vec::new();
        //let mut val = Vec::new();

        //let _ = extract_id(ocsp_der);
        //println!(
        //    "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
        //    tag, val
        //);
        //assert_eq!(tag, vec![0x06u8, 0x05, 0x04, 0x04, 0x02]);
        //assert_eq!(
        //    val,
        //    vec![
        //        vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
        //        vec![],
        //        vec![
        //            0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
        //            0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
        //        ],
        //        vec![
        //            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
        //            0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
        //        ],
        //        vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d]
        //    ]
        //);
    }
}
