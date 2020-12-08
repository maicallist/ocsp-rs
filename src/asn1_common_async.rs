use super::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use async_recursion::async_recursion;

pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

pub struct OcspDer {
    der: Vec<u8>,
}

#[async_recursion]
pub async fn extract_id(od: OcspDer) -> Result<u8, OcspError> {
    let seq = Sequence::decode(&od.der).map_err(OcspError::Asn1DecodingError)?;
    for i in 0..seq.len() {
        let tmp = seq.get(i).map_err(OcspError::Asn1DecodingError)?;
        match tmp.tag() {
            0x30 => {
                let mut raw = tmp.header().to_vec();
                raw.extend(tmp.value());
                let d = OcspDer { der: raw };
                match extract_id(d).await? {
                    0 => break,
                    1 => continue,
                    _ => return Err(OcspError::Asn1ExtractionUnknownError),
                }
            }
            _ => break,
        }
    }

    Ok(1)
}

#[async_recursion(?Send)]
async fn fib(n: u32) -> u64 {
    match n {
        0 => panic!("zero is not a valid argument to fib()!"),
        1 | 2 => 1,
        3 => 2,
        _ => fib(n - 1).await + fib(n - 2).await,
    }
}

//pub async fn ext_id(
//    od: OcspDer,
//    tag: Box<Mutex<Vec<u8>>>,
//    val: Box<Mutex<Vec<Vec<u8>>>>,
//) -> BoxFuture<'static, Result<u8, OcspError>> {
//    Box::pin(async move {
//        let mut examine = false;
//        let seq = Sequence::decode(&od.der).map_err(OcspError::Asn1DecodingError)?;
//
//        for i in 0..seq.len() {
//            let tmp = seq.get(i).map_err(OcspError::Asn1DecodingError)?;
//            match tmp.tag() {
//                0x30 => {
//                    let mut raw = tmp.header().to_vec();
//                    raw.extend(tmp.value());
//                    let d = OcspDer { der: raw };
//                    let a = ext_id(d, tag, val);
//                }
//                _ => break,
//            }
//        }
//        unimplemented!()
//    })
//
//
//    let mut examine = false;
//    let seq = match Sequence::decode(&od.der) {
//        Ok(s) => s,
//        Err(e) => {
//            error!(
//                "Unable to parse DER data while extracting cert id, due to {}",
//                e
//            );
//            return Box::pin(err::<u8, OcspError>(OcspError::Asn1DecodingError(e)));
//        }
//    };
//
//    for i in 0..seq.len() {
//        //let tmp = seq.get(i).map_err(OcspError::Asn1DecodingError)?;
//        let tmp = match seq.get(i) {
//            Ok(t) => t,
//            Err(e) => {
//                error!(
//                    "Unable to parse sequence in DER data while extracting cert id, due to {}",
//                    e
//                );
//                return Box::pin(err::<u8, OcspError>(OcspError::Asn1DecodingError(e)));
//            }
//        };
//        match tmp.tag() {
//            0x30 => {
//                let mut v = tmp.header().to_vec().to_vec();
//                v.extend(tmp.value());
//                let d = OcspDer { der: v };
//                let a = async move { ext_id(d, tag, val).await };
//
//                match ext_id(d, tag, val).await? {
//                    0 => break,
//                    1 => continue,
//                    _ => return Box::pin(err::<u8, OcspError>(OcspError::Asn1ExtractionUnknownError)), //return Err(OcspError::Asn1ExtractionUnknownError),
//                }
//            }
//            0x02 | 0x04 | 0x05 | 0x06 => {
//                tag.push(tmp.tag());
//                val.push(tmp.value().to_vec());
//                examine = true;
//            }
//            _ => break,
//        }
//    }
//
//    let target_len = CERTID_TAG.len();
//    if examine {
//        match count_matching_tags(&CERTID_TAG, tag).await % target_len {
//            0 => return Box::pin(ok::<u8, OcspError>(1)),
//            2 => return Box::pin(ok::<u8, OcspError>(1)),
//            _ => {
//                tag.truncate(tag.len() / target_len);
//                val.truncate(val.len() / target_len);
//                return Box::pin(ok::<u8, OcspError>(0));
//            }
//        }
//    }
//    Box::pin(ok::<u8, OcspError>(1))
//}

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

        let _ = extract_id(ocsp_der);
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
