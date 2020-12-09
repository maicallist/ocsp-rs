use super::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use futures::future::{BoxFuture, FutureExt};

pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

pub struct OcspAsn1DerAsync<'d> {
    seq: Sequence<'d>,
}

impl<'d> OcspAsn1DerAsync<'d> {
    fn extract_certid(
        &'d self,
        tag: &'d mut Vec<u8>,
        val: &'d mut Vec<Vec<u8>>,
    ) -> BoxFuture<'d, Result<u8, OcspError>> {
        async move {
            let mut examine = false;
            for i in 0..self.seq.len() {
                let tmp = self.seq.get(i).map_err(OcspError::Asn1DecodingError)?;
                match tmp.tag() {
                    0x30 => {
                        let mut raw = tmp.header().to_vec();
                        raw.extend(tmp.value());
                        let tseq =
                            Sequence::decode(&raw[..]).map_err(OcspError::Asn1DecodingError)?;

                        match OcspAsn1DerAsync::extract_certid(
                            &OcspAsn1DerAsync { seq: tseq },
                            tag,
                            val,
                        )
                        .await?
                        {
                            0 => break,
                            1 => continue,
                            _ => return Err(OcspError::Asn1ExtractionUnknownError),
                        }
                    }
                    0x02 | 0x04 | 0x05 | 0x06 => {
                        tag.push(tmp.tag());
                        val.push(tmp.value().to_vec());
                        examine = true;
                    }
                    _ => break,
                }
            }

            if examine {
                match count_matching_tags(&CERTID_TAG, tag).await % CERTID_TAG.len() {
                    0 | 2 => return Ok(1),
                    _ => {
                        tag.truncate(tag.len() / CERTID_TAG.len());
                        val.truncate(val.len() / CERTID_TAG.len());
                        return Ok(0);
                    }
                }
            }

            Ok(1)
        }
        .boxed()
    }
}

//pub struct OcspDer {
//    der: Vec<u8>,
//}
//
//fn ext_id<'d>(
//    od: OcspDer,
//    tag: &'d mut Vec<u8>,
//    val: &'d mut Vec<Vec<u8>>,
//) -> BoxFuture<'d, Result<u8, OcspError>> {
//    //async move {
//    //    ext_id().await;
//    //    let a = count_matching_tags(&vec![1u8][..], &vec![2u8][..]).await;
//    //}
//    //.boxed()
//
//    async move {
//        let mut examine = false;
//        let seq = Sequence::decode(&od.der).map_err(OcspError::Asn1DecodingError)?;
//        for i in 0..od.der.len() {
//            let tmp = seq.get(i).map_err(OcspError::Asn1DecodingError)?;
//            match tmp.tag() {
//                0x30 => {
//                    let mut v = tmp.header().to_vec();
//                    v.extend(tmp.value());
//                    let d = OcspDer { der: v };
//                    match ext_id(d, tag, val).await? {
//                        0 => break,
//                        1 => continue,
//                        _ => return Err(OcspError::Asn1ExtractionUnknownError),
//                    }
//                }
//                0x02 | 0x04 | 0x05 | 0x06 => {
//                    tag.push(tmp.tag());
//                    val.push(tmp.value().to_vec());
//                    examine = true
//                }
//                _ => break,
//            }
//        }
//
//        if examine {
//            let target_len = CERTID_TAG.len();
//            match count_matching_tags(&CERTID_TAG, tag).await % target_len {
//                0 | 2 => return Ok(1),
//                _ => {
//                    tag.truncate(tag.len() / target_len);
//                    val.truncate(val.len() / target_len);
//                    return Ok(0);
//                }
//            }
//        }
//
//        Ok(1)
//    }
//    .boxed()
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
    use tokio;

    #[tokio::test]
    async fn ocsp_req_get_certid() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46da223302130\
    1f06092b060105050730010204120410\
    1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req = hex::decode(ocsp_req_hex).unwrap();
        let seq = Sequence::decode(&ocsp_req[..]).unwrap();
        let der = OcspAsn1DerAsync { seq: seq };
        let mut tag = Vec::new();
        let mut val = Vec::new();
        let _ = der.extract_certid(&mut tag, &mut val).await;

        println!(
            "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
            tag, val
        );
        assert_eq!(tag, vec![0x06u8, 0x05, 0x04, 0x04, 0x02]);
        assert_eq!(
            val,
            vec![
                vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
                vec![],
                vec![
                    0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
                    0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
                ],
                vec![
                    0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
                    0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
                ],
                vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d]
            ]
        );
    }
}
