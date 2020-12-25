//! OCSP request

use asn1_der::{typed::Sequence, DerObject};
use futures::future::{BoxFuture, FutureExt};
use std::convert::TryFrom;

use crate::common::{TryIntoSequence, ASN1_EXPLICIT_0};
use crate::err::OcspError;

/// RFC 6960 CertID
pub struct CertId {
    hash_algo: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_num: Vec<u8>,
}

/// RFC 6960 OCSPRequest
pub struct OcspRequest<'d> {
    /// RFC 6960 TBSRequest
    tbs_request: Sequence<'d>,
    /// RFC 6960 optionalSignature, explicit tag [0]
    optional_signature: Option<DerObject<'d>>,
}

impl<'d> OcspRequest<'d> {
    /// create OcspRequest from Vec<u8>
    pub fn parse(raw: &'d Vec<u8>) -> BoxFuture<'d, Result<Self, OcspError>> {
        async move {
            let s = raw.try_into()?;
            match s.len() {
                1 => {
                    let tbs: Sequence = s.get_as(0).map_err(OcspError::Asn1DecodingError)?;
                    return Ok(OcspRequest {
                        tbs_request: tbs,
                        optional_signature: None,
                    });
                }
                2 => {
                    let tbs: Sequence = s.get_as(0).map_err(OcspError::Asn1DecodingError)?;
                    let sig = s.get(1).map_err(OcspError::Asn1DecodingError)?;
                    // per RFC 6960
                    // optional signature is explicit 0
                    if sig.tag() != ASN1_EXPLICIT_0 {
                        return Err(OcspError::Asn1MalformedTBSRequest);
                    }
                    return Ok(OcspRequest {
                        tbs_request: tbs,
                        optional_signature: Some(sig),
                    });
                }
                _ => return Err(OcspError::Asn1MalformedTBSRequest),
            }
        }
        .boxed()
    }

    /// return RFC 6960 TBSRequest
    pub fn get_tbs_req(self) -> BoxFuture<'d, Sequence<'d>> {
        async move { self.tbs_request }.boxed()
    }

    /// return RFC 6960 optionalSignature
    pub fn get_signature(self) -> BoxFuture<'d, Option<DerObject<'d>>> {
        async move { self.optional_signature }.boxed()
    }
}

#[allow(dead_code)]
impl<'d> TryFrom<&'d Vec<u8>> for OcspRequest<'d> {
    type Error = OcspError;
    fn try_from(raw: &'d Vec<u8>) -> Result<Self, Self::Error> {
        let s = raw.try_into()?;
        match s.len() {
            1 => {
                let tbs: Sequence = s.get_as(0).map_err(OcspError::Asn1DecodingError)?;
                return Ok(OcspRequest {
                    tbs_request: tbs,
                    optional_signature: None,
                });
            }
            2 => {
                let tbs: Sequence = s.get_as(0).map_err(OcspError::Asn1DecodingError)?;
                let sig = s.get(1).map_err(OcspError::Asn1DecodingError)?;
                // per RFC 6960
                // optional signature is explicit 0
                if sig.tag() != 0xa0 {
                    return Err(OcspError::Asn1MalformedTBSRequest);
                }
                return Ok(OcspRequest {
                    tbs_request: tbs,
                    optional_signature: Some(sig),
                });
            }
            _ => return Err(OcspError::Asn1MalformedTBSRequest),
        }
    }
}

#[cfg(test)]
mod test {
    use asn1_der::{
        typed::{DerDecodable, Sequence},
        DerObject,
    };
    use hex;

    use super::OcspRequest;

    #[tokio::test]
    async fn ocsprequest_parse_from_v8() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46da223302130\
    1f06092b060105050730010204120410\
    1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_v8 = hex::decode(ocsp_req_hex).unwrap();
        let ocsp_request = OcspRequest::parse(&ocsp_req_v8).await;
        assert!(ocsp_request.is_ok());
        let _ = ocsp_request.unwrap();
    }

    // test confirms context specific tag cannot be recognized
    #[test]
    #[should_panic]
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

        let _reqlist = DerObject::decode(tbs.value()).unwrap();
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
