//! OCSP request

use asn1_der::{typed::Sequence, DerObject};
use futures::future::{BoxFuture, FutureExt};

use crate::common::{
    OcspExt, TryIntoSequence, ASN1_EXPLICIT_0, ASN1_INTEGER, ASN1_NULL, ASN1_OCTET, ASN1_OID,
    ASN1_SEQUENCE,
};
use crate::err::OcspError;

/// Oid represents a 0x06 OID type in ASN.1  
/// in OpenSSL ocsp request, OID is followed by NULL 0x05
/// REVIEW 0x05
pub struct Oid {
    id: Vec<u8>,
    //null: Vec<u8>,
}

impl Oid {
    /// get oid from raw bytes
    pub fn parse<'d>(oid: Vec<u8>) -> BoxFuture<'d, Result<Self, OcspError>> {
        async move {
            let s = oid.try_into()?;
            if s.len() != 2 {
                return Err(OcspError::Asn1OidLengthError);
            }
            let id = s.get(0).map_err(OcspError::Asn1DecodingError)?;
            let nil = s.get(1).map_err(OcspError::Asn1DecodingError)?;
            if id.tag() != ASN1_OID || nil.tag() != ASN1_NULL {
                return Err(OcspError::Asn1MismatchError("OID".to_owned()));
            }

            Ok(Oid {
                id: id.value().to_vec(),
            })
        }
        .boxed()
    }
}

/// RFC 6960 CertID
pub struct CertId {
    hash_algo: Oid,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_num: Vec<u8>,
}

impl CertId {
    /// get certid from raw bytes
    pub fn parse<'d>(self, certid: Vec<u8>) -> BoxFuture<'d, Result<Self, OcspError>> {
        async move {
            let s = certid.try_into()?;
            if s.len() != 4 {
                return Err(OcspError::Asn1CertidLengthError);
            }

            let oid = s.get(0).map_err(OcspError::Asn1DecodingError)?;
            let name_hash = s.get(1).map_err(OcspError::Asn1DecodingError)?;
            let key_hash = s.get(2).map_err(OcspError::Asn1DecodingError)?;
            let sn = s.get(3).map_err(OcspError::Asn1DecodingError)?;

            if oid.tag() != ASN1_SEQUENCE
                || name_hash.tag() != ASN1_OCTET
                || key_hash.tag() != ASN1_OCTET
                || sn.tag() != ASN1_INTEGER
            {
                return Err(OcspError::Asn1MismatchError("CertId".to_owned()));
            }

            let oid = Oid::parse(oid.value().to_vec()).await?;
            let name_hash = name_hash.value().to_vec();
            let key_hash = key_hash.value().to_vec();
            let sn = sn.value().to_vec();

            Ok(CertId {
                hash_algo: oid,
                issuer_name_hash: name_hash,
                issuer_key_hash: key_hash,
                serial_num: sn,
            })
        }
        .boxed()
    }
}
/// RFC 6960 Request
pub struct OneReq {
    one_req: CertId,
    one_req_ext: OcspExt,
}

impl OneReq {
    /// get single request
    pub fn parse<'d>() -> BoxFuture<'d, Result<Self, OcspError>> {
        async move { unimplemented!() }.boxed()
    }
}

/// RFC 6960 OCSPRequest
pub struct OcspRequest<'d> {
    /// RFC 6960 TBSRequest
    tbs_request: Sequence<'d>,
    /// RFC 6960 optionalSignature, explicit tag 0
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

/// RFC 6960 TBSRequest  
/// version is omitted as data produced from OpenSSL doesn't contain version  
/// REVIEW: omit version in tbs request
pub struct TBSRequest<'d> {
    // explicit tag 0
    // version: u8,
    /// requestorName is OPTIONAL and indicates the name of the OCSP requestor.
    /// explicit 1
    requestor_name: Option<Vec<u8>>,
    /// requestList contains one or more single certificate status requests.
    request_list: Vec<Sequence<'d>>,
    /// requestExtensions is OPTIONAL and includes extensions applicable
    /// to the requests found in reqCert.
    request_ext: Option<DerObject<'d>>,
}

impl<'d> TBSRequest<'d> {
    /// parse requestor name from vec\<u8\> via str::from_utf8()
    pub fn get_requestor_name(&'d self) -> BoxFuture<'d, Result<&'d str, OcspError>> {
        async move {
            match &self.requestor_name {
                None => Ok(""),
                Some(v) => {
                    let name = std::str::from_utf8(v).map_err(OcspError::Asn1Utf8Error)?;
                    Ok(name)
                }
            }
        }
        .boxed()
    }

    /// get list of onereq[OpenSSL]
    pub fn get_request_list(self) -> BoxFuture<'d, Vec<Sequence<'d>>> {
        async move { self.request_list }.boxed()
    }

    /// get extension for ocsp request
    pub fn get_request_ext(self) -> BoxFuture<'d, Option<DerObject<'d>>> {
        async move { self.request_ext }.boxed()
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
