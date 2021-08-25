//! OCSP request

use std::{collections::HashMap, vec};

use asn1_der::DerObject;
use tracing::{debug, error, trace, warn};

use crate::common::{
    asn1::{
        asn1_encode_length, Bytes, CertId, Oid, TryIntoSequence, ASN1_BIT_STRING, ASN1_EXPLICIT_0,
        ASN1_EXPLICIT_1, ASN1_EXPLICIT_2, ASN1_IA5STRING, ASN1_SEQUENCE,
    },
    ocsp::OcspExtI,
};
use crate::err::{OcspError, Result};

/// RFC 6960 Request
#[derive(Debug)]
pub struct OneReq {
    /// cid of a single request
    pub certid: CertId,
    /// extension of a single request  
    /// REVIEW: untested
    pub one_req_ext: Option<Vec<OcspExtI>>,
}

impl OneReq {
    /// get single request
    pub async fn parse(onereq: &[u8]) -> Result<Self> {
        trace!("OneReq: {}", hex::encode(onereq));
        let s = onereq.try_into()?;

        let cid = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        let cid = CertId::parse(cid.raw()).await?;
        trace!("OneReq cert sn {}", hex::encode(&cid.serial_num));
        trace!(
            "OneReq issuer key hash {}",
            hex::encode(&cid.issuer_key_hash)
        );

        let mut ext = None;
        match s.len() {
            1 => {
                trace!("No extension in OneReq");
            }
            2 => {
                let raw_ext = s.get(1).map_err(OcspError::Asn1DecodingError)?.raw();
                ext = Some(OcspExtI::parse(raw_ext).await?);
            }
            _ => {
                error!(
                    "OneReq contains {} items, expecting no more than 2: cid and extension",
                    s.len()
                );
                return Err(OcspError::Asn1LengthError("OneReq"));
            }
        }

        trace!("OneReq with cid {:?} successfully decoded", cid);
        Ok(OneReq {
            certid: cid,
            one_req_ext: ext,
        })
    }

    pub async fn to_der(&self) -> Result<Bytes> {
        let mut cid = self.certid.to_der().await?;
        match &self.one_req_ext {
            Some(r) => {
                cid.extend(OcspExtI::list_to_der(&r, ASN1_EXPLICIT_0).await?);
            }
            None => {}
        }
        let len = asn1_encode_length(cid.len()).await?;
        let mut r = vec![ASN1_SEQUENCE];
        r.extend(len);
        r.extend(cid);

        trace!("Cid successfully encoded");
        Ok(r)
    }
}

/// RFC 6960 TBSRequest  
/// version is omitted as data produced from OpenSSL doesn't contain version  
/// REVIEW: omit version in tbs request
#[derive(Debug)]
pub struct TBSRequest {
    // explicit tag 0
    // version: u8,
    /// requestorName is OPTIONAL and indicates the name of the OCSP requestor.
    /// explicit 1
    pub requestor_name: Option<Bytes>,
    /// requestList contains one or more single certificate status requests.
    pub request_list: Vec<OneReq>,
    /// requestExtensions is OPTIONAL and includes extensions applicable
    /// to the requests found in reqCert.
    pub request_ext: Option<Vec<OcspExtI>>,
}

impl TBSRequest {
    /// parse a tbs request
    pub async fn parse(tbs: &[u8]) -> Result<Self> {
        trace!("Parsing tbsrequest {}", hex::encode(tbs));
        let mut name = None;
        let mut ext = None;
        let mut req: Vec<OneReq> = Vec::new();

        let s = tbs.try_into()?;

        for i in 0..s.len() {
            let tbs_item = s.get(i).map_err(OcspError::Asn1DecodingError)?;
            match tbs_item.tag() {
                ASN1_EXPLICIT_0 => {
                    warn!("Version in TBS REQUEST is defined in RFC but yet implemented");
                    unimplemented!()
                }
                ASN1_EXPLICIT_1 => {
                    trace!("Found requestor name");
                    let val = tbs_item.value();
                    let val = DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                    if val.tag() != ASN1_IA5STRING {
                        return Err(OcspError::Asn1MismatchError("TBS requestor name"));
                    }
                    name = Some(val.value().to_vec());
                }
                ASN1_EXPLICIT_2 => {
                    trace!("Found tbs extension");
                    let ext_list = tbs_item.value();
                    let ext_list = OcspExtI::parse(ext_list).await?;
                    ext = Some(ext_list);
                }
                ASN1_SEQUENCE => {
                    let req_list = tbs_item.try_into()?;
                    trace!("Found {} OneReq", req_list.len());
                    for j in 0..req_list.len() {
                        let onereq = req_list.get(j).map_err(OcspError::Asn1DecodingError)?;
                        // onereq.raw() here always return the full sequence starting from first onereq
                        let mut current = onereq.header().to_vec();
                        current.extend(onereq.value());
                        let onereq = OneReq::parse(&current).await?;
                        req.push(onereq);
                    }
                }
                _ => {
                    return Err(OcspError::Asn1MismatchError("TBS Request"));
                }
            }
        }

        trace!("Tbs request successfully decoded");
        Ok(TBSRequest {
            requestor_name: name,
            request_list: req,
            request_ext: ext,
        })
    }
}

/// RFC 6960 Signature
/// Optional signature in ocsp request  
/// The requestor MAY choose to sign the OCSP request.  
/// In that case, the signature is computed over the tbsRequest structure.
/// REVIEW: *untested*
/// REVIEW: If the request is signed, the requestor SHALL specify its name in the requestorName field.
#[derive(Debug)]
pub struct Signature {
    /// algo oid for signature
    pub signing_algo: Oid,
    /// tho RFC 6960 indicates signature is BIT STRING,  
    /// which has arbitrary length comparing to OCTET,  
    /// but all signatures' length are multiple of 8,  
    /// so using Vec\<u8\> here.
    pub signature: Bytes,
    /// \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    pub certs: Option<Bytes>,
}

impl Signature {
    /// parsing ocsp signature from raw bytes
    pub async fn parse(sig: &[u8]) -> Result<Self> {
        trace!("Raw signature: {}", hex::encode(sig));
        let s = sig.try_into()?;

        let oid;
        let signature;

        match s.len() {
            2 => {
                let id = s.get(0).map_err(OcspError::Asn1DecodingError)?;
                oid = Oid::parse(id.raw()).await?;

                let raw = s.get(1).map_err(OcspError::Asn1DecodingError)?;
                if raw.tag() != ASN1_BIT_STRING {
                    return Err(OcspError::Asn1MismatchError("SIGNATURE"));
                }
                signature = raw.value().to_vec();
            }
            3 => {
                warn!("Signature CERT is defined in RFC but yet implemented");
                unimplemented!()
            }
            _ => return Err(OcspError::Asn1LengthError("SIGNATURE")),
        }

        trace!("Ocsp request signature successfully decoded");
        Ok(Signature {
            signing_algo: oid,
            signature,
            // unimplemented 3
            certs: None,
        })
    }
}

/// RFC 6960 OCSPRequest
#[derive(Debug)]
pub struct OcspRequest {
    /// RFC 6960 TBSRequest
    pub tbs_request: TBSRequest,
    /// RFC 6960 optionalSignature, explicit tag 0
    pub optional_signature: Option<Signature>,
}

impl OcspRequest {
    /// parsing an ocsp request from raw bytes
    pub async fn parse(ocsp_req: &[u8]) -> Result<Self> {
        debug!("Parsing ocsp request");
        trace!("Raw ocsp request: {}", hex::encode(ocsp_req));
        let s = ocsp_req.try_into()?;

        let req;
        let mut sig = None;
        match s.len() {
            1 => {
                trace!("No Signature in Ocsp Request");
            }
            2 => {
                let sig_v8 = s.get(1).map_err(OcspError::Asn1DecodingError)?;
                match sig_v8.tag() {
                    ASN1_EXPLICIT_0 => {
                        let val = sig_v8.value();
                        let val = DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                        sig = Some(Signature::parse(val.value()).await?);
                    }
                    _ => return Err(OcspError::Asn1MismatchError("SIGNATURE EXP 0 tag")),
                }
            }
            _ => {}
        }
        let req_v8 = s.get(0).map_err(OcspError::Asn1DecodingError)?;
        req = TBSRequest::parse(req_v8.raw()).await?;

        debug!("Ocsp request successfully decoded");
        Ok(OcspRequest {
            tbs_request: req,
            optional_signature: sig,
        })
    }

    /// extract all cert serial numbers from request
    pub async fn extract_cert_sn(&self) -> Vec<&Bytes> {
        let mut sn = vec![];
        let list = &self.tbs_request.request_list;
        list.iter().for_each(|r| sn.push(&(r.certid.serial_num)));
        sn
    }

    /// extract extensions from request
    pub async fn extract_ext(&self) -> Option<&Vec<OcspExtI>> {
        match &self.tbs_request.request_ext {
            Some(v) => Some(v),
            None => return None,
        }
    }

    /// extract cid
    pub async fn extract_certid(&self) -> Vec<&CertId> {
        let mut cid = vec![];
        let list = &self.tbs_request.request_list;
        list.iter().for_each(|r| {
            cid.push(&r.certid);
        });
        cid
    }

    /// extract owned certid
    pub async fn extract_certid_owned(self) -> Vec<CertId> {
        let mut cid = vec![];
        let list = self.tbs_request.request_list;
        list.iter().for_each(|r| {
            cid.push(r.certid.clone());
        });
        cid
    }

    /// extract cid map sn to cid
    pub async fn extract_certid_map(&self) -> HashMap<Bytes, CertId> {
        let mut map = HashMap::new();
        let list = &self.tbs_request.request_list;
        list.iter().for_each(|r| {
            let _ = map.insert(r.certid.serial_num.clone(), r.certid.clone());
        });
        map
    }
}

#[cfg(test)]
mod test {
    use asn1_der::{
        typed::{DerDecodable, Sequence},
        DerObject,
    };
    use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

    use crate::oid::i2b_oid;

    use super::{CertId, OcspRequest, Oid, OneReq, TBSRequest};

    // init log
    #[allow(dead_code)]
    fn init() {
        let log_level = "debug";
        let env_layer = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new(log_level));
        let fmt_layer = tracing_subscriber::fmt::layer().with_target(true).pretty();
        let reg = Registry::default().with(env_layer).with(fmt_layer);
        tracing_log::LogTracer::init().unwrap();
        tracing::subscriber::set_global_default(reg).unwrap();
    }

    // extracting cert cids from request
    #[tokio::test]
    async fn extract_cert_certid_owned() {
        let ocsp_req_hex = "3081B53081B230818A30433041300906\
    052B0E03021A05000414694D18A9BE42\
    F7802614D4844F23601478B788200414\
    397BE002A2F571FD80DCEB52A17A7F8B\
    632BE755020841300983331F9D4F3043\
    3041300906052B0E03021A0500041469\
    4D18A9BE42F7802614D4844F23601478\
    B788200414397BE002A2F571FD80DCEB\
    52A17A7F8B632BE75502086378E51D44\
    8FF46DA2233021301F06092B06010505\
    07300102041204105E7A74E51C861A3F\
    79454658BB090244";
        let req_v8 = hex::decode(ocsp_req_hex).unwrap();
        let req = OcspRequest::parse(&req_v8[..]).await.unwrap();
        let clist = req.extract_certid_owned().await;
        let mut v = vec![];
        clist.iter().for_each(|c| v.push(c.serial_num.clone()));

        let c1 = vec![0x41u8, 0x30, 0x09, 0x83, 0x33, 0x1F, 0x9D, 0x4F];
        let c2 = vec![0x63, 0x78, 0xE5, 0x1D, 0x44, 0x8F, 0xF4, 0x6D];
        let c = vec![c1, c2];

        assert_eq!(c, v);
    }

    // extracting cert serial numbers from request
    #[tokio::test]
    async fn extract_cert_sn() {
        let ocsp_req_hex = "3081B53081B230818A30433041300906\
    052B0E03021A05000414694D18A9BE42\
    F7802614D4844F23601478B788200414\
    397BE002A2F571FD80DCEB52A17A7F8B\
    632BE755020841300983331F9D4F3043\
    3041300906052B0E03021A0500041469\
    4D18A9BE42F7802614D4844F23601478\
    B788200414397BE002A2F571FD80DCEB\
    52A17A7F8B632BE75502086378E51D44\
    8FF46DA2233021301F06092B06010505\
    07300102041204105E7A74E51C861A3F\
    79454658BB090244";
        let req_v8 = hex::decode(ocsp_req_hex).unwrap();
        let req = OcspRequest::parse(&req_v8[..]).await.unwrap();
        let v = req.extract_cert_sn().await;

        let c1 = vec![0x41u8, 0x30, 0x09, 0x83, 0x33, 0x1F, 0x9D, 0x4F];
        let c2 = vec![0x63, 0x78, 0xE5, 0x1D, 0x44, 0x8F, 0xF4, 0x6D];
        let c = vec![&c1, &c2];

        assert_eq!(c, v);
    }

    // parsing two certs in single request
    #[tokio::test]
    async fn ocsp_two_cert_req() {
        let ocsp_req_hex = "3081B53081B230818A30433041300906\
    052B0E03021A05000414694D18A9BE42\
    F7802614D4844F23601478B788200414\
    397BE002A2F571FD80DCEB52A17A7F8B\
    632BE755020841300983331F9D4F3043\
    3041300906052B0E03021A0500041469\
    4D18A9BE42F7802614D4844F23601478\
    B788200414397BE002A2F571FD80DCEB\
    52A17A7F8B632BE75502086378E51D44\
    8FF46DA2233021301F06092B06010505\
    07300102041204105E7A74E51C861A3F\
    79454658BB090244";
        let req_v8 = hex::decode(ocsp_req_hex).unwrap();
        let req = OcspRequest::parse(&req_v8[..]).await;
        assert!(req.is_ok());
    }

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
        let ocsp_request = OcspRequest::parse(&ocsp_req_v8[..]).await;
        assert!(ocsp_request.is_ok());
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
        //    _reqlist.header(),
        //    _reqlist.value()
        //);

        let ocspseq = Sequence::decode(der.value()).unwrap();
        let t = ocspseq.get(1).unwrap().header();
        let v = ocspseq.get(1).unwrap().value();
        let mut t = t.to_vec();
        t.extend(v);
        //println!("context specific exp tag 2{:02X?}", t);
        let _ = Sequence::decode(&t[..]).unwrap();
    }

    // get one tbs request with nonce ext
    #[tokio::test]
    async fn parse_tbs_nonce_ext() {
        let tbs_hex = "306c304530433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46da223302130\
    1f06092b060105050730010204120410\
    1cfc8fa3f5e15ed760707bc46670559b";
        let tbs_v8 = hex::decode(tbs_hex).unwrap();
        let _ = TBSRequest::parse(&tbs_v8[..]).await.unwrap();
    }

    // get one request with no extension on either request
    #[tokio::test]
    async fn parse_onereq_no_ext() {
        let onereq_hex = "30433041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46d";
        let onereq_v8 = hex::decode(onereq_hex).unwrap();
        let _ = OneReq::parse(&onereq_v8[..]).await.unwrap();
    }

    /// get certid from raw hex
    #[tokio::test]
    async fn parse_certid_v8() {
        let certid_hex = "3041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46d";
        let certid_v8 = hex::decode(certid_hex).unwrap();
        let _ = CertId::parse(&certid_v8[..]).await.unwrap();
    }

    // this proves asn1_der drops data after null tag in a sequence
    #[tokio::test]
    async fn parse_oid_null_drops() {
        let oid_hex = "300906052b0e03021a0500040107";
        let oid_v8 = hex::decode(oid_hex).unwrap();
        let _ = Oid::parse(&oid_v8[..]).await.unwrap();
        //let s = oid_v8.try_into().unwrap();
        //let d = s.get(1).unwrap();
        //println!("{:?}", d.header());
    }

    // get oid Bytes from raw hex
    #[tokio::test]
    async fn parse_oid_v8() {
        let oid_hex = "300906052b0e03021a0500";
        let oid_v8 = hex::decode(oid_hex).unwrap();
        let oid = Oid::parse(&oid_v8).await.unwrap();
        assert_eq!(
            i2b_oid(&oid).await.unwrap(),
            vec![0x2b, 0x0e, 0x03, 0x02, 0x1a]
        );
    }

    // display error with file & line info
    #[tokio::test]
    #[should_panic]
    async fn parse_oid_sequence_into_err() {
        let oid_hex = "300906052b0e03021a";
        let oid_v8 = hex::decode(oid_hex).unwrap();
        let _ = Oid::parse(&oid_v8[..]).await.unwrap();
    }

    // incorrect sequence length
    #[tokio::test]
    #[should_panic]
    async fn parse_oid_length_err() {
        let oid_hex = "3041300906052b0e\
    03021a05000414694d18a9be42f78026\
    14d4844f23601478b788200414397be0\
    02a2f571fd80dceb52a17a7f8b632be7\
    5502086378e51d448ff46d";
        let oid_v8 = hex::decode(oid_hex).unwrap();
        let _ = Oid::parse(&oid_v8[..]).await.unwrap();
    }

    // mismatch sequence
    #[tokio::test]
    #[should_panic]
    async fn parse_oid_mismatch_err() {
        let oid_hex = "300a06052b0e03021a0201ff";
        let oid_v8 = hex::decode(oid_hex).unwrap();
        let _ = Oid::parse(&oid_v8[..]).await.unwrap();
    }
}
