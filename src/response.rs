//! OCSP response  
//! for binary details, see [crate::doc::resp]
use tracing::{debug, trace, warn};

use crate::{
    common::asn1::{ASN1_EXPLICIT_2, ASN1_OCTET, ASN1_SEQUENCE},
    err::{OcspError, Result},
};
use crate::{
    common::{
        asn1::{
            asn1_encode_length, CertId, GeneralizedTime, Oid, ASN1_ENUMERATED, ASN1_EXPLICIT_0,
            ASN1_EXPLICIT_1,
        },
        ocsp::OcspExt,
    },
    err_at,
};

/// possible revoke reason, See RFC 5280
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CrlReason {
    /// possible cert revocation reason
    OcspRevokeUnspecified = 0u8,
    /// possible cert revocation reason
    OcspRevokeKeyCompromise = 1u8,
    /// possible cert revocation reason
    OcspRevokeCaCompromise = 2u8,
    /// possible cert revocation reason
    OcspRevokeAffChanged = 3u8,
    /// possible cert revocation reason
    OcspRevokeSuperseded = 4u8,
    /// possible cert revocation reason
    OcspRevokeCessOperation = 5u8,
    /// possible cert revocation reason
    OcspRevokeCertHold = 6u8,
    /// possible cert revocation reason
    OcspRevokeRemoveFromCrl = 8u8,
    /// possible cert revocation reason
    OcspRevokePrivWithdrawn = 9u8,
    /// possible cert revocation reason
    OcspRevokeAaCompromise = 10u8,
}

/// see RFC 6960
#[derive(Debug)]
pub struct RevokedInfo {
    /// revocation time
    pub revocation_time: GeneralizedTime,
    /// revocation reason, exp 0, ENUMERATED
    pub revocation_reason: Option<CrlReason>,
}

impl RevokedInfo {
    /// return new RevokeInfo
    pub async fn new(gt: GeneralizedTime, reason: Option<CrlReason>) -> Self {
        RevokedInfo {
            revocation_time: gt,
            revocation_reason: reason,
        }
    }

    /// serialize to DER encoding
    pub async fn to_der(&self) -> Result<Vec<u8>> {
        debug!("Start encoding RevokeInfo");
        trace!("RevokeInfo to der: {:?}", self);
        let mut time = self.revocation_time.to_der_utc().await?;
        let mut reason = vec![];
        if let Some(re) = self.revocation_reason {
            debug!("revoke with reason {}", re as u8);
            reason = vec![ASN1_EXPLICIT_0, 0x03, ASN1_ENUMERATED, 0x01, re as u8];
        }
        time.extend(reason);
        debug!("RevokeInfo value length {}", time.len());
        let len = asn1_encode_length(time.len()).await?;
        let mut tag = vec![ASN1_EXPLICIT_1];
        tag.extend(len);
        tag.extend(time);

        debug!("Good REVOKEINFO encoded");
        Ok(tag)
    }
}

/// possible status for a cert
#[repr(u8)]
#[derive(Debug)]
pub enum CertStatusCode {
    /// cert is valid
    Good = 0x80,
    /// cert is revoked
    Revoked = 0xa1,
    /// The "unknown" state indicates that the responder doesn't know about  
    /// the certificate being requested, usually because the request  
    /// indicates an unrecognized issuer that is not served by this responder.
    Unknown = 0x82,
}

/// RFC 6960 cert status
#[derive(Debug)]
pub struct CertStatus {
    code: CertStatusCode,
    revoke_info: Option<RevokedInfo>,
}

impl CertStatus {
    /// create new status
    pub async fn new(status: CertStatusCode, rev_info: Option<RevokedInfo>) -> Self {
        match status {
            CertStatusCode::Good | CertStatusCode::Unknown => {
                warn!("Cert status good or unknown with revoke info, ignored.");
                CertStatus {
                    code: status,
                    revoke_info: None,
                }
            }

            CertStatusCode::Revoked => CertStatus {
                code: status,
                revoke_info: rev_info,
            },
        }
    }

    /// encode to ASN.1 DER
    pub async fn to_der(&self) -> Result<Vec<u8>> {
        debug!("Start encoding cert status");
        trace!("Cert status: {:?}", self);
        match self.code {
            CertStatusCode::Good => Ok(vec![CertStatusCode::Good as u8, 0x00]),
            CertStatusCode::Unknown => Ok(vec![CertStatusCode::Unknown as u8, 0x00]),
            CertStatusCode::Revoked => {
                debug!("Encoding revoke status");
                let v;
                match &self.revoke_info {
                    Some(r) => {
                        // revoke_info to_der contains status code
                        v = r.to_der().await?
                    }
                    None => return Err(OcspError::GenRevokeInfoNotFound(err_at!())),
                }
                Ok(v)
            }
        }
    }
}

/// RFC 6960 single response
#[derive(Debug)]
pub struct OneResp {
    /// certid of a single response
    pub one_resp: CertId,
    /// cert status
    pub cert_status: CertStatus,
    /// Responses whose thisUpdate time is later than the local system time SHOULD be considered unreliable.
    pub this_update: GeneralizedTime,
    /// Responses whose nextUpdate value is earlier than the local system time value SHOULD be considered unreliable
    pub next_update: Option<GeneralizedTime>,
    /// extension for single response
    pub one_resp_ext: Option<Vec<OcspExt>>,
}

impl OneResp {
    /// encode list of resp to ASN.1 DER
    pub async fn list_to_der(list: &[OneResp]) -> Result<Vec<u8>> {
        debug!("Start encoding {} responses", list.len());
        trace!("Resp list: {:?}", list);

        let mut v = vec![];
        for i in 0..list.len() {
            let t = list[i].to_der().await?;
            v.extend(t);
        }

        let len = asn1_encode_length(v.len()).await?;
        let mut tlv = vec![ASN1_SEQUENCE];
        tlv.extend(len);
        tlv.extend(v);

        debug!("Good RESPONSES list encoded");
        Ok(tlv)
    }

    /// encode to ASN.1 DER
    pub async fn to_der(&self) -> Result<Vec<u8>> {
        debug!("Encoding one response");
        trace!("Response: {:?}", self);
        let mut certid = self.one_resp.to_der().await?;
        let status = self.cert_status.to_der().await?;
        let this = self.this_update.to_der_utc().await?;

        certid.extend(status);
        certid.extend(this);

        if let Some(t) = self.next_update {
            debug!("Found nextUpdate");
            let next = t.to_der_utc().await?;
            let len = asn1_encode_length(next.len()).await?;
            let mut tagging = vec![ASN1_EXPLICIT_0];
            tagging.extend(len);
            tagging.extend(next);
            certid.extend(tagging);
        }

        if let Some(e) = self.one_resp_ext.clone() {
            debug!("Found extensions");
            // list_to_der comes with explicit tagging
            let list = OcspExt::list_to_der(&e, ASN1_EXPLICIT_1).await?;
            certid.extend(list);
        }

        let len = asn1_encode_length(certid.len()).await?;
        let mut r = vec![ASN1_SEQUENCE];
        r.extend(len);
        r.extend(certid);

        debug!("Good RESP encoded");
        Ok(r)
    }
}

/// responder type
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ResponderType {
    /// responder by name
    BY_NAME = 0x00,
    /// responder by key hash
    BY_KEY_HASH = 0x01,
}

/// indicates responder type
#[derive(Debug)]
pub struct ResponderId {
    /// id by name or key hash
    pub id_by: ResponderType,
    /// id
    pub id: Vec<u8>,
}

impl ResponderId {
    /// return new responder id
    pub async fn new_key_hash(key_hash: &[u8]) -> Self {
        ResponderId {
            id_by: ResponderType::BY_KEY_HASH,
            id: key_hash.to_vec(),
        }
    }

    /// encode to ASN.1
    // example by name
    // a1 56
    //  30 54
    //      31 0b 30 09 06 03 55 04 06 13 02 41 55
    //      31 13 30 11 06 03 55 04 08 0c 0a 53 6f 6d 65 2d 53 74 61 74 65
    //      31 21 30 1f 06 03 55 04 0a 0c 18 49 6e 74 65 72 6e 65 74 20 57 69 64 67 69 74 73 20 50 74 79 20 4c 74 64
    //      31 0d 30 0b 06 03 55 04 03 0c 04 4f 43 53 50
    pub async fn to_der(&self) -> Result<Vec<u8>> {
        debug!("Start encoding Responder Id by {:?}", self.id_by);
        trace!("Responder Id: {:?}", self);

        let mut v = vec![];
        match self.id_by {
            ResponderType::BY_NAME => {
                // FIXME:
                unimplemented!()
            }
            ResponderType::BY_KEY_HASH => {
                let len = asn1_encode_length(self.id.len()).await?;
                let mut octet = vec![ASN1_OCTET];
                octet.extend(len);
                octet.extend(self.id.clone());
                let len = asn1_encode_length(octet.len()).await?;
                v.push(ASN1_EXPLICIT_2);
                v.extend(len);
                v.extend(octet);
            }
        }

        debug!("Good RESPONDER ID encoded");
        Ok(v)
    }
}

/// RFC 6960
#[derive(Debug)]
pub struct ResponseData {
    // REVIEW:
    // version
    /// responder id  
    /// in case of KeyHash ::= OCTET STRING  
    /// SHA-1 hash of responder's public key (excluding the tag and length fields)
    pub responder_id: ResponderId,
    /// time of creating response
    pub produced_at: Vec<u8>,
    /// list of responses
    pub responses: Vec<OneResp>,
    /// exp 1
    pub resp_ext: Option<OcspExt>,
}

/// basic response
#[derive(Debug)]
pub struct BasicResponse {
    ///
    pub tbs_resp_data: ResponseData,
    ///
    pub signature_algo: Oid,
    ///  The value for signature SHALL be computed on the hash of the DER encoding of ResponseData
    pub signature: Vec<u8>,
    /// The responder MAY include certificates in  
    /// the certs field of BasicOCSPResponse that help the OCSP client verify  
    /// the responder's signature.  
    /// If no certificates are included, then certs SHOULD be absent
    pub certs: Option<Vec<Vec<u8>>>,
}

/// basic response  
/// The value for responseBytes consists of an OBJECT IDENTIFIER and a  
/// response syntax identified by that OID encoded as an OCTET STRING
#[derive(Debug)]
pub struct ResponseBytes {
    /// For a basic OCSP responder, responseType will be id-pkix-ocsp-basic
    pub response_type: Oid,
    /// basic response
    pub response_data: Vec<u8>,
}

/// possible status for ocsp request
#[repr(u8)]
#[derive(Debug)]
pub enum OcspRespStatus {
    /// See RFC 6960
    OcspRespStatusSuccessful = 0u8,
    /// See RFC 6960
    OcspRespStatusMalformedReq = 1u8,
    /// See RFC 6960
    OcspRespStatusInternalError = 2u8,
    /// See RFC 6960
    OcspRespStatusTryLater = 3u8,
    /// See RFC 6960
    OcspRespStatusSigRequired = 5u8,
    /// See RFC 6960
    OcspRespStatusUnauthorized = 6u8,
}

/// ocsp response
#[derive(Debug)]
pub struct OcspResponse {
    /// response status
    pub resp_status: OcspRespStatus,
    /// If the value of responseStatus is one of the error conditions,  
    /// the responseBytes field is not set
    pub resp_bytes: Option<ResponseBytes>,
}

#[cfg(test)]
mod test {
    use crate::oid::ALGO_SHA1_NUM;

    use super::*;

    /// responder by key hash
    #[tokio::test]
    async fn responder_by_key_to_der() {
        let key = [
            0x36, 0x6f, 0x35, 0xfb, 0xef, 0x16, 0xc6, 0xba, 0x8a, 0x31, 0x83, 0x42, 0x6d, 0x97,
            0xba, 0x89, 0x4d, 0x55, 0x6e, 0x91,
        ];
        let id = ResponderId::new_key_hash(&key).await;
        let v = id.to_der().await.unwrap();
        let c = vec![
            0xa2, 0x16, 0x04, 0x14, 0x36, 0x6f, 0x35, 0xfb, 0xef, 0x16, 0xc6, 0xba, 0x8a, 0x31,
            0x83, 0x42, 0x6d, 0x97, 0xba, 0x89, 0x4d, 0x55, 0x6e, 0x91,
        ];

        assert_eq!(c, v);
    }

    /// two resp to ASN.1 DER
    #[tokio::test]
    async fn two_resp_to_der() {
        let oid = Oid::new_from_dot(ALGO_SHA1_NUM).await.unwrap();
        let name = vec![
            0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23,
            0x60, 0x14, 0x78, 0xb7, 0x88, 0x20,
        ];
        let key = vec![
            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a,
            0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55,
        ];
        let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
        let certid = CertId::new(oid.clone(), &name, &key, &sn).await;
        let good = CertStatus::new(CertStatusCode::Good, None).await;
        let gt = GeneralizedTime::new(2021, 1, 12, 3, 26, 43).await.unwrap();

        let one = OneResp {
            one_resp: certid.clone(),
            cert_status: good,
            this_update: gt.clone(),
            next_update: None,
            one_resp_ext: None,
        };

        let sn2 = vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d];
        let certid2 = CertId::new(oid, &name, &key, &sn2).await;
        let rev_t = GeneralizedTime::new(2020, 11, 30, 1, 48, 25).await.unwrap();
        let rev_info = RevokedInfo::new(rev_t, Some(CrlReason::OcspRevokeUnspecified)).await;
        let revoke = CertStatus::new(CertStatusCode::Revoked, Some(rev_info)).await;
        let two = OneResp {
            one_resp: certid2,
            cert_status: revoke,
            this_update: gt,
            next_update: None,
            one_resp_ext: None,
        };

        let resp = [one, two];
        let v = OneResp::list_to_der(&resp).await.unwrap();

        let c = vec![
            0x30, 0x81, 0xc6, 0x30, 0x56, 0x30, 0x41, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
            0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80,
            0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20, 0x04, 0x14,
            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a,
            0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55, 0x02, 0x08, 0x41, 0x30, 0x09, 0x83, 0x33, 0x1f,
            0x9d, 0x4f, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x32,
            0x30, 0x33, 0x32, 0x36, 0x34, 0x33, 0x5a, 0x30, 0x6c, 0x30, 0x41, 0x30, 0x09, 0x06,
            0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x69, 0x4d, 0x18, 0xa9,
            0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23, 0x60, 0x14, 0x78, 0xb7,
            0x88, 0x20, 0x04, 0x14, 0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc,
            0xeb, 0x52, 0xa1, 0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55, 0x02, 0x08, 0x63, 0x78,
            0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d, 0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x30,
            0x31, 0x31, 0x33, 0x30, 0x30, 0x31, 0x34, 0x38, 0x32, 0x35, 0x5a, 0xa0, 0x03, 0x0a,
            0x01, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x33,
            0x32, 0x36, 0x34, 0x33, 0x5a,
        ];

        assert_eq!(c, v);
    }

    /// good one resp with next update
    #[tokio::test]
    async fn one_resp_good_next_update_to_der() {
        let oid = Oid::new_from_dot(ALGO_SHA1_NUM).await.unwrap();
        let name = vec![
            0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23,
            0x60, 0x14, 0x78, 0xb7, 0x88, 0x20,
        ];
        let key = vec![
            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a,
            0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55,
        ];
        let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
        let certid = CertId::new(oid, &name, &key, &sn).await;
        let good = CertStatus::new(CertStatusCode::Good, None).await;
        let gt = GeneralizedTime::new(2021, 1, 13, 3, 9, 25).await.unwrap();

        let one = OneResp {
            one_resp: certid,
            cert_status: good,
            this_update: gt.clone(),
            next_update: Some(gt),
            one_resp_ext: None,
        };

        let v = one.to_der().await.unwrap();

        let c = vec![
            0x30, 0x69, 0x30, 0x41, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
            0x00, 0x04, 0x14, 0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4,
            0x84, 0x4f, 0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20, 0x04, 0x14, 0x39, 0x7b, 0xe0,
            0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a, 0x7f, 0x8b, 0x63,
            0x2b, 0xe7, 0x55, 0x02, 0x08, 0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f, 0x80,
            0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x33, 0x30, 0x33, 0x30,
            0x39, 0x32, 0x35, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31,
            0x31, 0x33, 0x30, 0x33, 0x30, 0x39, 0x32, 0x35, 0x5a,
        ];

        assert_eq!(c, v);
    }

    // test encode one resp to ASN.1 DER
    #[tokio::test]
    async fn one_resp_good_to_der() {
        let oid = Oid::new_from_dot(ALGO_SHA1_NUM).await.unwrap();
        let name = vec![
            0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23,
            0x60, 0x14, 0x78, 0xb7, 0x88, 0x20,
        ];
        let key = vec![
            0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a,
            0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55,
        ];
        let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
        let certid = CertId::new(oid, &name, &key, &sn).await;
        let good = CertStatus::new(CertStatusCode::Good, None).await;
        let gt = GeneralizedTime::new(2021, 1, 13, 3, 9, 25).await.unwrap();

        let one = OneResp {
            one_resp: certid,
            cert_status: good,
            this_update: gt.clone(),
            next_update: None,
            one_resp_ext: None,
        };

        let v = one.to_der().await.unwrap();

        let c = vec![
            0x30, 0x56, 0x30, 0x41, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
            0x00, 0x04, 0x14, 0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4,
            0x84, 0x4f, 0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20, 0x04, 0x14, 0x39, 0x7b, 0xe0,
            0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a, 0x7f, 0x8b, 0x63,
            0x2b, 0xe7, 0x55, 0x02, 0x08, 0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f, 0x80,
            0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x33, 0x30, 0x33, 0x30,
            0x39, 0x32, 0x35, 0x5a,
        ];

        assert_eq!(c, v);
    }

    // test good & unknown status don't deal with revoke info
    #[tokio::test]
    async fn cert_good_with_rev_info() {
        let rev_info = RevokedInfo::new(
            GeneralizedTime::new(2021, 1, 1, 1, 1, 1).await.unwrap(),
            Some(CrlReason::OcspRevokeUnspecified),
        )
        .await;

        let good_rev = CertStatus::new(CertStatusCode::Good, Some(rev_info)).await;
        assert!(good_rev.revoke_info.is_none());

        let rev_info = RevokedInfo::new(
            GeneralizedTime::new(2021, 1, 1, 1, 1, 1).await.unwrap(),
            Some(CrlReason::OcspRevokeUnspecified),
        )
        .await;

        let unknown_rev = CertStatus::new(CertStatusCode::Unknown, Some(rev_info)).await;
        assert!(unknown_rev.revoke_info.is_none());
    }

    // test unknown cert status
    #[tokio::test]
    async fn cert_unknown() {
        let unknown = CertStatus::new(CertStatusCode::Unknown, None).await;
        let v = unknown.to_der().await.unwrap();
        assert_eq!(vec![0x82, 0x00], v);
    }

    // test revoke cert status
    #[tokio::test]
    async fn cert_revoke() {
        let rev_info = RevokedInfo::new(
            GeneralizedTime::new(2021, 1, 1, 1, 1, 1).await.unwrap(),
            Some(CrlReason::OcspRevokeUnspecified),
        )
        .await;
        let revoke = CertStatus::new(CertStatusCode::Revoked, Some(rev_info)).await;
        let v = revoke.to_der().await.unwrap();

        assert_eq!(
            vec![
                0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
                0x30, 0x31, 0x30, 0x31, 0x5a, 0xa0, 0x03, 0x0a, 0x01, 0x00
            ],
            v
        );
    }

    // return good cert status
    #[tokio::test]
    async fn cert_good() {
        let good = CertStatus::new(CertStatusCode::Good, None).await;
        let v = good.to_der().await.unwrap();
        assert_eq!(vec![0x80, 0x00], v);
    }

    // test revoke info to der without reason
    #[tokio::test]
    async fn revoke_info_to_der_no_reason() {
        let ri = RevokedInfo {
            revocation_time: GeneralizedTime::new(2021, 1, 12, 8, 32, 56).await.unwrap(),
            revocation_reason: None,
        };

        let v = ri.to_der().await.unwrap();
        assert_eq!(
            vec![
                0xa1, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x38,
                0x33, 0x32, 0x35, 0x36, 0x5a
            ],
            v
        );
    }

    // test revoke info to der with reason
    #[tokio::test]
    async fn revoke_info_to_der() {
        let ri = RevokedInfo {
            revocation_time: GeneralizedTime::new(2020, 11, 30, 1, 48, 25).await.unwrap(),
            revocation_reason: Some(CrlReason::OcspRevokeUnspecified),
        };

        let v = ri.to_der().await.unwrap();
        assert_eq!(
            vec![
                0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x30, 0x31, 0x31, 0x33, 0x30, 0x30, 0x31,
                0x34, 0x38, 0x32, 0x35, 0x5a, 0xa0, 0x03, 0x0a, 0x01, 0x00
            ],
            v
        );
    }
}
