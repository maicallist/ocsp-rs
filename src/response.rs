//! OCSP response  
//! for binary details, see [crate::doc::resp]
use tracing::{debug, trace};

use crate::common::{
    asn1::{
        asn1_encode_length, CertId, GeneralizedTime, Oid, ASN1_ENUMERATED, ASN1_EXPLICIT_0,
        ASN1_EXPLICIT_1,
    },
    ocsp::OcspExt,
};
use crate::err::Result;

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
    /// serialize to DER encoding, explicit tag 1 included
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
    OcspRespCertStatusGood = 0u8,
    /// cert is revoked
    OcspRespCertStatusRevoked = 1u8,
    /// The "unknown" state indicates that the responder doesn't know about  
    /// the certificate being requested, usually because the request  
    /// indicates an unrecognized issuer that is not served by this responder.
    OcspRespCertStatusUnknown = 2u8,
}

/// RFC 6960 cert status
#[derive(Debug)]
pub struct CertStatus {
    code: CertStatusCode,
    reason: Option<RevokedInfo>,
}

/// RFC 6960 single response
#[derive(Debug)]
pub struct OneResp {
    /// certid of a single response
    pub one_resp: CertId,
    /// cert status
    pub cert_status: CertStatus,
    /// Responses whose thisUpdate time is later than the local system time SHOULD be considered unreliable.
    pub this_update: Vec<u8>,
    /// Responses whose nextUpdate value is earlier than the local system time value SHOULD be considered unreliable
    pub next_update: Option<Vec<u8>>,
    /// extension for single response
    pub one_resp_ext: Option<Vec<OcspExt>>,
}

/// Responder ID type
pub const OCSP_RESPONDER_BY_NAME: u8 = 0x0;
/// Responder ID type
pub const OCSP_RESPONDER_BY_KEY_HASH: u8 = 0x01;
/// responder type
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ResponderType {
    /// responder by name
    OCSP_RESPONDER_BY_NAME,
    /// responder by key hash
    OCSP_RESPONDER_BY_KEY_HASH,
}

/// indicates responder type
#[derive(Debug)]
pub struct ResponderId {
    /// id by name or key hash
    pub id_by: ResponderType,
    /// id
    pub id: Vec<u8>,
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
    use crate::common::asn1::ASN1_GENERALIZED_TIME;

    use super::*;

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
