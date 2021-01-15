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

/// good status in single response
pub const OCSP_RESP_CERT_STATUS_GOOD: u8 = 0x00;
/// revoke status in single response
pub const OCSP_RESP_CERT_STATUS_REVOKED: u8 = 0x01;
/// The "unknown" state indicates that the responder doesn't know about  
/// the certificate being requested, usually because the request  
/// indicates an unrecognized issuer that is not served by this responder.
pub const OCSP_RESP_CERT_STATUS_UNKNOWN: u8 = 0x02;

/// possible status for a cert
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum CertStatus {
    /// cert is valid
    OCSP_RESP_CERT_STATUS_GOOD,
    /// cert is revoked
    OCSP_RESP_CERT_STATUS_REVOKED,
    /// no cert info
    OCSP_RESP_CERT_STATUS_UNKNOWN,
}

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
    /// serialize to DER encoding
    pub async fn to_der(&self) -> Result<Vec<u8>> {
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

        debug!("RevokeInfo serialized");
        Ok(tag)
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

/// possible ocsp response status
pub const OCSP_RESP_STATUS_SUCCESSFUL: u8 = 0x00;
/// possible ocsp response status
pub const OCSP_RESP_STATUS_MALFORMED_REQ: u8 = 0x01;
/// possible ocsp response status
pub const OCSP_RESP_STATUS_INTERNAL_ERROR: u8 = 0x02;
/// possible ocsp response status
pub const OCSP_RESP_STATUS_TRY_LATER: u8 = 0x03;
/// possible ocsp response status
pub const OCSP_RESP_STATUS_SIG_REQUIRED: u8 = 0x05;
/// possible ocsp response status
pub const OCSP_RESP_STATUS_UNAUTHORIZED: u8 = 0x06;

/// possible status for ocsp request
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum OcspRespStatus {
    /// See RFC 6960
    OCSP_RESP_STATUS_SUCCESSFUL,
    /// See RFC 6960
    OCSP_RESP_STATUS_MALFORMED_REQ,
    /// See RFC 6960
    OCSP_RESP_STATUS_INTERNAL_ERROR,
    /// See RFC 6960
    OCSP_RESP_STATUS_TRY_LATER,
    /// See RFC 6960
    OCSP_RESP_STATUS_SIG_REQUIRED,
    /// See RFC 6960
    OCSP_RESP_STATUS_UNAUTHORIZED,
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
