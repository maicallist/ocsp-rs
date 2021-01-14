//! OCSP response

/// 30 821295           %% RFC OCSP Response
///     0a 01 00        %% RFC response status ENUMERATED
///     a0 82128e 30 82128a  %% RFC response bytes
///         06 09 2b0601050507300101        %% response type
///         04 82127b                       %% response
///
///             30 821277                   %% basic response
///                 30 81f2                 %% tbs response data
///                 |   a2 16 04 14 366f35fbef16c6ba8a3183426d97ba894d556e91    %% Responder By Key EXP 2
///                 |   18 0f 32303231303131323033323634335a                    %% produced at
///                 |   30 81c6                                                 %% responses
///                 |       30 56                                               %% response 1
///                 |       |   30 41                                           %% certid
///                 |       |       30 09                                       %% oid
///                 |       |           06 05 2b0e03021a
///                 |       |           05 00
///                 |       |       04 14 694d18a9be42f7802614d4844f23601478b78820
///                 |       |       04 14 397be002a2f571fd80dceb52a17a7f8b632be755
///                 |       |       02 08 41300983331f9d4f
///                 |       |   80 00                                           %% cert status good
///                 |       |   18 0f 32303231303131323033323634335a            %% this update
///                 |       30 6c                                               %% response 2
///                 |           30 41                                           %% certid
///                 |               30 09
///                 |                   06 05 2b0e03021a
///                 |                   05 00
///                 |               04 14 694d18a9be42f7802614d4844f23601478b78820
///                 |               04 14 397be002a2f571fd80dceb52a17a7f8b632be755
///                 |               02 08 6378e51d448ff46d
///                 |           a1 16                                           %% status revoke            
///                 |               18 0f 32303230313133303031343832355a        %% revoke time
///                 |               a0 03 0a 01 00                              %% reason ENUMERATED
///                 |           18 0f 32303231303131323033323634335a            %% this update
///                 30 0d                                                       %% sign algo                  
///                     06 09 2a864886f70d010105
///                     05 00
///                 03 820101 001e022d5ba25aa6ee97c5d910c61ebe                  %% signature   
///                             b73db75a767deb43af88c2a56377d9e5aeaa5484
///                             30087b5429d9b90b30569f9444676ad3
///                             a9885fb6d29cd46489ea1a82c369790d
///                             2a4943f4ca93c97706c929707fb6e5b4
///                             9d433b84003bd9aa24a395278ab63e7a
///                             2622d2ec7d3579453e7960bbcfca6d0d
///                             3db0fe460f7c2bbaf72e8c6fb85c7c65
///                             37ea0cb3c36811a8950f7396987598a5
///                             b3c89fc1466cb17c559589d85d8af954
///                             d607c43ff708ddf5d6672faa14fbc717
///                             b55352c2110450f220e8a0be9e6a8664
///                             a6acdca63ae3a706b72cc19da227ce5e
///                             1a8f69adce38f45f8dd3874885898d7c
///                             ebd6057fd8e5f327694198edd90fe6e8
///                             21613be71e3ba24f4db85f10a7
/// optional certs below
///                 a0 82106a 30 821066         %% certs
///                     30 8205a2               %% cert 1
///                         30 82038a           %% tbs certificate
///                             a0 03 02 01 02  %% version EXP 0
///                             02 08 590cb28d6ededd2c        
///                         30 0d               %% signature algo id
///                             06 09 2a864886f70d01010b    
///                             05 00
///                         30 3d               %% issuer
///                             31 0b 30 09 06 035504061302434e    
///                             31 0d 30 0b 06 0355040a0c04434e5043
///                             31 1f 30 1d 06 035504030c16e8aebee5a487e8af81e4b9a6e4b8ade5bf835f525341
///                         30 1e               %% validity
///                             17 0d 3139303432323039323730325a
///                             17 0d 3339303431373039323730325a
///                         30 3b               %% subject
///                             31 0b 30 09 06 035504061302434e310d300b060355040a0c04434e5043311d301b06035504030c14e8aebee5a487e8aea4e8af814f4353505f525341
///                         30 82               %% subject public key info
///                             0122300d06092a864886f70d01010105000382010f003082010a0282010100ce405ecf00076a7b
///                             2582bd9d5d21e1e4c6cacdc402604213
///                             a1cd04c7f3e3a40fe949a1d4b9c69328
///                             2fcdbe82289072a07fe845a897f30b41
///                             1be90b9e1906b440f33026890bbc9641
///                             5abdfa05082f0f538ee39e426e65312f
///                             116b789a5b99e164526b05d57cbf7ad4
///                             fe8766a8d939ef777f3c029e2d48ef05
///                             03bb93ee4ebc9373d22e0d60a09b8de5
///                             01df2c84942672705865b87aa3aed09f
///                             d744553c294e689511c237275f4472ea
///                             fac0c63d4922be3f1c143f23bfa05083
///                             3a3c3bcf9a95e0a64e7d8d47796cfe0d
///                             074d444ad5c2eff88549e10dcca2aca6
///                             5d3a2b4aafa1f4b0bdee0a8a6d36af13
///                             b019223952cb6a09f66ff2c129302449
///                             67dffbcf43cdccb10203010001
///                         a3 82 01a6 30 8201a %% extension 6 ext below
///                             301f0603551d2304183016
///                             8014397be002a2f571fd80dceb52a17a
///                             7f8b632be755301d0603551d0e041604
///                             14366f35fbef16c6ba8a3183426d97ba
///                             894d556e91300c0603551d1304053003
///                             010100300b0603551d0f0404030206c0
///                             3081e00603551d1f0481d83081d53036
///                             a034a032a430302e310b300906035504
///                             061302434e3110300e060355040b0c07
///                             4144443143524c310d300b0603550403
///                             0c0463726c303023a021a01f861d6874
///                             74703a2f2f31312e31302e3134372e31
///                             37322f63726c302e63726c3076a074a0
///                             7286706c6461703a2f2f31312e31302e
///                             3134372e3137323a3338392f434e3d63
///                             726c302c4f553d4144443143524c2c43
///                             3d434e3f636572746966696361746552
///                             65766f636174696f6e4c6973743f6261
///                             73653f6f626a656374636c6173733d63
///                             524c446973747269627574696f6e506f
///                             696e74306206082b0601050507010104
///                             563054302b06082b0601050507300286
///                             1f687474703a2f2f31312e31302e3134
///                             382e38332f636169737375652e68746d
///                             302506082b0601050507300186196874
///                             74703a2f2f31312e31302e3134372e31
///                             393a3230343433
///                         30 0d                   %% algo id
///                             06 09 2a864886f70d01010b
///                             05 00
//                          03 820201 00205e726dbb      %% signature
///                                     8ffb9b91a6e04e587549e9c61a499972
///                                     c84536fe11dde7ff40a5aab9403614ac
///                                     cf473c3efc6023f9e5095a06af6ea542
///                                     68f756b7aa115050fd6c2325f027e9ac
///                                     bbe09152f1ec1940e1c98607f396589c
///                                     4cf00206ec9a5a73d72fd0ee8f22dbbd
///                                     e194730fa8bd0035289a5cdb84ac4a80
///                                     604c192d58bfb56c90b47a4603adff67
///                                     a36a4c02e6258250b92ddabdea470c44
///                                     938d2dc675666b17d781419e96b89f9b
///                                     b245f0c5a625b4a0f419ac5672f91952
///                                     f9166ee1170bdabcdc718aef397391d5
///                                     9c4c88df4ceeb90f8e087ac3a9f7df71
///                                     44bf4e24afbd33d89ed424d8dfbae042
///                                     90182cf16a5c648ae2ae821d9f60ae7f
///                                     87fe2d990f9ba977a9acdde463551a87
///                                     990cfe726e3a40c4f57fcd2f8cce82a7
///                                     494b09156ae54706925d5e78cc3abc40
///                                     cf2b5959203fcc84c4572510d0b4680c
///                                     963854770b131a0b9c0c3e8520ad6448
///                                     8312b89dac978d1cff5c3e788e70fced
///                                     dc76ea950093aff5198172894d37105d
///                                     d8b8f3f44de4a6b8c5bc819b8830eaa5
///                                     c3be76bd7b75c3da887f41faf8e50db4
///                                     9cdac42181731132de39ca89db0d4130
///                                     43323da5b59874209c1c6cac1b341326
///                                     f2facd45b845c038a0645c5bc61e046a
///                                     e487fef0643a2271456e9ab8b8d6b1b2
///                                     cf0110e448d4ed634cea2922314e6b92
///                                     b081db23a4a2d597f64aaeeedccf8163
///                                     9288c886ee88fc304606fbd724c6e10c
///                                     f0dd80eeae5f4bb758d381
/// two more certs below

use crate::common::{asn1::GeneralizedTime, ocsp::OcspExt};
use crate::err::Result;
use crate::request::{CertId, Oid};

const OCSP_RESP_CERT_STATUS_GOOD: u8 = 0x00;
const OCSP_RESP_CERT_STATUS_REVOKED: u8 = 0x01;
const OCSP_RESP_CERT_STATUS_UNKNOWN: u8 = 0x02;

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

/// see RFC 6960
#[derive(Debug)]
pub struct RevokedInfo {
    /// revocation time
    pub revocation_time: GeneralizedTime,
    /// revocation reason, exp 0
    pub revocation_reason: Option<Vec<u8>>,
}

impl RevokedInfo {
    /// return new instance
    pub async fn new(time: GeneralizedTime, reason: Option<String>) -> Self {
        let mut r = None;
        if let Some(s) = reason {
            r = Some(s.as_bytes().to_vec());
        }

        RevokedInfo {
            revocation_time: time,
            revocation_reason: r,
        }
    }

    /// serialize to DER encoding
    pub async fn to_der(&self) -> Vec<u8> {
        unimplemented!()
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

const OCSP_RESPONDER_BY_NAME: u8 = 0x0;
const OCSP_RESPONDER_BY_KEY_HASH: u8 = 0x01;
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

const OCSP_RESP_STATUS_SUCCESSFUL: u8 = 0x00;
const OCSP_RESP_STATUS_MALFORMED_REQ: u8 = 0x01;
const OCSP_RESP_STATUS_INTERNAL_ERROR: u8 = 0x02;
const OCSP_RESP_STATUS_TRY_LATER: u8 = 0x03;
const OCSP_RESP_STATUS_SIG_REQUIRED: u8 = 0x05;
const OCSP_RESP_STATUS_UNAUTHORIZED: u8 = 0x06;

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
