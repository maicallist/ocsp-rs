//! OID const and conversions

use lazy_static::lazy_static;
use std::collections::HashMap;
use tracing::{debug, error};

use crate::common::asn1::Bytes;
use crate::{common::asn1::Oid, err::OcspError};

/// oid bytes to internal id
pub(crate) async fn b2i_oid(oid: &[u8]) -> Option<usize> {
    debug!("Oid bytes {} to internal", hex::encode(oid));
    match OID_MAP.get(oid) {
        None => {
            error!("No matching oid found");
            None
        }
        Some(u) => Some(u.to_owned()),
    }
}

/// oid dot notation to internal id
pub(crate) async fn d2i_oid(oid_dot: &str) -> Option<Oid> {
    debug!("Oid dot notation {} to internal", hex::encode(oid_dot));
    match OCSP_OID_DOT_LIST
        .iter()
        .enumerate()
        .find(|(_, dot_name)| **dot_name == oid_dot)
    {
        None => {
            error!("No matching oid found");
            None
        }
        Some((i, _)) => Some(Oid { index: i }),
    }
}

/// oid internal to bytes
pub async fn i2b_oid(oid: &Oid) -> Result<&'static [u8], OcspError> {
    debug!("Oid {:?} to bytes", oid);
    let id = oid.index;
    if id > OID_MAX_ID {
        error!("No matching oid found");
        return Err(OcspError::Asn1OidUnknown);
    }
    Ok(&OCSP_OID_HEX_LIST[id][..])
}

// ocsp nonce extension internal id
pub(crate) const OCSP_EXT_NONCE_ID: usize = 0;
/// ocsp nonce extension bytes in DER
pub const OCSP_EXT_NONCE_HEX: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
/// ocsp nonce extension name dot notation
pub const OCSP_EXT_NONCE_DOT: &str = "1.3.6.1.5.5.7.48.1.2";
/// ocsp nonce extension name asn1 notation
pub const OCSP_EXT_NONCE_NAME: &str = "id-pkix-ocsp 2";

pub(crate) const OCSP_EXT_CRLREF_ID: usize = 1;
/// ocsp crlref extension bytes in DER
pub const OCSP_EXT_CRLREF_HEX: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x03];
/// ocsp crlref extension name dot notation
pub const OCSP_EXT_CRLREF_DOT: &str = "1.3.6.1.5.5.7.48.1.3";
/// ocsp crlref extension name asn1 notation
pub const OCSP_EXT_CRLREF_NAME: &str = "id-pkix-ocsp 3";

pub(crate) const OCSP_EXT_RESP_TYPE_ID: usize = 2;
/// ocsp response type extension bytes in DER
pub const OCSP_EXT_RESP_TYPE_HEX: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04];
/// ocsp response type extension name dot notation
pub const OCSP_EXT_RESP_TYPE_DOT: &str = "1.3.6.1.5.5.7.48.1.4";
/// ocsp response type extension name asn1 notation
pub const OCSP_EXT_RESP_TYPE_NAME: &str = "id-pkix-ocsp 4";

pub(crate) const OCSP_EXT_ARCHIVE_CUTOFF_ID: usize = 3;
/// ocsp archive cutoff extension bytes in DER
pub const OCSP_EXT_ARCHIVE_CUTOFF_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06];
/// ocsp archive cutoff extension name dot notation
pub const OCSP_EXT_ARCHIVE_CUTOFF_DOT: &str = "1.3.6.1.5.5.7.48.1.6";
/// ocsp archive cutoff extension name asn1 notation
pub const OCSP_EXT_ARCHIVE_CUTOFF_NAME: &str = "id-pkix-ocsp 6";

// crl entry 1
pub(crate) const OCSP_EXT_CRL_REASON_ID: usize = 4;
/// ocsp crl reason extension bytes in DER
pub const OCSP_EXT_CRL_REASON_HEX: [u8; 4] = [0x02, 0x05, 0x1d, 0x15];
/// ocsp crl reason extension name dot notation
pub const OCSP_EXT_CRL_REASON_DOT: &str = "2.5.29.21";
/// ocsp crl reason extension name asn1 notation
pub const OCSP_EXT_CRL_REASON_NAME: &str = "id-ce 21";

// crl entry 2
pub(crate) const OCSP_EXT_INVALID_DATE_ID: usize = 5;
/// ocsp invalid date extension bytes in DER
pub const OCSP_EXT_INVALID_DATE_HEX: [u8; 4] = [0x02, 0x05, 0x1d, 0x18];
/// ocsp invalid date extension name dot notation
pub const OCSP_EXT_INVALID_DATE_DOT: &str = "2.5.29.24";
/// ocsp invalid date extension name asn1 notation
pub const OCSP_EXT_INVALID_DATE_NAME: &str = "id-ce 24";

pub(crate) const OCSP_EXT_SERVICE_LOCATOR_ID: usize = 6;
/// ocsp service locator extension bytes in DER
pub const OCSP_EXT_SERVICE_LOCATOR_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x07];
/// ocsp service locator extension name dot notation
pub const OCSP_EXT_SERVICE_LOCATOR_DOT: &str = "1.3.6.1.5.5.7.48.1.7";
/// ocsp service locator extension name asn1 notation
pub const OCSP_EXT_SERVICE_LOCATOR_NAME: &str = "id-pkix-ocsp 7";

pub(crate) const OCSP_EXT_PREF_SIG_ALGS_ID: usize = 7;
/// ocsp preferred signature algorithms extension bytes in DER
pub const OCSP_EXT_PREF_SIG_ALGS_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x08];
/// ocsp preferred signature algorithms extension name dot notation
pub const OCSP_EXT_PREF_SIG_ALGS_DOT: &str = "1.3.6.1.5.5.7.48.1.8";
/// ocsp preferred signature algorithms extension name asn1 notation
pub const OCSP_EXT_PREF_SIG_ALGS_NAME: &str = "id-pkix-ocsp 8";

pub(crate) const OCSP_EXT_EXTENDED_REVOKE_ID: usize = 8;
/// ocsp extended revoke extension bytes in DER
pub const OCSP_EXT_EXTENDED_REVOKE_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x09];
/// ocsp extended revoke extension name dot notation
pub const OCSP_EXT_EXTENDED_REVOKE_DOT: &str = "1.3.6.1.5.5.7.48.1.9";
/// ocsp extended revoke extension name asn1 notation
pub const OCSP_EXT_EXTENDED_REVOKE_NAME: &str = "id-pkix-ocsp 9";

pub(crate) const ALGO_SHA1_ID: usize = 9;
/// sha1 bytes in DER
pub const ALGO_SHA1_HEX: [u8; 5] = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// sha1 dot notation
pub const ALGO_SHA1_DOT: &str = "1.3.14.3.2.26";
/// sha1 asn1 notation
pub const ALGO_SHA1_NAME: &str = "{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)}";

pub(crate) const ALGO_SHA1_WITH_RSA_ENCRYPTION_ID: usize = 10;
/// sha1WithRSAEncryption bytes in DER
pub const ALGO_SHA1_WITH_RSA_ENCRYPTION_HEX: [u8; 9] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
///sha1WithRSAEncryption dot notation
pub const ALGO_SHA1_WITH_RSA_ENCRYPTION_DOT: &str = "1.2.840.113549.1.1.5";
///sha1WithRSAEncryption asn1 notation
pub const ALGO_SHA1_WITH_RSA_ENCRYPTION_NAME: &str =
    "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha1-with-rsa-signature(5)}";

pub(crate) const OCSP_RESPONSE_BASIC_ID: usize = 11;
/// ocsp responder type basic bytes in DER
pub const OCSP_RESPONSE_BASIC_HEX: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// ocsp responder type basic dot notation
pub const OCSP_RESPONSE_BASIC_DOT: &str = "1.3.6.1.5.5.7.48.1.1";
/// ocsp responder type basic asn1 notation
pub const OCSP_RESPONSE_BASIC_NAME: &str = "id-pkix-ocsp 1";

pub(crate) const ALGO_SHA256_WITH_RSA_ENCRYPTION_ID: usize = 12;
/// sha1WithRSAEncryption bytes in DER
pub const ALGO_SHA256_WITH_RSA_ENCRYPTION_HEX: [u8; 9] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
///sha1WithRSAEncryption dot notation
pub const ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT: &str = "1.2.840.113549.1.1.11";
///sha1WithRSAEncryption asn1 notation
pub const ALGO_SHA256_WITH_RSA_ENCRYPTION_NAME: &str =
    "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256-with-rsa-signature(11)}";

/// NOT the number of OID, highest num in OID_MAX  
/// eg.  
/// oid_map contains 4 algos [0..3]  
/// OID_MAX_ID = 3
pub(crate) const OID_MAX_ID: usize = 12;

lazy_static! {
    /// search oid index by oid binary
    pub static ref OID_MAP: HashMap<Bytes, usize> = vec![
        (OCSP_EXT_NONCE_HEX.to_vec(), OCSP_EXT_NONCE_ID),
        (OCSP_EXT_CRLREF_HEX.to_vec(), OCSP_EXT_CRLREF_ID),
        (OCSP_EXT_RESP_TYPE_HEX.to_vec(), OCSP_EXT_RESP_TYPE_ID),
        (OCSP_EXT_ARCHIVE_CUTOFF_HEX.to_vec(), OCSP_EXT_ARCHIVE_CUTOFF_ID),
        (OCSP_EXT_CRL_REASON_HEX.to_vec(), OCSP_EXT_CRL_REASON_ID),
        (OCSP_EXT_INVALID_DATE_HEX.to_vec(), OCSP_EXT_INVALID_DATE_ID),
        (OCSP_EXT_SERVICE_LOCATOR_HEX.to_vec(), OCSP_EXT_SERVICE_LOCATOR_ID),
        (OCSP_EXT_PREF_SIG_ALGS_HEX.to_vec(), OCSP_EXT_PREF_SIG_ALGS_ID),
        (OCSP_EXT_EXTENDED_REVOKE_HEX.to_vec(), OCSP_EXT_EXTENDED_REVOKE_ID),
        (ALGO_SHA1_HEX.to_vec(), ALGO_SHA1_ID),
        (ALGO_SHA1_WITH_RSA_ENCRYPTION_HEX.to_vec(), ALGO_SHA1_WITH_RSA_ENCRYPTION_ID),
        (OCSP_RESPONSE_BASIC_HEX.to_vec(), OCSP_RESPONSE_BASIC_ID),
        (ALGO_SHA256_WITH_RSA_ENCRYPTION_HEX.to_vec(), ALGO_SHA256_WITH_RSA_ENCRYPTION_ID),
    ]
    .into_iter()
    .collect();

    /// list of ocsp extension oid names
    pub static ref OCSP_OID_NAME_LIST: [&'static str; 13] = [
        OCSP_EXT_NONCE_NAME,
        OCSP_EXT_CRLREF_NAME,
        OCSP_EXT_RESP_TYPE_NAME,
        OCSP_EXT_ARCHIVE_CUTOFF_NAME,
        OCSP_EXT_CRL_REASON_NAME,
        OCSP_EXT_INVALID_DATE_NAME,
        OCSP_EXT_SERVICE_LOCATOR_NAME,
        OCSP_EXT_PREF_SIG_ALGS_NAME,
        OCSP_EXT_EXTENDED_REVOKE_NAME,
        ALGO_SHA1_NAME,
        ALGO_SHA1_WITH_RSA_ENCRYPTION_NAME,
        OCSP_RESPONSE_BASIC_NAME,
        ALGO_SHA256_WITH_RSA_ENCRYPTION_NAME,
    ];

    /// list of ocsp extension oid in num dot format
    pub static ref OCSP_OID_DOT_LIST: [&'static str; 13] = [
        OCSP_EXT_NONCE_DOT,
        OCSP_EXT_CRLREF_DOT,
        OCSP_EXT_RESP_TYPE_DOT,
        OCSP_EXT_ARCHIVE_CUTOFF_DOT,
        OCSP_EXT_CRL_REASON_DOT,
        OCSP_EXT_INVALID_DATE_DOT,
        OCSP_EXT_SERVICE_LOCATOR_DOT,
        OCSP_EXT_PREF_SIG_ALGS_DOT,
        OCSP_EXT_EXTENDED_REVOKE_DOT,
        ALGO_SHA1_DOT,
        ALGO_SHA1_WITH_RSA_ENCRYPTION_DOT,
        OCSP_RESPONSE_BASIC_DOT,
        ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT,
    ];

    /// list of ocsp extension oid in bytes
    pub static ref OCSP_OID_HEX_LIST: [Bytes; 13] = [
        OCSP_EXT_NONCE_HEX.to_vec(),
        OCSP_EXT_CRLREF_HEX.to_vec(),
        OCSP_EXT_RESP_TYPE_HEX.to_vec(),
        OCSP_EXT_ARCHIVE_CUTOFF_HEX.to_vec(),
        OCSP_EXT_CRL_REASON_HEX.to_vec(),
        OCSP_EXT_INVALID_DATE_HEX.to_vec(),
        OCSP_EXT_SERVICE_LOCATOR_HEX.to_vec(),
        OCSP_EXT_PREF_SIG_ALGS_HEX.to_vec(),
        OCSP_EXT_EXTENDED_REVOKE_HEX.to_vec(),
        ALGO_SHA1_HEX.to_vec(),
        ALGO_SHA1_WITH_RSA_ENCRYPTION_HEX.to_vec(),
        OCSP_RESPONSE_BASIC_HEX.to_vec(),
        ALGO_SHA256_WITH_RSA_ENCRYPTION_HEX.to_vec(),
    ];
}

#[cfg(test)]
mod test {
    use super::*;

    // test dot notation to oid
    #[tokio::test]
    async fn test_dot2oid() {
        let dot = OCSP_EXT_EXTENDED_REVOKE_DOT;
        let oid = d2i_oid(dot).await.unwrap().index;
        assert_eq!(oid, OCSP_EXT_EXTENDED_REVOKE_ID);
    }

    // test dot to oid return None for unknown id
    #[tokio::test]
    async fn test_unknown_oid() {
        let dot = "this does not exists, obviously";
        let oid = d2i_oid(dot).await;
        assert!(oid.is_none());
    }
}
