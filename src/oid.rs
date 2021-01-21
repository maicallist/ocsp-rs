//! OID const and conversions

use lazy_static::lazy_static;
use std::collections::HashMap;
use tracing::{debug, error, trace, warn};

use crate::{common::asn1::Oid, err::OcspError, err_at};

// search oid in binary
// see [doc](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN)
//pub async fn b2i_oid(oid: &[u8]) -> Option<ConstOid> {
//    match OID_MAP.get(oid) {
//        None => None,
//        Some(&index) => Some(ConstOid {
//            id: index,
//            num: OCSP_EXT_NUM_LIST[index],
//            name: OCSP_EXT_NAME_LIST[index],
//            bin: OCSP_EXT_HEX_LIST[index].clone(),
//        }),
//    }
//}

pub(crate) async fn b2i_oid(oid: &[u8]) -> Option<usize> {
    debug!("OID bytes to internal");
    trace!("OID to internal from bytes: {:02X?}", oid);
    match OID_MAP.get(oid) {
        None => {
            warn!("No OID found");
            None
        }
        Some(u) => Some(u.to_owned()),
    }
}

// OID dot notation to internal
pub(crate) async fn d2i_oid(oid_dot: &str) -> Option<Oid> {
    debug!("OID dot name to internal");
    trace!("OID to internal from dot notation: {:?}", oid_dot);
    match OCSP_EXT_NUM_LIST
        .iter()
        .enumerate()
        .find(|(_, dot_name)| **dot_name == oid_dot)
    {
        None => {
            warn!("No OID found");
            None
        }
        Some((i, _)) => Some(Oid { index: i }),
    }
}

/// OID internal to byte array
pub async fn i2b_oid(oid: &Oid) -> Result<&'static [u8], OcspError> {
    debug!("OID internal to bytes");
    trace!("OID to byte array from {:?}", oid);
    let id = oid.index;
    if id > OID_MAX_ID {
        error!("No OID found");
        return Err(OcspError::Asn1OidUnknown(err_at!()));
    }
    Ok(&OCSP_EXT_HEX_LIST[id][..])
}

// OID info
//#[derive(Debug)]
//pub struct ConstOid {
//    /// internal id for OID
//    pub(crate) id: usize,
//    /// OID in number format, eg. 1.3.6.1.3.5
//    pub num: &'static str,
//    /// OID in text format, eg. pkix-ocsp 1
//    pub name: &'static str,
//    /// OID in binary format
//    pub bin: Vec<u8>,
//}

pub(crate) const OCSP_EXT_NONCE_ID: usize = 0;
pub(crate) const OCSP_EXT_NONCE_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
pub(crate) const OCSP_EXT_NONCE_NUM: &str = "1.3.6.1.5.5.7.48.1.2";
pub(crate) const OCSP_EXT_NONCE_NAME: &str = "id-pkix-ocsp 2";

pub(crate) const OCSP_EXT_CRLREF_ID: usize = 1;
pub(crate) const OCSP_EXT_CRLREF_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x03];
pub(crate) const OCSP_EXT_CRLREF_NUM: &str = "1.3.6.1.5.5.7.48.1.3";
pub(crate) const OCSP_EXT_CRLREF_NAME: &str = "id-pkix-ocsp 3";

pub(crate) const OCSP_EXT_RESP_TYPE_ID: usize = 2;
pub(crate) const OCSP_EXT_RESP_TYPE_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04];
pub(crate) const OCSP_EXT_RESP_TYPE_NUM: &str = "1.3.6.1.5.5.7.48.1.4";
pub(crate) const OCSP_EXT_RESP_TYPE_NAME: &str = "id-pkix-ocsp 4";

pub(crate) const OCSP_EXT_ARCHIVE_CUTOFF_ID: usize = 3;
pub(crate) const OCSP_EXT_ARCHIVE_CUTOFF_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06];
pub(crate) const OCSP_EXT_ARCHIVE_CUTOFF_NUM: &str = "1.3.6.1.5.5.7.48.1.6";
pub(crate) const OCSP_EXT_ARCHIVE_CUTOFF_NAME: &str = "id-pkix-ocsp 6";

// crl entry 1
pub(crate) const OCSP_EXT_CRL_REASON_ID: usize = 4;
pub(crate) const OCSP_EXT_CRL_REASON_HEX: [u8; 4] = [0x02, 0x05, 0x1d, 0x15];
pub(crate) const OCSP_EXT_CRL_REASON_NUM: &str = "2.5.29.21";
pub(crate) const OCSP_EXT_CRL_REASON_NAME: &str = "id-ce 21";

// crl entry 2
pub(crate) const OCSP_EXT_INVALID_DATE_ID: usize = 5;
pub(crate) const OCSP_EXT_INVALID_DATE_HEX: [u8; 4] = [0x02, 0x05, 0x1d, 0x18];
pub(crate) const OCSP_EXT_INVALID_DATE_NUM: &str = "2.5.29.24";
pub(crate) const OCSP_EXT_INVALID_DATE_NAME: &str = "id-ce 24";

pub(crate) const OCSP_EXT_SERVICE_LOCATOR_ID: usize = 6;
pub(crate) const OCSP_EXT_SERVICE_LOCATOR_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x07];
pub(crate) const OCSP_EXT_SERVICE_LOCATOR_NUM: &str = "1.3.6.1.5.5.7.48.1.7";
pub(crate) const OCSP_EXT_SERVICE_LOCATOR_NAME: &str = "id-pkix-ocsp 7";

pub(crate) const OCSP_EXT_PREF_SIG_ALGS_ID: usize = 7;
pub(crate) const OCSP_EXT_PREF_SIG_ALGS_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x08];
pub(crate) const OCSP_EXT_PREF_SIG_ALGS_NUM: &str = "1.3.6.1.5.5.7.48.1.8";
pub(crate) const OCSP_EXT_PREF_SIG_ALGS_NAME: &str = "id-pkix-ocsp 8";

pub(crate) const OCSP_EXT_EXTENDED_REVOKE_ID: usize = 8;
pub(crate) const OCSP_EXT_EXTENDED_REVOKE_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x09];
pub(crate) const OCSP_EXT_EXTENDED_REVOKE_NUM: &str = "1.3.6.1.5.5.7.48.1.9";
pub(crate) const OCSP_EXT_EXTENDED_REVOKE_NAME: &str = "id-pkix-ocsp 9";

pub(crate) const ALGO_SHA1_ID: usize = 9;
pub(crate) const ALGO_SHA1_HEX: [u8; 5] = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
pub(crate) const ALGO_SHA1_NUM: &str = "1.3.14.3.2.26";
pub(crate) const ALGO_SHA1_NAME: &str = "{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26)}";

pub(crate) const ALGO_SHA1_WITH_RSA_ENCRYPTION_ID: usize = 10;
pub(crate) const ALGO_SHA1_WITH_RSA_ENCRYPTION_HEX: [u8; 9] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
pub(crate) const ALGO_SHA1_WITH_RSA_ENCRYPTION_NUM: &str = "1.2.840.113549.1.1.5";
pub(crate) const ALGO_SHA1_WITH_RSA_ENCRYPTION_NAME: &str =
    "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha1-with-rsa-signature(5)}";

/// NOT the number of OID, highest num in OID_MAX  
/// eg.  
/// oid_map contains 4 algos [0..3]  
/// OID_MAX_ID = 3
pub(crate) const OID_MAX_ID: usize = 10;

lazy_static! {
    /// search oid index by oid binary
    pub static ref OID_MAP: HashMap<Vec<u8>, usize> = vec![
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
    ]
    .into_iter()
    .collect();

    /// list of ocsp extension oid names
    pub static ref OCSP_EXT_NAME_LIST: [&'static str; 11] = [
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
    ];

    /// list of ocsp extension oid in num dot format
    pub static ref OCSP_EXT_NUM_LIST: [&'static str; 11] = [
        OCSP_EXT_NONCE_NUM,
        OCSP_EXT_CRLREF_NUM,
        OCSP_EXT_RESP_TYPE_NUM,
        OCSP_EXT_ARCHIVE_CUTOFF_NUM,
        OCSP_EXT_CRL_REASON_NUM,
        OCSP_EXT_INVALID_DATE_NUM,
        OCSP_EXT_SERVICE_LOCATOR_NUM,
        OCSP_EXT_PREF_SIG_ALGS_NUM,
        OCSP_EXT_EXTENDED_REVOKE_NUM,
        ALGO_SHA1_NUM,
        ALGO_SHA1_WITH_RSA_ENCRYPTION_NUM,
    ];

    /// list of ocsp extension oid in bytes
    pub static ref OCSP_EXT_HEX_LIST: [Vec<u8>; 11] = [
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
    ];
}

#[cfg(test)]
mod test {
    use tokio;

    use super::*;

    // test dot notation to oid
    #[tokio::test]
    async fn test_dot2oid() {
        let dot = OCSP_EXT_EXTENDED_REVOKE_NUM;
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
