//! OID const and conversions

use lazy_static::lazy_static;
use std::collections::HashMap;

pub(crate) const OCSP_EXT_NONCE_ID: u8 = 2u8;
pub(crate) const OCSP_EXT_NONCE_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
pub(crate) const OCSP_EXT_NONCE_NUM: &str = "1.3.6.1.5.5.7.48.1.2";
pub(crate) const OCSP_EXT_NONCE_NAME: &str = "id-pkix-ocsp 2";

pub(crate) const OCSP_EXT_CRLREF_ID: u8 = 3u8;
pub(crate) const OCSP_EXT_CRLREF_HEX: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x03];
pub(crate) const OCSP_EXT_CRLREF_NUM: &str = "1.3.6.1.5.5.7.48.1.3";
pub(crate) const OCSP_EXT_CRLREF_NAME: &str = "id-pkix-ocsp 3";

/// converting oid to human-readable num
/// see https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN
pub async fn b2v_oid(oid: Vec<u8>) -> u8 {
    unimplemented!()
}

/// defined OID
pub struct ConstOid {
    pub(crate) id: u8,
    num: &'static str,
    name: &'static str,
}

lazy_static! {
    pub(crate) static ref OID_LIST: HashMap<Vec<u8>, ConstOid> = vec![
        (
            OCSP_EXT_NONCE_HEX.to_vec(),
            ConstOid {
                id: OCSP_EXT_NONCE_ID,
                num: OCSP_EXT_NONCE_NUM,
                name: OCSP_EXT_NONCE_NAME
            }
        ),
        (
            OCSP_EXT_CRLREF_HEX.to_vec(),
            ConstOid {
                id: OCSP_EXT_CRLREF_ID,
                num: OCSP_EXT_CRLREF_NUM,
                name: OCSP_EXT_CRLREF_NAME,
            }
        ),
    ]
    .into_iter()
    .collect();
}
