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

/// find OID info
/// see [doc](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN)
pub async fn find_oid(oid: Vec<u8>) -> Option<&'static ConstOid> {
    OID_LIST.get(&oid)
}

/// OID info
#[derive(Debug)]
pub struct ConstOid {
    /// internal id for OID
    pub(crate) id: u8,
    /// OID in number format, eg. 1.3.6.1.3.5
    pub num: &'static str,
    /// OID in text format, eg. pkix-ocsp 1
    pub name: &'static str,
    /// OID in binary format
    pub bin: Vec<u8>,
}

lazy_static! {
    /// predefined OID list
    pub(crate) static ref OID_LIST: HashMap<Vec<u8>, ConstOid> = vec![
        (
            OCSP_EXT_NONCE_HEX.to_vec(),
            ConstOid {
                id: OCSP_EXT_NONCE_ID,
                num: OCSP_EXT_NONCE_NUM,
                name: OCSP_EXT_NONCE_NAME,
                bin: OCSP_EXT_NONCE_HEX.to_vec(),
            }
        ),
        (
            OCSP_EXT_CRLREF_HEX.to_vec(),
            ConstOid {
                id: OCSP_EXT_CRLREF_ID,
                num: OCSP_EXT_CRLREF_NUM,
                name: OCSP_EXT_CRLREF_NAME,
                bin: OCSP_EXT_CRLREF_HEX.to_vec(),
            }
        ),
    ]
    .into_iter()
    .collect();
}
