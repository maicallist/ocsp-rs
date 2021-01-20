//! common ocsp components

use asn1_der::DerObject;
use tracing::{debug, error, trace};

use crate::common::asn1::{
    TryIntoSequence, ASN1_EXPLICIT_0, ASN1_EXPLICIT_1, ASN1_EXPLICIT_2, ASN1_OID,
};
use crate::err_at;
use crate::{err::OcspError, oid::*};

use super::asn1::{asn1_encode_length, asn1_encode_octet, ASN1_SEQUENCE};

/// RFC 6960 4.4 OCSP extensions
#[derive(Debug)]
pub enum OcspExt {
    /// 4.4.1
    Nonce {
        ///id-pkix-ocsp 2
        oid_id: usize,
        /// nonce value
        nonce: Vec<u8>,
    },
    /// 4.4.2  
    /// REVIEW: untested
    CrlRef {
        /// id-pkix-ocsp 3
        oid_id: usize,
        /// EXPLICIT 0 IA5String OPTIONAL
        url: Option<Vec<u8>>,
        /// EXPLICIT 1 INTEGER OPTIONAL
        num: Option<Vec<u8>>,
        /// EXPLICIT 2 GeneralizedTime OPTIONAL
        time: Option<Vec<u8>>,
    },
}

impl OcspExt {
    /// parse ocsp extension  
    /// raw is sequence of list extensions  
    /// remove explicit and implicit tags first
    pub async fn parse<'d>(raw: &[u8]) -> Result<Vec<Self>, OcspError> {
        debug!("Start decoding Extensions");
        trace!("Parsing EXTENSION list {:02X?}", raw);

        let mut r: Vec<OcspExt> = Vec::new();

        debug!("Converting EXT data into asn1 sequence");
        let list = raw.try_into()?;
        for i in 0..list.len() {
            //let ext: Sequence = list.get_as(i).map_err(OcspError::Asn1DecodingError)?;
            let ext = list.get(i).map_err(OcspError::Asn1DecodingError)?;
            r.push(OcspExt::parse_oneext(ext.raw()).await?);
        }

        debug!("Good extensions decoded");
        Ok(r)
    }

    /// pass in each sequence of extension, return OcspExt
    async fn parse_oneext<'d>(oneext: &[u8]) -> Result<Self, OcspError> {
        debug!("Start decoding one extension");
        trace!("Parsing SINGLE EXTENSION {:02X?}", oneext);
        debug!("Converting EXT data into asn1 sequence");
        let oneext = oneext.try_into()?;

        let oid = oneext.get(0).map_err(OcspError::Asn1DecodingError)?;
        debug!("Checking OID tag");
        if oid.tag() != ASN1_OID {
            return Err(OcspError::Asn1MismatchError("OID", err_at!()));
        }
        let val = oid.value();
        // translate oid
        debug!("Resolving OID");
        let ext_id = match b2i_oid(val).await {
            None => return Err(OcspError::Asn1OidUnknown(err_at!())),
            Some(v) => v,
        };

        let r = match ext_id {
            OCSP_EXT_NONCE_ID => {
                debug!("Found NONCE extension");
                OcspExt::Nonce {
                    oid_id: ext_id,
                    nonce: oneext
                        .get(1)
                        .map_err(OcspError::Asn1DecodingError)?
                        .value()
                        .to_vec(),
                }
            }
            OCSP_EXT_CRLREF_ID => {
                debug!("Found CRLREF extension");
                let mut url = None;
                let mut num = None;
                let mut time = None;
                for i in 1..oneext.len() {
                    let tmp = oneext.get(i).map_err(OcspError::Asn1DecodingError)?;
                    let val = match tmp.tag() {
                        ASN1_EXPLICIT_0..=ASN1_EXPLICIT_2 => tmp.value(),
                        _ => return Err(OcspError::Asn1MismatchError("Ext CrlRef", err_at!())),
                    };
                    match tmp.tag() {
                        ASN1_EXPLICIT_0 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            url = Some(val.value().to_vec());
                        }
                        ASN1_EXPLICIT_1 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            num = Some(val.value().to_vec());
                        }
                        ASN1_EXPLICIT_2 => {
                            let val =
                                DerObject::decode(val).map_err(OcspError::Asn1DecodingError)?;
                            time = Some(val.value().to_vec());
                        }
                        _ => {
                            return Err(OcspError::Asn1MismatchError(
                                "Ext CrlRef EXP tag",
                                err_at!(),
                            ))
                        }
                    }
                }

                OcspExt::CrlRef {
                    oid_id: ext_id,
                    url: url,
                    num: num,
                    time: time,
                }
            }
            OCSP_EXT_RESP_TYPE_ID
            | OCSP_EXT_ARCHIVE_CUTOFF_ID
            | OCSP_EXT_CRL_REASON_ID
            | OCSP_EXT_INVALID_DATE_ID
            | OCSP_EXT_SERVICE_LOCATOR_ID
            | OCSP_EXT_PREF_SIG_ALGS_ID
            | OCSP_EXT_EXTENDED_REVOKE_ID => {
                unimplemented!()
            }
            _ => return Err(OcspError::OcspExtUnknown(err_at!())),
        };

        debug!("Good single extension decoded");
        Ok(r)
    }

    /// encode a list of extensions, wrapped in explicit tag
    pub async fn list_to_der(ext_list: &[OcspExt], exp_tag: u8) -> Result<Vec<u8>, OcspError> {
        debug!(
            "Start encoding {} ext, with tag {:02x?}",
            ext_list.len(),
            exp_tag
        );
        trace!("Ext list: {:?}", ext_list);

        // in req and resp, extensions are labelled either 0, 1, 2
        match exp_tag {
            ASN1_EXPLICIT_0 | ASN1_EXPLICIT_1 | ASN1_EXPLICIT_2 => {}
            _ => {
                return Err(OcspError::OcspUndefinedTagging(err_at!()));
            }
        }

        let mut v = vec![];
        for i in 0..ext_list.len() {
            v.extend(ext_list[i].to_der().await?);
        }
        let len = asn1_encode_length(v.len()).await?;
        let mut r = vec![ASN1_SEQUENCE];
        r.extend(len);
        r.extend(v);

        let mut exp = vec![exp_tag];
        let len = asn1_encode_length(r.len()).await?;
        exp.extend(len);
        exp.extend(r);

        debug!("Good ext list encoded");
        Ok(exp)
    }

    /// encode one extension to ASN.1 DER
    pub async fn to_der(&self) -> Result<Vec<u8>, OcspError> {
        let mut v = vec![ASN1_SEQUENCE];
        match &self {
            OcspExt::Nonce { oid_id: _, nonce } => {
                debug!("Start encoding Nonce extension");
                trace!("Nonce {:?}", self);
                // == OCSP_EXT_HEX_NONCE
                let mut id = vec![
                    0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02,
                ];
                let nc = asn1_encode_octet(&nonce).await?;
                id.extend(nc);
                let len = asn1_encode_length(id.len()).await?;
                v.extend(len);
                v.extend(id);
            }
            _ => {
                error!("Unsupported Extension");
                unimplemented!()
            }
        };

        debug!("Good extension encoded");
        Ok(v)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio;

    /// test ext list to ASN.1 DER
    #[tokio::test]
    async fn list_nonce_to_der() {
        let nonce = OcspExt::Nonce {
            oid_id: OCSP_EXT_NONCE_ID,
            nonce: vec![
                0x04, 0x10, 0x5E, 0x7A, 0x74, 0xE5, 0x1C, 0x86, 0x1A, 0x3F, 0x79, 0x45, 0x46, 0x58,
                0xBB, 0x09, 0x02, 0x44,
            ],
        };
        let list = [nonce];
        let v = OcspExt::list_to_der(&list, ASN1_EXPLICIT_2).await.unwrap();
        let c = vec![
            0xa2, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
            0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x5E, 0x7A, 0x74, 0xE5, 0x1C, 0x86, 0x1A,
            0x3F, 0x79, 0x45, 0x46, 0x58, 0xBB, 0x09, 0x02, 0x44,
        ];

        assert_eq!(c, v);
    }

    /// test nonce to ASN.1 DER
    #[tokio::test]
    async fn nonce_to_der() {
        let nonce = OcspExt::Nonce {
            oid_id: OCSP_EXT_NONCE_ID,
            nonce: vec![
                0x04, 0x10, 0x5E, 0x7A, 0x74, 0xE5, 0x1C, 0x86, 0x1A, 0x3F, 0x79, 0x45, 0x46, 0x58,
                0xBB, 0x09, 0x02, 0x44,
            ],
        };

        let v = nonce.to_der().await.unwrap();
        let c = vec![
            0x30, 0x1f, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
            0x12, 0x04, 0x10, 0x5E, 0x7A, 0x74, 0xE5, 0x1C, 0x86, 0x1A, 0x3F, 0x79, 0x45, 0x46,
            0x58, 0xBB, 0x09, 0x02, 0x44,
        ];

        assert_eq!(c, v);
    }
}
