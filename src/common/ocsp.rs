//! Common ocsp components

use asn1_der::DerObject;
use tracing::{error, trace};

use crate::common::asn1::{
    TryIntoSequence, ASN1_EXPLICIT_0, ASN1_EXPLICIT_1, ASN1_EXPLICIT_2, ASN1_OID,
};
use crate::{err::OcspError, oid::*};

use super::asn1::{asn1_encode_length, asn1_encode_octet, ASN1_SEQUENCE};
use crate::common::asn1::Bytes;

/// OCSP extension with internal id
#[derive(Debug, Clone)]
pub struct OcspExtI {
    /// internal id of extension, see const in [crate::oid]
    pub id: usize,
    /// extension variant
    pub ext: OcspExt,
}

impl OcspExtI {
    /// parse ocsp extension  
    /// raw is a sequence of multiple extensions  
    /// remove explicit and implicit tags first
    pub async fn parse(raw: &[u8]) -> Result<Vec<Self>, OcspError> {
        trace!("Parsing extension list");

        let mut r: Vec<OcspExtI> = Vec::new();

        let list = raw.try_into()?;
        for i in 0..list.len() {
            let ext = list.get(i).map_err(OcspError::Asn1DecodingError)?;
            let (id, ext) = OcspExt::parse_oneext(ext.raw()).await?;
            r.push(OcspExtI { id, ext });
        }

        trace!("{} extensions successfully decoded", r.len());
        Ok(r)
    }

    /// encode a list of extensions, wrapped in explicit tag
    pub async fn list_to_der(ext_list: &[OcspExtI], exp_tag: u8) -> Result<Bytes, OcspError> {
        trace!("Encoding {} ext, with tag {:02x?}", ext_list.len(), exp_tag);
        trace!("Ext list: {:?}", ext_list);

        // in req and resp, extensions are labelled either 0, 1, 2
        match exp_tag {
            ASN1_EXPLICIT_0 | ASN1_EXPLICIT_1 | ASN1_EXPLICIT_2 => {}
            _ => {
                return Err(OcspError::OcspUndefinedTagging);
            }
        }

        let mut v = vec![];
        for e in ext_list {
            v.extend(e.ext.to_der().await?)
        }

        let len = asn1_encode_length(v.len()).await?;
        let mut r = vec![ASN1_SEQUENCE];
        r.extend(len);
        r.extend(v);

        let mut exp = vec![exp_tag];
        let len = asn1_encode_length(r.len()).await?;
        exp.extend(len);
        exp.extend(r);

        trace!("Ext list successfully encoded");
        Ok(exp)
    }
}

/// RFC 6960 4.4 OCSP extensions
#[derive(Debug, Clone)]
pub enum OcspExt {
    /// 4.4.1
    Nonce {
        /// nonce value
        nonce: Bytes,
    },
    /// 4.4.2  
    /// REVIEW: untested
    CrlRef {
        /// EXPLICIT 0 IA5String OPTIONAL
        url: Option<Bytes>,
        /// EXPLICIT 1 INTEGER OPTIONAL
        num: Option<Bytes>,
        /// EXPLICIT 2 GeneralizedTime OPTIONAL
        time: Option<Bytes>,
    },
}

impl OcspExt {
    /// pass in each sequence of extension, return OcspExt
    async fn parse_oneext<'d>(oneext: &[u8]) -> Result<(usize, Self), OcspError> {
        trace!("Parsing single extension {}", hex::encode(oneext));
        let oneext = oneext.try_into()?;

        let oid = oneext.get(0).map_err(OcspError::Asn1DecodingError)?;
        if oid.tag() != ASN1_OID {
            return Err(OcspError::Asn1MismatchError("OID"));
        }
        let val = oid.value();
        // translate oid
        let ext_id = match b2i_oid(val).await {
            None => return Err(OcspError::Asn1OidUnknown),
            Some(v) => v,
        };

        let r = match ext_id {
            OCSP_EXT_NONCE_ID => {
                trace!("Found nonce extension");
                OcspExt::Nonce {
                    nonce: oneext
                        .get(1)
                        .map_err(OcspError::Asn1DecodingError)?
                        .value()
                        .to_vec(),
                }
            }
            OCSP_EXT_CRLREF_ID => {
                trace!("Found crlref extension");
                let mut url = None;
                let mut num = None;
                let mut time = None;
                for i in 1..oneext.len() {
                    let tmp = oneext.get(i).map_err(OcspError::Asn1DecodingError)?;
                    let val = match tmp.tag() {
                        ASN1_EXPLICIT_0..=ASN1_EXPLICIT_2 => tmp.value(),
                        _ => return Err(OcspError::Asn1MismatchError("Ext CrlRef")),
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
                        _ => return Err(OcspError::Asn1MismatchError("Ext CrlRef EXP tag")),
                    }
                }

                OcspExt::CrlRef { url, num, time }
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
            _ => return Err(OcspError::OcspExtUnknown),
        };

        trace!("One extension successfully decoded");
        Ok((ext_id, r))
    }

    /// encode one extension to ASN.1 DER
    pub async fn to_der(&self) -> Result<Bytes, OcspError> {
        let mut v = vec![ASN1_SEQUENCE];
        match &self {
            OcspExt::Nonce { nonce } => {
                trace!("Encoding nonce extension");
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

        trace!("Extension successfully encoded");
        Ok(v)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// test ext list to ASN.1 DER
    #[tokio::test]
    async fn list_nonce_to_der() {
        let nonce = OcspExt::Nonce {
            nonce: vec![
                0x04, 0x10, 0x5E, 0x7A, 0x74, 0xE5, 0x1C, 0x86, 0x1A, 0x3F, 0x79, 0x45, 0x46, 0x58,
                0xBB, 0x09, 0x02, 0x44,
            ],
        };
        let nonce = OcspExtI {
            id: OCSP_EXT_NONCE_ID,
            ext: nonce,
        };
        let list = [nonce];
        let v = OcspExtI::list_to_der(&list, ASN1_EXPLICIT_2).await.unwrap();
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
