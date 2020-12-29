//! error definitions
use thiserror::Error;
/// crate error enum
#[derive(Error, Debug)]
pub enum OcspError {
    /// cannot convert raw data into asn1_der::typed::*;
    #[error(transparent)]
    Asn1DecodingError(#[from] asn1_der::Asn1DerError),

    /// extractor cannot find matching sequence  
    /// eg. OID sequence is not 0x06, 0x05
    #[error("Unable to extract desired sequence of {0}")]
    Asn1MismatchError(String),

    /// ocsp request contains unexpected data
    /// case 1: no sequence in request
    /// case 2: ocsp request is not {0x30} or {0x30, 0xA0}
    #[error("Ocsp request contains unexpected data")]
    Asn1MalformedTBSRequest,

    /// unable to parse vec\<u8\> to &str   
    /// eg. requestorName
    #[error("Unable to deserialize string from ocsp req/resp")]
    Asn1Utf8Error(#[from] std::str::Utf8Error),

    /// OID length is not 2, 0x06, 0x05
    #[error("Unable to deserialize {0} due to incorrect sequence length at {1}")]
    Asn1LengthError(&'static str, &'static str),

    /// CertID length is not 4
    #[error("Unable to deserialize CertID")]
    Asn1CertidLengthError,

    /// Cannot find OID in predefined list
    #[error("Unable to locate OID info")]
    Asn1OidUnknown,
}

/// display error location
#[macro_export]
macro_rules! error_origin {
    () => {
        concat!("at ", file!(), " line ", line!(), " column ", column!())
    };
}
