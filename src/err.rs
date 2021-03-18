//! error definitions
use thiserror::Error;

/// all lib functions return OcspError
pub type Result<T> = std::result::Result<T, OcspError>;

/// crate error enum
#[derive(Error, Debug)]
pub enum OcspError {
    /// cannot convert raw data into asn1_der::typed::*;
    #[error(transparent)]
    Asn1DecodingError(#[from] asn1_der::Asn1DerError),

    /// cannot find matching sequence  
    /// eg. OID sequence is not 0x06, 0x05
    #[error("Unable to extract desired sequence of {0}")]
    Asn1MismatchError(&'static str),

    /// unable to parse vec\<u8\> to &str   
    /// eg. requestorName
    #[error("Unable to deserialize string from ocsp req/resp")]
    Asn1Utf8Error(#[from] std::str::Utf8Error),

    /// sequence length does not match intended data  
    /// eg. OID length is not 2, 0x06, 0x05
    #[error("Unable to deserialize {0} due to incorrect sequence length")]
    Asn1LengthError(&'static str),

    /// Cannot find OID in predefined list
    #[error("Unable to locate OID info")]
    Asn1OidUnknown,

    /// ASN.1 TLV reaches max length allowed
    #[error("ASN.1 allows max 127 bytes to represents a length in TLV, but got {0}")]
    Asn1LengthOverflow(usize),

    /// Cannot recognize ocsp extension
    #[error("Unable to recognize extension")]
    OcspExtUnknown,

    /// Explicit tag not defined in RFC
    #[error("Non RFC defined tagging")]
    OcspUndefinedTagging,

    /// OCSP response type is not supported
    // only basic type is supported now
    #[error("Unsupported response type")]
    OcspUnsupportedResponseType,

    /// Creating an OCSP response with inappropriate method
    #[error("Inappropriate response creation due to {0}")]
    OcspRespStatusError(&'static str),

    /// Undefined OCSP response status
    #[error("Undefined OCSP response status {0}")]
    OcspRespUndefinedStatus(u8),

    /// Cannot parse provided date
    #[error("Invalid date year {0} month {1} day {2}")]
    GenInvalidDate(i32, u32, u32),

    /// Cannot parse provided time
    #[error("Invalid time hour {0} minute {1} second {2}")]
    GenInvalidTime(u32, u32, u32),

    /// Missing revoke info for revoked certificate
    #[error("Revoke info not found")]
    GenRevokeInfoNotFound,
}

// display error location
//#[macro_export]
//macro_rules! err_at {
//    () => {
//        concat!("at ", file!(), " line ", line!(), " column ", column!())
//    };
//}
