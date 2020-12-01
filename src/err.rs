use thiserror::Error;

#[derive(Error, Debug)]
pub enum OcspError {
    /// raw data does not start with a sequence
    #[error("Expecting data start with Sequence")]
    Asn1UnexpectedType,
    /// cannot convert raw data into asn1_der::typed::*;
    #[error("Unable to decode ASN1 data")]
    Asn1DecodingError(#[from] asn1_der::Asn1DerError),
    /// unexpected result from sequence matching fn
    #[error("Unable to extract data from asn1 due to traversal issue")]
    Asn1ExtractionUnknownError,
    #[error("Unable to convert between asn1 types")]
    Asn1ConversionError,
}
