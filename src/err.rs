use thiserror::Error;

#[derive(Error, Debug)]
pub enum OcspError {
    #[error("Expecting data start with Sequence")]
    Asn1UnexpectedType,
    #[error("Unable to decode ASN1 data")]
    Asn1DecodingError(#[from] asn1_der::Asn1DerError),
    #[error("Unable to extract data from asn1 due to traversal issue")]
    Asn1ExtractionUnknownError,
}
