//! ocsp-rs provides de/serialization for ocsp request and response in asn.1 der

use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use log::error;

mod err;
use err::OcspError;

/// OCSP request structure binary object
///
///```rust
/// use ocsp_rs::OcspRequestAsn1;
/// use asn1_der::typed::DerDecodable;
///
/// let ocsp_req = "306e306c304530433041300906052b0e\
///03021a05000414694d18a9be42f78026\
///14d4844f23601478b788200414397be0\
///02a2f571fd80dceb52a17a7f8b632be7\
///5502086378e51d448ff46da223302130\
///1f06092b060105050730010204120410\
///1cfc8fa3f5e15ed760707bc46670559b";
/// let ocsp_bin = hex::decode(ocsp_req).unwrap();
/// let asn1 = asn1_der::DerObject::decode(&ocsp_bin[..]).unwrap();
/// println!("asn1 tag: {:02X}, asn1 header: {:02X?}, asn1 value: {:02X?}", asn1.tag(), asn1.header(), asn1.value());
/// let seq = asn1_der::typed::Sequence::decode(asn1.raw()).unwrap();
/// let req = OcspRequestAsn1{ seq: seq};
///```
/// above binary data has the following structure:
///
/// <table>
///   <tr>
///     <th>ASN1 hex</th>
///     <th>ASN1 scheme</th>
///     <th>simple_asn1 struct</th>
///   </tr>
///   <tr>
///     <td>
///       <pre>
/// 30 6E
/// | 30 6C
/// |   30 45
/// |     30 43
/// |       30 41
/// |         30 09
/// |           06 05 2B0E03021A  --- OID
/// |           05 00             --- NULL
/// |         04 14 694D18A9BE42F7802614D4844F23601478B78820  --- OCTET
/// |         04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755  --- OCTET
/// |         02 08 6378E51D448FF46D  --- INT
/// |   A2 23  --- EXPLICIT TAG 2
/// |     30 21
/// |       30 1F
/// |         06 09 2B0601050507300102
/// |         04 12 04101CFC8FA3F5E15ED760707BC46670559B
/// |
/// |--- Sequence(30), 110 bytes(6E)
///       </pre>
///     </td>
///     <td>
///       <pre>
/// SEQUENCE {
///   SEQUENCE {
///   | SEQUENCE {
///   |   SEQUENCE {
///   |     SEQUENCE {
///   |     | SEQUENCE {
///   |     |    OBJECTIDENTIFIER 1.3.14.3.2.26 (id_sha1)
///   |     |    NULL
///   |     | }
///   |     | OCTETSTRING 694d18a9be42f7802614d4844f23601478b78820
///   |     | OCTETSTRING 397be002a2f571fd80dceb52a17a7f8b632be755
///   |     | INTEGER 0x6378e51d448ff46d
///   |     }
///   |   }
///   | }
///   | [2] {
///   |   SEQUENCE {
///   |   | SEQUENCE {
///   |   |   OBJECTIDENTIFIER 1.3.6.1.5.5.7.48.1.2
///   |   |   OCTETSTRING 04101cfc8fa3f5e15ed760707bc46670559b
///   |   | }
///   |   }
///   | }
///   }
/// }
///       </pre>
///     </td>
/// </table>
///
///
pub struct OcspRequestAsn1<'d> {
    /// Sequence of ASN1 data
    pub seq: Sequence<'d>,
}

/// see [OcspRequestAsn1::extract_certid()]
pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

impl<'d> OcspRequestAsn1<'d> {
    fn parse(data: &'d DerObject) -> Result<(), OcspError> {
        // ocsp request must be wrapped in sequence.
        if data.tag() != 0x30 {
            error!("OCSP request must start with a SEQUENCE.");
            return Err(OcspError::Asn1UnexpectedType);
        }; // error
           //let sequence = Sequence::decode(data.raw()).map_err(OcspError::Asn1DecodingError)?;

        unimplemented!()
    }

    /// Extracting CertId Sequence from ASN1 DER data.  
    /// tags must match following hex order:  
    /// 30(6, 5), 4, 4, 2  
    ///
    /// - **self.seq** A sequence to be examined
    /// - **tag** CertId tag array  
    /// per rfc 6960 CERTID matches sequence of OID, OCTET, OCTET, INTEGER,  
    /// thus tag should contain 0x06, 0x05, 0x04, 0x04, 0x02 as result.  
    /// In practice, openssl has 0x05 after OID 0x06.  
    /// - **value** corresponding value of @tag array  
    pub fn extract_certid(
        &self,
        tag: &mut Vec<u8>,
        value: &mut Vec<Vec<u8>>,
    ) -> Result<u8, OcspError> {
        // push tag sequence
        let mut examine = false;
        for i in 0..self.seq.len() {
            let tmp = self.seq.get(i).map_err(OcspError::Asn1DecodingError)?;
            match tmp.tag() {
                0x30 => {
                    let seq = Sequence::decode(tmp.raw()).map_err(OcspError::Asn1DecodingError)?;

                    match OcspRequestAsn1::extract_certid(
                        &OcspRequestAsn1 { seq: seq },
                        tag,
                        value,
                    )? {
                        0 => {}
                        1 => return Ok(1),
                        2 => break,
                        _ => return Err(OcspError::Asn1ExtractionUnknownError),
                    }
                }
                _ => {
                    tag.push(tmp.tag());
                    value.push(tmp.value().to_vec());
                    examine = true;
                }
            }
        }

        // check tag sequence
        if examine {
            if tag.len() > CERTID_TAG.len() {
                // we should never reach this line, cuz if we get a mismatch
                // we simply clear the result array.
                return Err(OcspError::Asn1ExtractionUnknownError);
            }
            // only comparing what we have.OcspError
            // when we start with inner sequence 30(6, 5)
            // we should only compare 6, 5
            // if it is the case, see if the remaining outer sequence matches 4, 4, 2
            let partial = &CERTID_TAG[0..tag.len()];
            if tag.iter().zip(partial).filter(|(t, p)| t == p).count() == tag.len() {
                if tag.len() == 5 {
                    // we have full the sequence
                    return Ok(1);
                } else {
                    // so far matching, keep checking
                    return Ok(0);
                }
            } else {
                // mismatching tag array, this is not our sequence
                tag.clear();
                value.clear();
                return Ok(2);
            }
        }

        Ok(0)
    }

    /// list type of items in a sequence
    fn list_sequence(seq: Sequence) -> Result<Vec<u8>, OcspError> {
        let mut r = Vec::new();
        for i in 0..seq.len() {
            r.push(seq.get(i).map_err(OcspError::Asn1DecodingError)?.tag());
        }
        Ok(r)
    }
}

pub struct OcspRequest {}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1_der::{
        typed::{
            Boolean, DerDecodable, DerEncodable, DerTypeView, Integer, Null, OctetString, Sequence,
            SequenceVec, Utf8String,
        },
        DerObject, SliceSink,
    };
    use hex;
    /// test data produces an ocsp request generated by openssl.
    #[test]
    fn ocsp_req_from_der() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
03021a05000414694d18a9be42f78026\
14d4844f23601478b788200414397be0\
02a2f571fd80dceb52a17a7f8b632be7\
5502086378e51d448ff46da223302130\
1f06092b060105050730010204120410\
1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let seq = Sequence::decode(asn1.raw()).unwrap();
        let first_item = seq.get(0).unwrap();
        let seq = Sequence::decode(first_item.raw()).unwrap();
        let _second_item = seq.get(1).unwrap();
    }

    #[test]
    fn ocsp_req_get_certid() {
        let ocsp_req_hex = "306e306c304530433041300906052b0e\
03021a05000414694d18a9be42f78026\
14d4844f23601478b788200414397be0\
02a2f571fd80dceb52a17a7f8b632be7\
5502086378e51d448ff46da223302130\
1f06092b060105050730010204120410\
1cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let seq = Sequence::decode(asn1.raw()).unwrap();
        let asn1 = OcspRequestAsn1 { seq: seq };
        let mut res = Vec::new();
        let mut val: Vec<Vec<u8>> = Vec::new();
        let _ = asn1.extract_certid(&mut res, &mut val);
        println!("{:02X?} ++ {:02X?}", res, val);
    }
}
