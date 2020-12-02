//! asn1_common contains common trait and fn for OCSP request and response
use super::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use log::error;

/// OCSP request binary object
///
///```rust
/// use ocsp_rs::asn1_common::*;
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
/// let req = OcspAsn1Der::parse(&asn1).unwrap();
///```
/// above binary data has the following structure:
///
/// <table>
///   <tr>
///     <th>ASN1 hex</th>
///     <th>ASN1 scheme</th>
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
/// Or Verifying two certificates in one request
/// ```
/// 30 81B5(181)
///   30 81B2(178)
///   30 818A(138)
///   | 30 43
///   |   30 41
///   |     30 09
///   |       06 05 2B0E03021A
///   |       05 00
///   |     04 14 694D18A9BE42F7802614D4844F23601478B78820
///   |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
///   |     02 08 41300983331F9D4F
///   | 30 43
///   |   30 41
///   |     30 09
///   |       06 05 2B0E03021A
///   |       05 00
///   |     04 14 694D18A9BE42F7802614D4844F23601478B78820
///   |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
///   |     02 08 6378E51D448FF46D
///   A2 23
///   | 30 21
///   |   30 1F
///   |     06 09 2B0601050507300102
///   |     04 12 04105E7A74E51C861A3F79454658BB090244
/// ```
///
pub struct OcspAsn1Der<'d> {
    seq: Sequence<'d>,
}

impl<'d> OcspAsn1Der<'d> {
    /// create Sequence type from raw der
    pub fn parse(t: &'d DerObject) -> Result<Self, OcspError> {
        match t.try_into() {
            Ok(v) => Ok(OcspAsn1Der { seq: v }),
            Err(e) => {
                error!("Unable to parse ocsp request, due to {}.", e);
                Err(e)
            }
        }
    }
}

impl<'d> DecodeAsn1 for OcspAsn1Der<'d> {
    /// extracting CERTID list into vector
    fn extract_certid(&self, tag: &mut Vec<u8>, value: &mut Vec<Vec<u8>>) -> Result<u8, OcspError> {
        // push tag sequence
        let mut examine = false;
        for i in 0..self.seq.len() {
            let tmp = self.seq.get(i).map_err(OcspError::Asn1DecodingError)?;
            match tmp.tag() {
                0x30 => {
                    let seq = Sequence::decode(tmp.raw()).map_err(OcspError::Asn1DecodingError)?;

                    match OcspAsn1Der::extract_certid(&OcspAsn1Der { seq: seq }, tag, value)? {
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
            match count_match_tags(&CERTID_TAG.to_vec(), tag) {
                // mismatching tag sequence, this is not our sequence
                0 => {
                    tag.clear();
                    value.clear();
                    return Ok(2);
                }
                // matching 30(6, 5), keep checking
                2 => return Ok(0),
                // we have the full sequence
                5 => return Ok(1),
                _ => return Err(OcspError::Asn1ExtractionUnknownError),
            }
        }

        Ok(0)
    }

    /// return sequence data
    fn get_sequence(&self) -> &Sequence {
        &self.seq
    }
}

/// see [ocsp_rs::asn1_common::OcspAsn1Der::extract_certid()]
pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

/// count number of matching tag to a sequence
/// - **target** target tag sequence
/// - **tbm** tag sequence to be examined
pub(crate) fn count_match_tags(target: &Vec<u8>, tbm: &Vec<u8>) -> usize {
    if tbm.len() > target.len() {
        return 0;
    }

    let partial = &target[0..tbm.len()];
    tbm.iter().zip(partial).filter(|(t, p)| t == p).count()
}

/// allow convert to asn1_der::typed::Sequence
pub trait TryIntoSequence {
    /// converting asn1_der::err
    type Error;
    /// try converting to Sequence
    fn try_into(&self) -> Result<Sequence, Self::Error>;
}

impl TryIntoSequence for DerObject<'_> {
    type Error = OcspError;
    fn try_into(&self) -> Result<Sequence, Self::Error> {
        Sequence::decode(self.raw()).map_err(OcspError::Asn1DecodingError)
    }
}

/// common asn1 value extractions
pub trait DecodeAsn1 {
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
    fn extract_certid(&self, tag: &mut Vec<u8>, value: &mut Vec<Vec<u8>>) -> Result<u8, OcspError>;

    /// get sequence type of asn1 data
    fn get_sequence(&self) -> &Sequence;
}
