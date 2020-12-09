//! asn1_common contains common trait and fn for OCSP request and response
//! this module provides sync functions only under 'sync' feature
use crate::err::OcspError;
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use log::error;

use crate::common::TryIntoSequence;

/// OCSP request binary object
///
///```rust
/// use ocsp_rs::sync::asn1_common::*;
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
/// ```asn1
/// 30 81B5(181)
///   30 81B2(178)
///     30 818A(138)
///     | 30 43
///     |   30 41
///     |     30 09
///     |       06 05 2B0E03021A
///     |       05 00
///     |     04 14 694D18A9BE42F7802614D4844F23601478B78820
///     |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
///     |     02 08 41300983331F9D4F
///     | 30 43
///     |   30 41
///     |     30 09
///     |       06 05 2B0E03021A
///     |       05 00
///     |     04 14 694D18A9BE42F7802614D4844F23601478B78820
///     |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
///     |     02 08 6378E51D448FF46D
///     A2 23
///     | 30 21
///     |   30 1F
///     |     06 09 2B0601050507300102
///     |     04 12 04105E7A74E51C861A3F79454658BB090244
/// ```
///
#[allow(dead_code)]
pub struct OcspAsn1Der<'d> {
    seq: Sequence<'d>,
}

#[allow(dead_code)]
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
    fn extract_certid(&self, tag: &mut Vec<u8>, value: &mut Vec<Vec<u8>>) -> Result<u8, OcspError> {
        // push tag sequence
        let mut examine = false;
        for i in 0..self.seq.len() {
            let tmp = self.seq.get(i).map_err(OcspError::Asn1DecodingError)?;
            match tmp.tag() {
                0x30 => {
                    let mut v = tmp.header().to_vec();
                    v.extend(tmp.value());
                    let seq = Sequence::decode(&v[..]).map_err(OcspError::Asn1DecodingError)?;

                    match OcspAsn1Der::extract_certid(&OcspAsn1Der { seq }, tag, value)? {
                        0 => break,
                        1 => continue,
                        _ => return Err(OcspError::Asn1ExtractionUnknownError),
                    }
                }
                0x02 | 0x04 | 0x05 | 0x06 => {
                    tag.push(tmp.tag());
                    value.push(tmp.value().to_vec());
                    examine = true;
                }
                _ => break,
            }
        }

        // check tag sequence
        if examine {
            match count_match_tags(&CERTID_TAG.to_vec(), tag) % CERTID_TAG.len() {
                // we have the sequence
                0 => return Ok(1),
                // matching 30(6, 5), keep checking
                2 => return Ok(1),
                // bad match
                _ => {
                    tag.truncate(tag.len() / CERTID_TAG.len());
                    value.truncate(value.len() / CERTID_TAG.len());
                    return Ok(0);
                }
            }
        }

        Ok(1)
    }
}

#[allow(dead_code)]
/// see [ocsp_rs::asn1_common::OcspAsn1Der::extract_certid()]
pub(crate) const CERTID_TAG: [u8; 5] = [6u8, 5u8, 4u8, 4u8, 2u8];

/// count number of matching tag to a sequence
/// - **target** target tag sequence
/// - **tbm** tag sequence to be examined
#[allow(dead_code)]
pub(crate) fn count_match_tags(target: &[u8], tbm: &[u8]) -> usize {
    let mut tt = target.to_vec();
    while tt.len() < tbm.len() {
        tt.extend(target);
    }
    let tt = &tt[..tbm.len()];
    tbm.iter().zip(tt).filter(|(m, t)| m == t).count()
}

#[cfg(test)]
mod test {
    use super::OcspAsn1Der;
    use asn1_der::{
        typed::{DerDecodable, Sequence},
        DerObject,
    };
    // test data produces an ocsp request generated by openssl.
    // trying parse asn1
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
    // extracting single certid
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
        let asn1 = OcspAsn1Der::parse(&asn1).unwrap();
        let mut tag = Vec::new();
        let mut val: Vec<Vec<u8>> = Vec::new();
        let _ = asn1.extract_certid(&mut tag, &mut val);
        //println!(
        //    "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
        //    tag, val
        //);
        assert_eq!(tag, vec![0x06u8, 0x05, 0x04, 0x04, 0x02]);
        assert_eq!(
            val,
            vec![
                vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
                vec![],
                vec![
                    0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
                    0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
                ],
                vec![
                    0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
                    0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
                ],
                vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d]
            ]
        );
    }

    #[test]
    // extracting multiple certid
    fn ocsp_req_multiple_certid() {
        let ocsp_req_hex = "3081b53081b230818a30433041300906\
052b0e03021a05000414694d18a9be42\
f7802614d4844f23601478b788200414\
397be002a2f571fd80dceb52a17a7f8b\
632be755020841300983331f9d4f3043\
3041300906052b0e03021a0500041469\
4d18a9be42f7802614d4844f23601478\
b788200414397be002a2f571fd80dceb\
52a17a7f8b632be75502086378e51d44\
8ff46da2233021301f06092b06010505\
07300102041204105e7a74e51c861a3f\
79454658bb090244";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let asn1 = OcspAsn1Der::parse(&asn1).unwrap();
        let mut tag = Vec::new();
        let mut val = Vec::new();
        let _ = asn1.extract_certid(&mut tag, &mut val);
        //println!(
        //    "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
        //    tag, val
        //);
        assert_eq!(
            tag,
            vec![0x06u8, 0x05, 0x04, 0x04, 0x02, 0x06, 0x05, 0x04, 0x04, 0x02]
        );
        assert_eq!(
            val,
            vec![
                vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
                vec![],
                vec![
                    0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
                    0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
                ],
                vec![
                    0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
                    0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
                ],
                vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f],
                vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
                vec![],
                vec![
                    0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
                    0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
                ],
                vec![
                    0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
                    0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
                ],
                vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d],
            ]
        );
    }

    #[test]
    // first sequence mismatch
    fn ocsp_req_wrong_certid() {
        // missing 05 after 06
        let ocsp_req_hex = "306c\
306a\
3043\
3041\
303f\
3007\
06052b0e03021a\
0414694d18a9be42f7802614d4844f23601478b78820\
0414397be002a2f571fd80dceb52a17a7f8b632be755\
02086378e51d448ff46d\
a2233021\
301f\
06092b0601050507300102\
041204101cfc8fa3f5e15ed760707bc46670559b";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let asn1 = OcspAsn1Der::parse(&asn1).unwrap();
        let mut tag = Vec::new();
        let mut val = Vec::new();
        let _ = asn1.extract_certid(&mut tag, &mut val);
        //println!(
        //    "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
        //    tag, val
        //);
        assert_eq!(tag, vec![]);
    }

    #[test]
    // second sequence mismatch
    // removing first 04 from first certid
    fn ocsp_req_extract_second_certid() {
        let ocsp_req_hex = "30819e\
30819b\
3074\
302d\
302b\
3009\
06052b0e03021a\
0500\
0414397be002a2f571fd80dceb52a17a7f8b632be755\
020841300983331f9d4f\
3043\
3041\
3009\
06052b0e03021a\
0500\
0414694d18a9be42f7802614d4844f23601478b78820\
0414397be002a2f571fd80dceb52a17a7f8b632be755\
02086378e51d448ff46d\
a2233021301f06092b0601050507300102041204105e7a74e51c861a3f79454658bb090244";
        let ocsp_req_bin = hex::decode(ocsp_req_hex).unwrap();
        let asn1 = DerObject::decode(&ocsp_req_bin[..]).unwrap();
        let asn1 = OcspAsn1Der::parse(&asn1).unwrap();
        let mut tag = Vec::new();
        let mut val = Vec::new();
        let _ = asn1.extract_certid(&mut tag, &mut val);
        //println!(
        //    "-----tag-----\n{:02X?}\n{:02X?}\n------end of line -----",
        //    tag, val
        //);
        assert_eq!(tag, vec![0x06u8, 0x05, 0x04, 0x04, 0x02]);
        assert_eq!(
            val,
            vec![
                vec![0x2b, 0x0e, 0x03, 0x02, 0x1a],
                vec![],
                vec![
                    0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f,
                    0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20
                ],
                vec![
                    0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1,
                    0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55
                ],
                vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d]
            ]
        );
    }
}
