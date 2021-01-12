//! OCSP response

///

/// 30 821295           %% RFC OCSP Response
///     0a 01 00        %% RFC response status ENUMERATED
///     a0 82128e 30 82128a  %% RFC response bytes
///         06 09 2b0601050507300101        %% response type
///         04 82127b                       %% response
///
///             30 821277                   %% basic response
///                 30 81f2                 %% tbs response data
///                 |   a2 16 04 14 366f35fbef16c6ba8a3183426d97ba894d556e91    %% Responder By Key EXP 2
///                 |   18 0f 32303231303131323033323634335a                    %% produced at
///                 |   30 81c6                                                 %% responses
///                 |       30 56                                               %% response 1
///                 |       |   30 41                                           %% certid
///                 |       |       30 09                                       %% oid
///                 |       |           06 05 2b0e03021a
///                 |       |           05 00
///                 |       |       04 14 694d18a9be42f7802614d4844f23601478b78820
///                 |       |       04 14 397be002a2f571fd80dceb52a17a7f8b632be755
///                 |       |       02 08 41300983331f9d4f
///                 |       |   80 00                                           %% cert status good
///                 |       |   18 0f 32303231303131323033323634335a            %% this update
///                 |       30 6c                                               %% response 2
///                 |           30 41                                           %% certid
///                 |               30 09
///                 |                   06 05 2b0e03021a
///                 |                   05 00
///                 |               04 14 694d18a9be42f7802614d4844f23601478b78820
///                 |               04 14 397be002a2f571fd80dceb52a17a7f8b632be755
///                 |               02 08 6378e51d448ff46d
///                 |           a1 16                                           %% status revoke            
///                 |               18 0f 32303230313133303031343832355a        %% revoke time
///                 |               a0 03 0a 01 00                              %% reason ENUMERATED
///                 |           18 0f 32303231303131323033323634335a            %% this update
///                 30 0d                                                       %% sign algo                  
///                     06 09 2a864886f70d010105
///                     05 00
///                 03 820101 001e022d5ba25aa6ee97c5d910c61ebe                  %% signature   
///                             b73db75a767deb43af88c2a56377d9e5aeaa5484
///                             30087b5429d9b90b30569f9444676ad3
///                             a9885fb6d29cd46489ea1a82c369790d
///                             2a4943f4ca93c97706c929707fb6e5b4
///                             9d433b84003bd9aa24a395278ab63e7a
///                             2622d2ec7d3579453e7960bbcfca6d0d
///                             3db0fe460f7c2bbaf72e8c6fb85c7c65
///                             37ea0cb3c36811a8950f7396987598a5
///                             b3c89fc1466cb17c559589d85d8af954
///                             d607c43ff708ddf5d6672faa14fbc717
///                             b55352c2110450f220e8a0be9e6a8664
///                             a6acdca63ae3a706b72cc19da227ce5e
///                             1a8f69adce38f45f8dd3874885898d7c
///                             ebd6057fd8e5f327694198edd90fe6e8
///                             21613be71e3ba24f4db85f10a7
/// optional certs below
///                 a0 82106a 30 821066         %% certs
///                     30 8205a2               %% cert 1
///                         30 82038a           %% tbs certificate
///                             a0 03 02 01 02  %% version EXP 0
///                             02 08 590cb28d6ededd2c        
///                         30 0d               %% signature algo id
///                             06 09 2a864886f70d01010b    
///                             05 00
///                         30 3d               %% issuer
///                             31 0b 30 09 06 035504061302434e    
///                             31 0d 30 0b 06 0355040a0c04434e5043
///                             31 1f 30 1d 06 035504030c16e8aebee5a487e8af81e4b9a6e4b8ade5bf835f525341
///                         30 1e               %% validity
///                             17 0d 3139303432323039323730325a
///                             17 0d 3339303431373039323730325a
///                         30 3b               %% subject
///                             31 0b 30 09 06 035504061302434e310d300b060355040a0c04434e5043311d301b06035504030c14e8aebee5a487e8aea4e8af814f4353505f525341
///                         30 82               %% subject public key info
///                             0122300d06092a864886f70d01010105000382010f003082010a0282010100ce405ecf00076a7b
///                             2582bd9d5d21e1e4c6cacdc402604213
///                             a1cd04c7f3e3a40fe949a1d4b9c69328
///                             2fcdbe82289072a07fe845a897f30b41
///                             1be90b9e1906b440f33026890bbc9641
///                             5abdfa05082f0f538ee39e426e65312f
///                             116b789a5b99e164526b05d57cbf7ad4
///                             fe8766a8d939ef777f3c029e2d48ef05
///                             03bb93ee4ebc9373d22e0d60a09b8de5
///                             01df2c84942672705865b87aa3aed09f
///                             d744553c294e689511c237275f4472ea
///                             fac0c63d4922be3f1c143f23bfa05083
///                             3a3c3bcf9a95e0a64e7d8d47796cfe0d
///                             074d444ad5c2eff88549e10dcca2aca6
///                             5d3a2b4aafa1f4b0bdee0a8a6d36af13
///                             b019223952cb6a09f66ff2c129302449
///                             67dffbcf43cdccb10203010001
///                         a3 82 01a6 30 8201a %% extension 6 ext below
///                             301f0603551d2304183016
///                             8014397be002a2f571fd80dceb52a17a
///                             7f8b632be755301d0603551d0e041604
///                             14366f35fbef16c6ba8a3183426d97ba
///                             894d556e91300c0603551d1304053003
///                             010100300b0603551d0f0404030206c0
///                             3081e00603551d1f0481d83081d53036
///                             a034a032a430302e310b300906035504
///                             061302434e3110300e060355040b0c07
///                             4144443143524c310d300b0603550403
///                             0c0463726c303023a021a01f861d6874
///                             74703a2f2f31312e31302e3134372e31
///                             37322f63726c302e63726c3076a074a0
///                             7286706c6461703a2f2f31312e31302e
///                             3134372e3137323a3338392f434e3d63
///                             726c302c4f553d4144443143524c2c43
///                             3d434e3f636572746966696361746552
///                             65766f636174696f6e4c6973743f6261
///                             73653f6f626a656374636c6173733d63
///                             524c446973747269627574696f6e506f
///                             696e74306206082b0601050507010104
///                             563054302b06082b0601050507300286
///                             1f687474703a2f2f31312e31302e3134
///                             382e38332f636169737375652e68746d
///                             302506082b0601050507300186196874
///                             74703a2f2f31312e31302e3134372e31
///                             393a3230343433
///                         30 0d                   %% algo id
///                             06 09 2a864886f70d01010b
///                             05 00
//                          03 820201 00205e726dbb      %% signature
///                                     8ffb9b91a6e04e587549e9c61a499972
///                                     c84536fe11dde7ff40a5aab9403614ac
///                                     cf473c3efc6023f9e5095a06af6ea542
///                                     68f756b7aa115050fd6c2325f027e9ac
///                                     bbe09152f1ec1940e1c98607f396589c
///                                     4cf00206ec9a5a73d72fd0ee8f22dbbd
///                                     e194730fa8bd0035289a5cdb84ac4a80
///                                     604c192d58bfb56c90b47a4603adff67
///                                     a36a4c02e6258250b92ddabdea470c44
///                                     938d2dc675666b17d781419e96b89f9b
///                                     b245f0c5a625b4a0f419ac5672f91952
///                                     f9166ee1170bdabcdc718aef397391d5
///                                     9c4c88df4ceeb90f8e087ac3a9f7df71
///                                     44bf4e24afbd33d89ed424d8dfbae042
///                                     90182cf16a5c648ae2ae821d9f60ae7f
///                                     87fe2d990f9ba977a9acdde463551a87
///                                     990cfe726e3a40c4f57fcd2f8cce82a7
///                                     494b09156ae54706925d5e78cc3abc40
///                                     cf2b5959203fcc84c4572510d0b4680c
///                                     963854770b131a0b9c0c3e8520ad6448
///                                     8312b89dac978d1cff5c3e788e70fced
///                                     dc76ea950093aff5198172894d37105d
///                                     d8b8f3f44de4a6b8c5bc819b8830eaa5
///                                     c3be76bd7b75c3da887f41faf8e50db4
///                                     9cdac42181731132de39ca89db0d4130
///                                     43323da5b59874209c1c6cac1b341326
///                                     f2facd45b845c038a0645c5bc61e046a
///                                     e487fef0643a2271456e9ab8b8d6b1b2
///                                     cf0110e448d4ed634cea2922314e6b92
///                                     b081db23a4a2d597f64aaeeedccf8163
///                                     9288c886ee88fc304606fbd724c6e10c
///                                     f0dd80eeae5f4bb758d381
/// two more certs
/// 3082055b30
/// 820343a003020102020828b8741df160
/// 3649300d06092a864886f70d01010b05
/// 00303f310b300906035504061302434e
/// 310d300b060355040a0c04434e504331
/// 21301f06035504030c18e4b8ade59bbd
/// e79fb3e6b2b9e8aea4e8af81e4b8ade5
/// bf83301e170d31393031313531333134
/// 34315a170d3438313131383133313434
/// 315a303d310b30090603550406130243
/// 4e310d300b060355040a0c04434e5043
/// 311f301d06035504030c16e8aebee5a4
/// 87e8af81e4b9a6e4b8ade5bf835f5253
/// 4130820222300d06092a864886f70d01
/// 010105000382020f003082020a028202
/// 0100d5c8d3036f264018fb6b70badd71
/// e1355585e35f77740636f4e53cce39a7
/// 34ae6d51babe652c0fee909383aa524d
/// a8561c7f1badca8de9fccfc24b6b630d
/// 87348f1842cdf7389d42d6766cd31a2b
/// 71e48f3024e7192d613bfff255c65812
/// fe9272f75ec5d6f717d28cde99b4e431
/// 1eeda2047cf7bffd942b6042fc568d50
/// 4ceb314d9a82fee33d287f68591a8e11
/// ea7e8e9fb94b1bcbd4dae531204f41ff
/// e4ac25428fb19ec788cc167e30e7ef79
/// 0244f006fb0d669362b1d9fc70ae8528
/// 30fa6240f1a9b138a8e4a325e0da316f
/// 43b0000c74268529b0c2d88c992a5473
/// 1dd1e01dfe86298cf09e8181cc8970ac
/// 65ea2fb41db6750e6571564faeecb04d
/// 5e8f54afc0002c639210eb71e971632b
/// ae3a4feef78842af91291c35b5c39113
/// 97bd30c601fbd00e2229bb8f86a1a0c3
/// 2d9230c03222f2d471a4db77f1ed44cb
/// 47c61edb807f1c0a1606dab68b2d9715
/// cd245bb1eda595873097ad475429d2c7
/// 6367b087bd4532da2e6447d1665becbb
/// 4dfc86edb1403d6acb7f40d41c1ec4ab
/// 6fe1588e2a97b3d3ecdcd3f9e760d6bd
/// 9ba6f56b4354e2a0520746e9293aaf10
/// c46db8600c6972518beb6e99750dbbdf
/// 914f60b034720e4568920e31385ebe81
/// 132350161ccf6b9d8189facbcb2889ec
/// 1b5b7ef87ca0b86f9ee1310cfb66965b
/// 8f1349ab8c625fbb3fddbf8064a8f7fe
/// 1aeb5f18cbb43ef8c1c379df22daa1ee
/// 041f0203010001a35d305b301f060355
/// 1d2304183016801495464638c8fde6e9
/// 7948ab0dd7dd66f233e76c1d301d0603
/// 551d0e04160414397be002a2f571fd80
/// dceb52a17a7f8b632be755300c060355
/// 1d13040530030101ff300b0603551d0f
/// 040403020106300d06092a864886f70d
/// 01010b05000382020100a7b3ce75bc33
/// 53f3fbcd47f05edd201923ce98506e08
/// 92911e386de87f746c6179e981f0afff
/// 7a817c7c19b8f34e1c02148fcc604e60
/// dddbbd0cb25835a498c5f184d904b8ae
/// aeecb7e12446d53894249a9241e18f26
/// b195fc65cd8655268ad4195460bedece
/// 6da38148256ea46ba1d09c2e2941ac9a
/// 7c88a36467d867798130da832d48c4f6
/// 3c556567453687c19f83615d9fca6cbf
/// 187d0d1ea391409e92c43a55a5730704
/// 38a680a65b07598ffcb6c560f1d44c17
/// 6f8d91a6473894a471255cb29bf76cf9
/// c6e7e568098e970874b5458e87e86040
/// e57ea310137b70bb8f7736fc6383bf46
/// b2684ebf5d9a43b19dc714865888709e
/// 3274d848b08dc416b57c54e8d96444d5
/// f2fb3f99f417deedb1905f2b5b82dc9f
/// f701eddc3dc8d64055b9694b6ca45083
/// e09a3ac793fc32d9a1e8d8f4f879071e
/// 347beadd2f5774edc80ddfa18b26b656
/// 586554cdd222eea6c4a9c00511615758
/// 6ebb41c684af490731098308ff8f37c4
/// 477c9595386f1504a3d3c98d818e685b
/// 08106d3308e2916f2e706c3c2e66edaa
/// d95bc7c60420dd8b7910e1120d6e3f10
/// 7b7ad5672cc76fc673743cb4a877f17a
/// d58b57fa93332a5ba77a9ea5ee28a83d
/// 30be13b4c6688d683a8662c20d5bad4e
/// 36e784cf51703def778fe0eff1872471
/// e33abea5b6e78e43e38f424ba2a00acd
/// 90a77913fba57120f6c60b8ee9987e83
/// b620d528f35b4f305add3082055d3082
/// 0345a003020102020860ce251d0fe412
/// 67300d06092a864886f70d01010b0500
/// 303f310b300906035504061302434e31
/// 0d300b060355040a0c04434e50433121
/// 301f06035504030c18e4b8ade59bbde7
/// 9fb3e6b2b9e8aea4e8af81e4b8ade5bf
/// 83301e170d3138313231303131303535
/// 315a170d343831323032313130353531
/// 5a303f310b300906035504061302434e
/// 310d300b060355040a0c04434e504331
/// 21301f06035504030c18e4b8ade59bbd
/// e79fb3e6b2b9e8aea4e8af81e4b8ade5
/// bf8330820222300d06092a864886f70d
/// 01010105000382020f003082020a0282
/// 020100bea2f11b6e1a5b20bd56d9072e
/// 4726a2c8b280451feeddb4db7e818c53
/// e463d4037c9a9f400054930d62cb22a4
/// 3838e410c0c8220e1fa51a86ce831be1
/// 544c25fa4e02c4fb82a6dcb00b496cd2
/// aa780c7b3393bf5289fc4a065d87a289
/// 094c9f2639cc51fb34011fe91da3231e
/// 25e979741728e3f07c6a9600f8b6f88e
/// ad6fd16ef50eb10728494d55a92d07ed
/// d2b55cbc4622b8b587710262e91c980e
/// 9ff65254c0272a95f656a752efd2fe48
/// 878dd62f3a972eb034ae9b89ef7da343
/// 8e7ce5f5437b99fc70bfcceb9e1f2f8a
/// c04678806f6f43061f44879c24466f8f
/// a8fe4d645024e8e24576a282a79ecf2d
/// 9bdb50aae3caf87026341ba5efdee947
/// e84988907cde132fb680536f32ef0da3
/// fc9953bd714685e80cdb85be7a713e88
/// d6298b836151c9c9028e9dd85806b5e3
/// e66eef792b61bda591a4c63d023caf1f
/// fddbc07d7a1e9d7bc8cc0175f8e91fe5
/// 140d942d056a3364f61758044b3fdcb6
/// 5247e55d227861eb3f5b017c52324039
/// 828ba809f6b71f090c6dd971e95dd2c4
/// 52090e10b1080fd77ef3db3d87fe3c0a
/// 53d200099a31768c8ce9458e8fc22374
/// 214d8ac32bbc414e5fa7cece2e041607
/// 9d7e38629ed3d910b8973603ad5ba00e
/// cef4daa200380ee641f527e2c3e1104b
/// 43009052af786071947c4f5424b8a8db
/// 339e7d60a6cf2019def587e30999a987
/// 8b23c957f748dd5b5786f910cc9f934a
/// 3449e30203010001a35d305b300b0603
/// 551d0f040403020106300c0603551d13
/// 040530030101ff301d0603551d0e0416
/// 041495464638c8fde6e97948ab0dd7dd
/// 66f233e76c1d301f0603551d23041830
/// 16801495464638c8fde6e97948ab0dd7
/// dd66f233e76c1d300d06092a864886f7
/// 0d01010b050003820201008098d8ebc2
/// 851de89f6df24893435a83e18521c571
/// 449183bb8fe95ed2655e3b658ce7552f
/// e6eb7729bbc04f9bee9ec83d0d7b7fb7
/// bfe09484d45483b8b7c75480d8ca9169
/// 1cd6ca0e37ff048ea2929d49a0beef27
/// 021f9cb0818d7c002e047dbdfb4d0291
/// a3f4aea939676c0e02a29d09bc228acb
/// d9bfa96e30af7c6a8058ce95c6b8677b
/// 117e56b22e4289a579ff60132f0e39ce
/// 98badf6aa00a9099930d99c9056a0189
/// 85b8fe6b7712db1d3e81a790bacd1b8c
/// a3977a7e473347bb90d94af960de0094
/// 4077430276669121b4b853c4724503ff
/// b78a8bc49288946d817bc14c54a10b67
/// 72c11b4a64da5eafb2343c6491acc63f
/// 5eda9f331fe2152c3a2753087d45b35c
/// 53c6d33510b03365e8d70d4acc3725fa
/// b59538163afd0907404d3afa6322d790
/// e9deb1c076d793f7f963bc681e1cf3b0
/// bb78c91a54e8fe4d80c8ffa4cfab2efe
/// 50487fdd96dcdc39c443ff3ac91cb6e7
/// b3850d39ccf3f565917720ecd1f71491
/// d97d0a81c699aae8a422f2eac1184fb2
/// a13f6150c60b654cace739870e9fdc34
/// 71f4d60d02f0306f0584dd057817bd3c
/// 52d50ce58f8aff7f7972dc7f2ed43219
/// aa06ac283c26063a7360d7b121ea29f2
/// 778db3604d040a512c864a9baae28448
/// 1adf7cfd7870afea2db54bc224d6f14e
/// 6a20e9e8a0a7bb9aa3fd41d865bb2403
/// 172abfde79c2fc2c9c759e4d003154fd
/// a92f48b476778ff0ce84d7
use crate::common::{asn1::GeneralizedTime, ocsp::OcspExt};
use crate::err::Result;
use crate::request::{CertId, Oid};

const OCSP_RESP_CERT_STATUS_GOOD: u8 = 0x00;
const OCSP_RESP_CERT_STATUS_REVOKED: u8 = 0x01;
const OCSP_RESP_CERT_STATUS_UNKNOWN: u8 = 0x02;

/// possible status for a cert
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum CertStatus {
    /// cert is valid
    OCSP_RESP_CERT_STATUS_GOOD,
    /// cert is revoked
    OCSP_RESP_CERT_STATUS_REVOKED,
    /// no cert info
    OCSP_RESP_CERT_STATUS_UNKNOWN,
}

/// see RFC 6960
#[derive(Debug)]
pub struct RevokedInfo {
    /// revocation time
    pub revocation_time: GeneralizedTime,
    /// revocation reason, exp 0
    pub revocation_reason: Option<Vec<u8>>,
}

impl RevokedInfo {
    /// return new instance
    pub async fn new(time: GeneralizedTime, reason: Option<String>) -> Self {
        let mut r = None;
        if let Some(s) = reason {
            r = Some(s.as_bytes().to_vec());
        }

        RevokedInfo {
            revocation_time: time,
            revocation_reason: r,
        }
    }

    /// serialize to DER encoding
    pub async fn to_der(&self) -> Vec<u8> {
        unimplemented!()
    }
}

/// RFC 6960 single response
#[derive(Debug)]
pub struct OneResp {
    /// certid of a single response
    pub one_resp: CertId,
    /// cert status
    pub cert_status: CertStatus,
    /// Responses whose thisUpdate time is later than the local system time SHOULD be considered unreliable.
    pub this_update: Vec<u8>,
    /// Responses whose nextUpdate value is earlier than the local system time value SHOULD be considered unreliable
    pub next_update: Option<Vec<u8>>,
    /// extension for single response
    pub one_resp_ext: Option<Vec<OcspExt>>,
}

const OCSP_RESPONDER_BY_NAME: u8 = 0x0;
const OCSP_RESPONDER_BY_KEY_HASH: u8 = 0x01;
/// responder type
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ResponderType {
    /// responder by name
    OCSP_RESPONDER_BY_NAME,
    /// responder by key hash
    OCSP_RESPONDER_BY_KEY_HASH,
}

/// indicates responder type
#[derive(Debug)]
pub struct ResponderId {
    /// id by name or key hash
    pub id_by: ResponderType,
    /// id
    pub id: Vec<u8>,
}

/// RFC 6960
#[derive(Debug)]
pub struct ResponseData {
    // REVIEW:
    // version
    /// responder id
    /// in case of KeyHash ::= OCTET STRING  
    /// SHA-1 hash of responder's public key (excluding the tag and length fields)
    pub responder_id: ResponderId,
    /// time of creating response
    pub produced_at: Vec<u8>,
    /// list of responses
    pub responses: Vec<OneResp>,
    /// exp 1
    pub resp_ext: Option<OcspExt>,
}

/// basic response
#[derive(Debug)]
pub struct BasicResponse {
    ///
    pub tbs_resp_data: ResponseData,
    ///
    pub signature_algo: Oid,
    ///  The value for signature SHALL be computed on the hash of the DER encoding of ResponseData
    pub signature: Vec<u8>,
    /// The responder MAY include certificates in  
    /// the certs field of BasicOCSPResponse that help the OCSP client verify  
    /// the responder's signature.  
    /// If no certificates are included, then certs SHOULD be absent
    pub certs: Option<Vec<Vec<u8>>>,
}

/// basic response  
/// The value for responseBytes consists of an OBJECT IDENTIFIER and a  
/// response syntax identified by that OID encoded as an OCTET STRING
#[derive(Debug)]
pub struct ResponseBytes {
    /// For a basic OCSP responder, responseType will be id-pkix-ocsp-basic
    pub response_type: Oid,
    /// basic response
    pub response_data: Vec<u8>,
}

const OCSP_RESP_STATUS_SUCCESSFUL: u8 = 0x00;
const OCSP_RESP_STATUS_MALFORMED_REQ: u8 = 0x01;
const OCSP_RESP_STATUS_INTERNAL_ERROR: u8 = 0x02;
const OCSP_RESP_STATUS_TRY_LATER: u8 = 0x03;
const OCSP_RESP_STATUS_SIG_REQUIRED: u8 = 0x05;
const OCSP_RESP_STATUS_UNAUTHORIZED: u8 = 0x06;

/// possible status for ocsp request
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum OcspRespStatus {
    /// See RFC 6960
    OCSP_RESP_STATUS_SUCCESSFUL,
    /// See RFC 6960
    OCSP_RESP_STATUS_MALFORMED_REQ,
    /// See RFC 6960
    OCSP_RESP_STATUS_INTERNAL_ERROR,
    /// See RFC 6960
    OCSP_RESP_STATUS_TRY_LATER,
    /// See RFC 6960
    OCSP_RESP_STATUS_SIG_REQUIRED,
    /// See RFC 6960
    OCSP_RESP_STATUS_UNAUTHORIZED,
}

/// ocsp response
#[derive(Debug)]
pub struct OcspResponse {
    /// response status
    pub resp_status: OcspRespStatus,
    /// If the value of responseStatus is one of the error conditions,  
    /// the responseBytes field is not set
    pub resp_bytes: Option<ResponseBytes>,
}
