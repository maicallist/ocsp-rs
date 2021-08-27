# OCSP-RS

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![codecov](https://codecov.io/gh/maicallist/ocsp-rs/branch/master/graph/badge.svg?token=TMNVADDBOK)](https://codecov.io/gh/maicallist/ocsp-rs)
![master](https://github.com/maicallist/ocsp-rs/actions/workflows/master.yml/badge.svg?branch=master)

## ocsp-rs supports encoding/decoding OCSP request and response

## Features

- request encoding [WIP]
- request decoding
- response encoding
- response decoding [WIP]

## Usage

```toml
[dependencies]
ocsp = "*"
```

### Server side

- parsing incoming request

```rust
use ocsp::request::OcspRequest;

let recv_request: BytesMut = BytesMut::new();
// reading payload
let ocsp_request = OcspRequest::parse(&recv_request[..]).await.unwrap();

// get CertId from request
let cid_list = ocsp_request.extract_certid_owned().await;
```

- generating response

```rust
use ocsp::{
    common::asn1::{CertId, GeneralizedTime, Oid},
    oid::{ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT, OCSP_RESPONSE_BASIC_DOT},
    response::{
        BasicResponse, CertStatus as OcspCertStatus, CertStatus, CertStatusCode, CrlReason,
        OcspRespStatus, OcspResponse, OneResp, ResponderId, ResponseBytes, ResponseData,
        RevokedInfo,
    },
};


let key = [0x36, 0x6f, 0x35, 0xfb, 0xef, 0x16, 0xc6, 0xba, 0x8a, 0x31, 0x83, 0x42, 0x6d, 0x97, 0xba, 0x89, 0x4d, 0x55, 0x6e, 0x91];
let id = ResponderId::new_key_hash(&key).await; // responding by id

// year, month, day, hour(24), minute, second
let produce = GeneralizedTime::new(2021, 1, 12, 21, 26, 43).await.unwrap();
// you can extract cid from request
let oid = Oid::new_from_dot("1.3.14.3.2.26").await.unwrap();
let name = vec![ 0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23, 0x60, 0x14, 0x78, 0xb7, 0x88, 0x20];
let key = vec![ 0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a, 0x7f, 0x8b, 0x63, 0x2b, 0xe7, 0x55];
let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
let certid = CertId::new(oid.clone(), &name, &key, &sn).await;

let good = OcspCertStatus::new(CertStatusCode::Good, None).await;
let gt = GeneralizedTime::new(2021, 1, 12, 3, 26, 43).await.unwrap();

let one = OneResp {
    cid: certid.clone(),
    cert_status: good,
    this_update: gt,
    next_update: None,
    one_resp_ext: None,
};

let sn2 = vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d];
let certid2 = CertId::new(oid, &name, &key, &sn2).await;
let rev_t = GeneralizedTime::new(2020, 11, 30, 1, 48, 25).await.unwrap();
let rev_info = RevokedInfo::new(rev_t, Some(CrlReason::OcspRevokeUnspecified)).await;
let revoke = OcspCertStatus::new(CertStatusCode::Revoked, Some(rev_info)).await;
let two = OneResp {
    cid: certid2,
    cert_status: revoke,
    this_update: gt,
    next_update: None,
    one_resp_ext: None,
};

let list = [one, two].to_vec();
let data = ResponseData::new(id, produce, list, None).await;
// other signatures also supported, see oid
// equivalent to
// let oid = Oid::new_from_dot("1.2.840.113549.1.1.5").await.unwrap();
let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT).await.unwrap();
let sign = vec![ 0x00 ]; //example signature

let basic = BasicResponse::new(data, oid, sign, None).await;
// equivalent to
// let resp_type = Oid::new_from_dot("1.3.6.1.5.5.7.48.1.1").await.unwrap();
let resp_type = Oid::new_from_dot(OCSP_RESPONSE_BASIC_DOT).await.unwrap();
let bytes = ResponseBytes::new_basic(resp_type, basic).await.unwrap();
let ocsp = OcspResponse::new_success(bytes).await;
let resp_binary = ocsp.to_der().await.unwrap();

// return resp_binary as response body
```

---

### Client side [WIP]

- generating request
