//! OCSP request format
//! <pre>
//! 30 6E               %% RFC OCSPRequest
//! | 30 6C             %% RFC TBSRequest
//! |   30 45           %% RFC requestList
//! |   | 30 43         %% RFC Request
//! |   |   30 41       %% RFC CertID
//! |   |     30 09
//! |   |       06 05 2B0E03021A  --- OID
//! |   |       05 00             --- NULL
//! |   |     04 14 694D18A9BE42F7802614D4844F23601478B78820  --- OCTET
//! |   |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755  --- OCTET
//! |   |     02 08 6378E51D448FF46D  --- INT
//!         30 imagine    %% RFC singleRequestExtensions
//! |   A2 23  --- EXPLICIT TAG 2   %% RFC requestExtensions
//! |   | 30 21
//! |   |   30 1F
//! |   |     06 09 2B0601050507300102
//! |   |     04 12 04101CFC8FA3F5E15ED760707BC46670559B
//! |
//! |--- Sequence(30), 110 bytes(6E)
//! </pre>
//!
//! Or verifying two certs in one request
//! <pre>
//! 30 81B5(181)
//!   30 81B2(178)
//!     30 818A(138)
//!     | 30 43
//!     |   30 41
//!     |     30 09
//!     |       06 05 2B0E03021A
//!     |       05 00
//!     |     04 14 694D18A9BE42F7802614D4844F23601478B78820
//!     |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
//!     |     02 08 41300983331F9D4F
//!     | 30 43
//!     |   30 41
//!     |     30 09
//!     |       06 05 2B0E03021A
//!     |       05 00
//!     |     04 14 694D18A9BE42F7802614D4844F23601478B78820
//!     |     04 14 397BE002A2F571FD80DCEB52A17A7F8B632BE755
//!     |     02 08 6378E51D448FF46D
//!     A2 23
//!     | 30 21
//!     |   30 1F
//!     |     06 09 2B0601050507300102
//!     |     04 12 04105E7A74E51C861A3F79454658BB090244
//! </pre>
