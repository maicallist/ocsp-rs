//! ocsp-rs provides de/serialization for ocsp request and response in asn.1 der

struct OcspRequest {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    use hex;
    use simple_asn1;
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
        let asn1b = simple_asn1::from_der(&ocsp_req_bin[..]).unwrap();
        println!("{:?}", asn1b);
    }
}
