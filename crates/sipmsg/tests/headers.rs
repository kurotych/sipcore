use sipmsg::*;

#[test]
fn parse_headers() {
    let parse_headers_result = SipHeaders::parse(
        "To: sip:user@example.com\r\n\
         From: caller<sip:caller@example.com>;tag=323\r\n\
         Max-Forwards: 70\r\n\
         Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
         CSeq: 60 OPTIONS\r\n\
         Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
            .as_bytes(),
    );

    match parse_headers_result {
        Ok((input, hdrs)) => {
            assert_eq!(hdrs.len(), 6);
            assert_eq!(hdrs.get_s("to").unwrap().value, "sip:user@example.com");
            assert_eq!(hdrs.get_s("from").unwrap().value, "caller<sip:caller@example.com>");
            assert_eq!(hdrs.get_s("from").unwrap().params().unwrap().get(&"tag"), Some(&"323"));

            assert_eq!(hdrs.get_s("Max-forwards").unwrap().value, "70");
            assert_eq!(hdrs.get_s("Max-forwards").unwrap().params(), None);

            assert_eq!(hdrs.get_s("call-id").unwrap().value, "lwsdisp.1234abcd@funky.example.com");
            assert_eq!(hdrs.get_s("call-id").unwrap().params(), None);

            assert_eq!(hdrs.get_s("cseq").unwrap().value, "60 OPTIONS");
            assert_eq!(hdrs.get_s("cseq").unwrap().params(), None);

            assert_eq!(hdrs.get_s("via").unwrap().value, "SIP/2.0/UDP funky.example.com");
            assert_eq!(hdrs.get_s("via").unwrap().params().unwrap().get(&"branch"), Some(&"z9hG4bKkdjuw"));

            assert_eq!(input, "\r\nsomebody".as_bytes());
        }
        Err(_e) => panic!(),
    }
}