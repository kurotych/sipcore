use sipmsg::*;

#[test]
fn parse_headers() {
    let parse_headers_result = SipHeaders::parse(
        "To: sip:user@example.com\r\n\
         From: caller<sip:caller@example.com>;tag=323\r\n\
         Max-Forwards: 70\r\n\
         Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
         CSeq: 60 OPTIONS\r\n\
         CustomHeader: value;param=false\r\n\
         Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
            .as_bytes(),
    );

    match parse_headers_result {
        Ok((input, hdrs)) => {
            assert_eq!(hdrs.len(), 7);
            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::To).unwrap().value,
                "sip:user@example.com"
            );
            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::From).unwrap().value,
                "caller<sip:caller@example.com>"
            );
            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"tag"),
                Some((&SipAscii::new("tag"), &Some("323")))
            );

            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::MaxForwards).unwrap().value,
                "70"
            );
            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::MaxForwards).unwrap().params(),
                None
            );

            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::CallID).unwrap().value,
                "lwsdisp.1234abcd@funky.example.com"
            );
            assert_eq!(hdrs.get_rfc_s(SipRFCHeader::CallID).unwrap().params(), None);

            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::CSeq).unwrap().value,
                "60 OPTIONS"
            );
            assert_eq!(hdrs.get_rfc_s(SipRFCHeader::CSeq).unwrap().params(), None);

            assert_eq!(hdrs.get_ext_s("customheader").unwrap().value, "value");
            assert_eq!(
                hdrs.get_ext_s("customheader")
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"param"),
                Some((&SipAscii::new("param"), &Some("false")))
            );

            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::Via).unwrap().value,
                "SIP/2.0/UDP funky.example.com"
            );
            assert_eq!(
                hdrs.get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"branch"),
                Some((&SipAscii::new("branch"), &Some("z9hG4bKkdjuw")))
            );

            assert_eq!(input, "\r\nsomebody".as_bytes());
        }
        Err(_e) => panic!(),
    }
}
