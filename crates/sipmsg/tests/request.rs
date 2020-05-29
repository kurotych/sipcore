use sipmsg::*;
use unicase::Ascii;

#[test]
fn parse_request() {
    let invite_msg_buf = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                          Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
                          To: Bob <sip:bob@biloxi.com>\r\n\
                          From: Alice <sip:alice@atlanta.com>;tag=88sja8x;onemore\r\n\
                          Max-Forwards: 70\r\n\
                          Call-ID: 987asjd97y7atg\r\n\
                          CSeq: 986759 INVITE\r\n\r\nbody_stuff"
        .as_bytes();

    match SipRequest::parse(invite_msg_buf) {
        Ok((_, parsed_req)) => {
            assert_eq!(parsed_req.rl.method, SipRequestMethod::INVITE);
            assert_eq!(parsed_req.rl.uri.scheme, SipRequestUriScheme::SIP);
            assert_eq!(parsed_req.rl.uri.user_info().unwrap().value, "bob");
            assert_eq!(parsed_req.rl.uri.hostport.host, "biloxi.com");
            assert_eq!(parsed_req.rl.sip_version, SipVersion(2, 0));

            assert_eq!(parsed_req.headers.len(), 6);
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .value,
                "SIP/2.0/UDP pc33.atlanta.com"
            );
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"branch"),
                Some((&SipAscii::new("branch"), &Some("z9hG4bKkjshdyff")))
            );
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::To)
                    .unwrap()
                    .value,
                "Bob <sip:bob@biloxi.com>"
            );
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .value,
                "Alice <sip:alice@atlanta.com>"
            );
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"tag"),
                Some((&SipAscii::new("tag"), &Some("88sja8x")))
            );
            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"onemore"),
                Some((&SipAscii::new("onemore"), &None))
            );

            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::MaxForwards)
                    .unwrap()
                    .value,
                "70"
            );

            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::CallID)
                    .unwrap()
                    .value,
                "987asjd97y7atg"
            );

            assert_eq!(
                parsed_req
                    .headers
                    .get_rfc_s(SipRFCHeader::CSeq)
                    .unwrap()
                    .value,
                "986759 INVITE"
            );

            assert_eq!(parsed_req.body.unwrap(), "body_stuff".as_bytes())
        }
        Err(_) => panic!(),
    }
}

#[test]
fn get_method_type() {
    match SipRequestLine::parse("OPTIONS sip:user@example.com SIP/2.0\r\n".as_bytes()) {
        Ok((_b, rl)) => {
            assert_eq!(rl.method, SipRequestMethod::OPTIONS);
            assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIP);
            assert_eq!(rl.sip_version, SipVersion(2, 0));
            assert_eq!(rl.uri.user_info().unwrap().value, "user");
            assert_eq!(rl.uri.hostport.host, "example.com");
        }
        Err(_e) => panic!(),
    }

    match SipRequestLine::parse(
        "INVITE sips:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n".as_bytes(),
    ) {
        Ok((_b, rl)) => {
            assert_eq!(rl.method, SipRequestMethod::INVITE);
            assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIPS);
            assert_eq!(rl.sip_version, SipVersion(2, 0));
            assert_eq!(rl.uri.user_info().unwrap().value, "vivekg");
            assert_eq!(rl.uri.hostport.host, "chair-dnrc.example.com");
            assert_eq!(
                rl.uri.params().unwrap().get(&"unknownparam"),
                Some((&Ascii::new("unknownparam"), &None))
            );
        }
        Err(_e) => panic!(),
    }

    match SipRequestLine::parse("REGISTER sip:[2001:db8::10]:9999 SIP/3.1\r\n".as_bytes()) {
        Ok((_b, rl)) => {
            assert_eq!(rl.method, SipRequestMethod::REGISTER);
            assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIP);
            assert_eq!(rl.sip_version, SipVersion(3, 1));
            assert_eq!(rl.uri.hostport.host, "2001:db8::10");
            assert_eq!(rl.uri.hostport.port.unwrap(), 9999);
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn get_method_type_fail() {
    match SipRequestLine::parse("OPTI2ONS sip:user@example.com SIP/2.0\r\n".as_bytes()) {
        Ok((_, _)) => panic!(),
        Err(_e) => (),
    }
}
