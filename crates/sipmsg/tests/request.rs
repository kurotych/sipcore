use sipmsg::*;
use unicase::Ascii;

#[test]
fn parse_request() {
    let invite_msg_buf = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                          Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
                          To: Bob <sip:bob@biloxi.com>\r\n\
                          From: Alice <sip:alice@atlanta.com>;tag=88sja8x;onemore\r\n\
                          Max-Forwards: 70\r\n\
                          Contact: Caller <sip:alice@client.atlanta.example.com;transport=tcp>\r\n\
                          Call-ID: 987asjd97y7atg\r\n\
                          Call-Info: <http://wwww.example.com/alice/photo.jpg> ;purpose=icon, \r\n \
                          <http://www.example.com/alice/> ;purpose=info\r\n\
                          Accept: application/h.245;q=0.1\r\n\
                          CSeq: 986759 INVITE\r\n\r\nbody_stuff"
        .as_bytes();

    let res = SipRequest::parse(invite_msg_buf);
    let (_, parsed_req) = res.unwrap();

    assert_eq!(parsed_req.rl.method, SipMethod::INVITE);
    assert_eq!(parsed_req.rl.uri.scheme, SipRequestUriScheme::SIP);
    assert_eq!(parsed_req.rl.uri.user_info().unwrap().value, "bob");
    assert_eq!(parsed_req.rl.uri.hostport.host, "biloxi.com");
    assert_eq!(parsed_req.rl.sip_version, SipVersion(2, 0));

    assert_eq!(parsed_req.headers.len(), 9);
    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::Via)
            .unwrap()
            .value
            .vstr,
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
            .value
            .vstr,
        "Bob <sip:bob@biloxi.com>"
    );
    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::From)
            .unwrap()
            .value
            .vstr,
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
            .value
            .vstr,
        "70"
    );

    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::CallID)
            .unwrap()
            .value
            .vstr,
        "987asjd97y7atg"
    );

    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::CSeq)
            .unwrap()
            .value
            .vstr,
        "986759 INVITE"
    );

    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::Accept)
            .unwrap()
            .value
            .vstr,
        "application/h.245"
    );

    assert_eq!(
        parsed_req
            .headers
            .get_rfc_s(SipRFCHeader::Accept)
            .unwrap()
            .params()
            .unwrap()
            .get(&"q"),
        Some((&SipAscii::new("q"), &Some("0.1")))
    );

    let callinfo_headers = parsed_req.headers.get_rfc(SipRFCHeader::CallInfo).unwrap();
    assert_eq!(
        callinfo_headers[0].value.vstr,
        "http://wwww.example.com/alice/photo.jpg"
    );
    assert_eq!(
        callinfo_headers[0].value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "http://wwww.example.com/alice/photo.jpg".as_bytes()
    );

    assert_eq!(
        callinfo_headers[0].params().unwrap().get("purpose"),
        Some((&SipAscii::new("purpose"), &Some("icon")))
    );

    assert_eq!(
        callinfo_headers[1].value.vstr,
        "http://www.example.com/alice/"
    );
    assert_eq!(
        callinfo_headers[1].value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "http://www.example.com/alice/".as_bytes()
    );

    assert_eq!(
        callinfo_headers[1].params().unwrap().get("purpose"),
        Some((&SipAscii::new("purpose"), &Some("info")))
    );

    let contact_header = parsed_req.headers.get_rfc_s(SipRFCHeader::Contact).unwrap();
    assert_eq!(
        contact_header.value.tags().unwrap()[&SipHeaderTagType::DisplayName],
        b"Caller"
    );
    assert_eq!(
        contact_header
            .value
            .sip_uri()
            .unwrap()
            .user_info()
            .unwrap()
            .value,
        "alice"
    );
    assert_eq!(
        contact_header.value.sip_uri().unwrap().hostport.host,
        "client.atlanta.example.com"
    );
    assert_eq!(
        contact_header
            .value
            .sip_uri()
            .unwrap()
            .params()
            .unwrap()
            .get(&"transport"),
        Some((&Ascii::new("transport"), &Some("tcp")))
    );

    assert_eq!(parsed_req.body.unwrap(), "body_stuff".as_bytes())
}

#[test]
fn get_method_type() {
    let res = SipRequestLine::parse("OPTIONS sip:user@example.com SIP/2.0\r\n".as_bytes());
    let (_, rl) = res.unwrap();

    assert_eq!(rl.method, SipMethod::OPTIONS);
    assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIP);
    assert_eq!(rl.sip_version, SipVersion(2, 0));
    assert_eq!(rl.uri.user_info().unwrap().value, "user");
    assert_eq!(rl.uri.hostport.host, "example.com");

    let res = SipRequestLine::parse(
        "INVITE sips:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n".as_bytes(),
    );
    let (_, rl) = res.unwrap();

    assert_eq!(rl.method, SipMethod::INVITE);
    assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIPS);
    assert_eq!(rl.sip_version, SipVersion(2, 0));
    assert_eq!(rl.uri.user_info().unwrap().value, "vivekg");
    assert_eq!(rl.uri.hostport.host, "chair-dnrc.example.com");
    assert_eq!(
        rl.uri.params().unwrap().get(&"unknownparam"),
        Some((&Ascii::new("unknownparam"), &None))
    );

    let res = SipRequestLine::parse("REGISTER sip:[2001:db8::10]:9999 SIP/3.1\r\n".as_bytes());
    let (_, rl) = res.unwrap();

    assert_eq!(rl.method, SipMethod::REGISTER);
    assert_eq!(rl.uri.scheme, SipRequestUriScheme::SIP);
    assert_eq!(rl.sip_version, SipVersion(3, 1));
    assert_eq!(rl.uri.hostport.host, "2001:db8::10");
    assert_eq!(rl.uri.hostport.port.unwrap(), 9999);
}

#[test]
fn get_method_type_fail() {
    match SipRequestLine::parse("OPTI2ONS sip:user@example.com SIP/2.0\r\n".as_bytes()) {
        Ok((_, _)) => panic!(),
        Err(_e) => (),
    }
}
