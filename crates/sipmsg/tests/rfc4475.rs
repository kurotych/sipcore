use sipmsg::*;

#[test]
fn parse_request() {
    let invite_msg_buf = "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n\
    TO :\r\n \
     sip:vivekg@chair-dnrc.example.com ;   tag    = 1918181833n\r\n\
    from   : \"J Rosenberg \\\"\"       <sip:jdrosen@example.com>\r\n \
      ;\r\n \
      tag = 98asjd8\r\n\
    MaX-fOrWaRdS: 0068\r\n\
    Call-ID: wsinv.ndaksdj@192.0.2.1\r\n\
    Content-Length   : 150\r\n\
    cseq: 0009\r\n \
      INVITE\r\n\
    Via  : SIP  /   2.0\r\n \
     /UDP\r\n \
        192.0.2.2;branch=390skdjuw\r\n\
    s :\r\n\
    NewFangledHeader:   newfangled value\r\n \
     continued newfangled value\r\n\
    UnknownHeaderWithUnusualValue: ;;,,;;,;\r\n\
    Content-Type: application/sdp\r\n\
    Route: \r\n \
     <sip:services.example.com;lr;unknownwith=value;unknown-no-value>\r\n\
    v:  SIP  / 2.0  / TCP     spindle.example.com   ;\r\n \
      branch  =   z9hG4bK9ikj8  ,\r\n \
     SIP  /    2.0   / UDP  192.168.255.111   ; branch=\r\n \
     z9hG4bK30239\r\n\
    m:\"Quoted string \\\"\\\"\" <sip:jdrosen@example.com> ; newparam =\r\n \
          newvalue ;\r\n \
          secondparam ; q = 0.33\r\n\
    \r\n\
    v=0\
    o=mhandley 29739 7272939 IN IP4 192.0.2.3\
    s=-\
    c=IN IP4 192.0.2.4\
    t=0 0\
    m=audio 49217 RTP/AVP 0 12\
    m=video 3227 RTP/AVP 31\
    a=rtpmap:31 LPC"
        .as_bytes();

    let res = SipRequest::parse(invite_msg_buf);
    let (_, parsed_req) = res.unwrap();
    let request_line = &parsed_req.rl;
    let headers = &parsed_req.headers;
    assert_eq!(request_line.method, SipMethod::INVITE);
    assert_eq!(request_line.uri.scheme, SipRequestUriScheme::SIP);
    assert_eq!(request_line.uri.user_info().unwrap().value, "vivekg");
    assert_eq!(request_line.uri.hostport.host, "chair-dnrc.example.com");
    assert_eq!(request_line.sip_version, SipVersion(2, 0));
    assert_eq!(
        request_line.uri.params().unwrap().get(&"unknownparam"),
        Some(&None)
    );

    let to_hdr = headers.get_rfc_s(SipRFCHeader::To).unwrap();
    assert_eq!(
        to_hdr.params().unwrap().get(&"tag"),
        Some(&Some("1918181833n"))
    );
    assert_eq!(to_hdr.value.vstr, "sip:vivekg@chair-dnrc.example.com");

    let from_hdr = headers.get_rfc_s(SipRFCHeader::From).unwrap();
    assert_eq!(
        from_hdr.value.vstr,
        "\"J Rosenberg \\\"\"       <sip:jdrosen@example.com>"
    );
    assert_eq!(
        from_hdr.value.tags().unwrap()[&SipHeaderTagType::DisplayName],
        b"J Rosenberg \\\""
    );
    assert_eq!(
        from_hdr.value.sip_uri().unwrap().user_info().unwrap().value,
        "jdrosen"
    );
    assert_eq!(
        from_hdr.value.sip_uri().unwrap().hostport.host,
        "example.com"
    );
    assert_eq!(
        from_hdr.params().unwrap().get(&"tag"),
        Some(&Some("98asjd8"))
    );

    let max_forwards = parsed_req
        .headers
        .get_rfc_s(SipRFCHeader::MaxForwards)
        .unwrap();
    assert_eq!(max_forwards.value.vstr, "0068");
    assert_eq!(max_forwards.params(), None);
    assert_eq!(max_forwards.value.vtype, SipHeaderValueType::Digit);

    let call_id = headers.get_rfc_s(SipRFCHeader::CallID).unwrap();
    assert_eq!(call_id.value.vstr, "wsinv.ndaksdj@192.0.2.1");
    assert_eq!(
        call_id.value.tags().unwrap()[&SipHeaderTagType::ID],
        b"wsinv.ndaksdj"
    );
    assert_eq!(
        call_id.value.tags().unwrap()[&SipHeaderTagType::Host],
        b"192.0.2.1"
    );

    let content_length = &parsed_req
        .headers
        .get_rfc_s(SipRFCHeader::ContentLength)
        .unwrap();
    assert_eq!(content_length.value.vstr, "150");

    let cseq_header = &headers.get_rfc_s(SipRFCHeader::CSeq).unwrap();
    assert_eq!(cseq_header.value.vstr, "0009\r\n INVITE");
    assert_eq!(cseq_header.params(), None);
    assert_eq!(
        cseq_header.value.tags().unwrap()[&SipHeaderTagType::Number],
        b"0009"
    );
    assert_eq!(
        cseq_header.value.tags().unwrap()[&SipHeaderTagType::Method],
        b"INVITE"
    );

    let via_hdrs = headers.get_rfc(SipRFCHeader::Via).unwrap();
    let first_via = &via_hdrs[0];
    assert_eq!(first_via.value.vstr, "SIP  /   2.0\r\n /UDP\r\n 192.0.2.2");
    assert_eq!(
        first_via.params().unwrap().get(&"branch"),
        Some(&Some("390skdjuw"))
    );

    assert_eq!(
        first_via.value.tags().unwrap()[&SipHeaderTagType::ProtocolName],
        b"SIP"
    );
    assert_eq!(
        first_via.value.tags().unwrap()[&SipHeaderTagType::ProtocolVersion],
        b"2.0"
    );
    assert_eq!(
        first_via.value.tags().unwrap()[&SipHeaderTagType::ProtocolTransport],
        b"UDP"
    );
    assert_eq!(
        first_via.value.tags().unwrap()[&SipHeaderTagType::Host],
        b"192.0.2.2"
    );

    let seond_via = &via_hdrs[1];
    assert_eq!(
        seond_via.value.tags().unwrap()[&SipHeaderTagType::ProtocolTransport],
        b"TCP"
    );
    assert_eq!(
        seond_via.value.vstr,
        "SIP  / 2.0  / TCP     spindle.example.com"
    );
    assert_eq!(
        seond_via.value.tags().unwrap()[&SipHeaderTagType::Host],
        b"spindle.example.com"
    );
    assert_eq!(
        seond_via.params().unwrap().get(&"branch"),
        Some(&Some("z9hG4bK9ikj8"))
    );

    let subject_hdr = &headers.get_rfc_s(SipRFCHeader::Subject).unwrap();
    assert_eq!(subject_hdr.value.vtype, SipHeaderValueType::EmptyValue);

    let new_fangled_header = &headers.get_ext_s("newfangledheader").unwrap();
    assert_eq!(
        new_fangled_header.value.vstr,
        "newfangled value\r\n continued newfangled value"
    );

    let unknown_header_with_unusual_value =
        &headers.get_ext_s("unknownHeaderwithunusualValue").unwrap();
    assert_eq!(unknown_header_with_unusual_value.value.vstr, ";;,,;;,;");

    let content_type = &headers.get_rfc_s(SipRFCHeader::ContentType).unwrap();
    assert_eq!(content_type.value.vstr, "application/sdp");

    let route_header = &headers.get_rfc_s(SipRFCHeader::Route).unwrap();
    assert_eq!(
        route_header.value.vstr,
        "<sip:services.example.com;lr;unknownwith=value;unknown-no-value>"
    );
    let route_uri = &route_header.value.sip_uri().unwrap();
    let route_uri_params = &route_uri.params().unwrap();
    assert_eq!(route_uri.scheme, sipuri::RequestUriScheme::SIP);
    assert_eq!(route_uri.hostport.host, "services.example.com");
    assert_eq!(route_uri_params.get(&"lr"), Some(&None));
    assert_eq!(route_uri_params.get(&"unknownwith"), Some(&Some("value")));
    assert_eq!(route_uri_params.get(&"unknown-no-value"), Some(&None));
    assert_eq!(route_uri_params.get(&"missing_param"), None);

    let contact = &headers.get_rfc_s(SipRFCHeader::Contact).unwrap();
    assert_eq!(
        contact.value.vstr,
        "\"Quoted string \\\"\\\"\" <sip:jdrosen@example.com>"
    );
    assert_eq!(
        contact.value.tags().unwrap()[&SipHeaderTagType::DisplayName],
        b"Quoted string \\\"\\\""
    );
    let contact_params = contact.params().unwrap();
    assert_eq!(contact_params.get(&"newparam"), Some(&Some("newvalue")));
    assert_eq!(contact_params.get(&"secondparam"), Some(&None));
    assert_eq!(contact_params.get(&"q"), Some(&Some("0.33")));

    let contact_uri = &contact.value.sip_uri().unwrap();
    assert_eq!(contact_uri.scheme, sipuri::RequestUriScheme::SIP);
    assert_eq!(contact_uri.user_info().unwrap().value, "jdrosen");
    assert_eq!(contact_uri.hostport.host, "example.com");
    assert_eq!(contact_uri.params(), None);
    /*********************************************************/
    assert_eq!(
        parsed_req.body.unwrap(),
        "v=0\
    o=mhandley 29739 7272939 IN IP4 192.0.2.3\
    s=-\
    c=IN IP4 192.0.2.4\
    t=0 0\
    m=audio 49217 RTP/AVP 0 12\
    m=video 3227 RTP/AVP 31\
    a=rtpmap:31 LPC"
            .as_bytes()
    );
}
