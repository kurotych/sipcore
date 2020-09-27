use sipmsg::*;

#[test]
fn parse_headers() {
    let parse_headers_result = SipHeaders::parse(
        "To: sip:user@example.com\r\n\
         From: caller <sip:caller2@example.com>;tag=323\r\n\
         Max-Forwards: 70\r\n\
         Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
         CSeq: 60 OPTIONS\r\n\
         e: tar\r\n\
         c: text/html; charset=ISO-8859-4\r\n\
         Content-Language: fr\r\n\
         CustomHeader: value;param=false\r\n\
         Authorization: Digest username=\"Alice\", realm=\"atlanta.com\" \r\n\
         \t,nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n \
         response=\"7587245234b3434cc3412213e5f113a5432\"\r\n\
         Content-Disposition: attachment; filename=smime.p7s; handling=required\r\n\
         l: 8\r\n\
         date: Sat, 15 Oct 2005 04:44:56 GMT\r\n\
         Expires: 5\r\n\
         Error-Info: <sip:not-in-service-recording@atlanta.com> \r\n\
         In-Reply-To: 70710@saturn.bell-tel.com, 17320@saturn.bell-tel.com\r\n\
         OrganizaTion: Boxes by Bob\r\n nextline\r\n\
         Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
            .as_bytes(),
    );

    let (input, hdrs) = parse_headers_result.unwrap();
    assert_eq!(hdrs.len(), 18);
    assert_eq!(
        hdrs.get_rfc_s(SipRFCHeader::To).unwrap().value.vstr,
        "sip:user@example.com"
    );

    let from_hdr = hdrs.get_rfc_s(SipRFCHeader::From).unwrap();
    assert_eq!(from_hdr.value.vstr, "caller <sip:caller2@example.com>");
    assert_eq!(from_hdr.params().unwrap().get(&"tag"), Some(&Some("323")));

    assert_eq!(
        from_hdr.value.tags().unwrap()[&SipHeaderTagType::DisplayName],
        b"caller"
    );
    assert_eq!(
        from_hdr.value.sip_uri().unwrap().scheme,
        sipuri::RequestUriScheme::SIP
    );
    assert_eq!(
        from_hdr.value.sip_uri().unwrap().user_info().unwrap().value,
        "caller2"
    );
    assert_eq!(
        from_hdr.value.sip_uri().unwrap().hostport.host,
        "example.com"
    );

    let max_forwards_header = hdrs.get_rfc_s(SipRFCHeader::MaxForwards).unwrap();
    assert_eq!(max_forwards_header.value.vstr, "70");
    assert_eq!(
        max_forwards_header.params(),
        None
    );
    assert_eq!(
        max_forwards_header.value.vtype,
        SipHeaderValueType::Digit
    );

    assert_eq!(
        hdrs.get_rfc_s(SipRFCHeader::CallID).unwrap().value.vstr,
        "lwsdisp.1234abcd@funky.example.com"
    );
    assert_eq!(hdrs.get_rfc_s(SipRFCHeader::CallID).unwrap().params(), None);

    let cseq_header = hdrs.get_rfc_s(SipRFCHeader::CSeq).unwrap();
    assert_eq!(cseq_header.value.vstr, "60 OPTIONS");
    assert_eq!(hdrs.get_rfc_s(SipRFCHeader::CSeq).unwrap().params(), None);
    assert_eq!(
        cseq_header.value.tags().unwrap()[&SipHeaderTagType::Number],
        b"60"
    );
    assert_eq!(
        cseq_header.value.tags().unwrap()[&SipHeaderTagType::Method],
        b"OPTIONS"
    );

    assert_eq!(hdrs.get_ext_s("customheader").unwrap().value.vstr, "value");
    assert_eq!(
        hdrs.get_ext_s("customheader")
            .unwrap()
            .params()
            .unwrap()
            .get(&"param"),
        Some(&Some("false"))
    );

    assert_eq!(
        hdrs.get_rfc_s(SipRFCHeader::Via).unwrap().value.vstr,
        "SIP/2.0/UDP funky.example.com"
    );
    assert_eq!(
        hdrs.get_rfc_s(SipRFCHeader::Via)
            .unwrap()
            .params()
            .unwrap()
            .get(&"branch"),
        Some(&Some("z9hG4bKkdjuw"))
    );
    let auth_val = &hdrs.get_rfc_s(SipRFCHeader::Authorization).unwrap().value;
    assert_eq!(
        auth_val.vstr,
        "Digest username=\"Alice\", realm=\"atlanta.com\" \r\n\
        \t,nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n \
        response=\"7587245234b3434cc3412213e5f113a5432\""
    );
    assert_eq!(
        auth_val.tags().unwrap()[&SipHeaderTagType::Username],
        b"Alice"
    );
    assert_eq!(
        auth_val.tags().unwrap()[&SipHeaderTagType::Realm],
        b"atlanta.com"
    );
    assert_eq!(
        auth_val.tags().unwrap()[&SipHeaderTagType::Nonce],
        b"84a4cc6f3082121f32b42a2187831a9e"
    );
    assert_eq!(
        auth_val.tags().unwrap()[&SipHeaderTagType::Dresponse],
        "7587245234b3434cc3412213e5f113a5432".as_bytes()
    );

    let content_disp_hdr = &hdrs.get_rfc_s(SipRFCHeader::ContentDisposition).unwrap();

    assert_eq!(content_disp_hdr.value.vstr, "attachment");
    assert_eq!(
        content_disp_hdr.params().unwrap().get("filename").unwrap(),
        &Some("smime.p7s")
    );
    assert_eq!(
        content_disp_hdr.params().unwrap().get("handling").unwrap(),
        &Some("required")
    );

    let content_language = &hdrs.get_rfc_s(SipRFCHeader::ContentLanguage).unwrap();
    assert_eq!(content_language.value.vstr, "fr");

    let content_encoding = &hdrs.get_rfc_s(SipRFCHeader::ContentEncoding).unwrap();
    assert_eq!(content_encoding.value.vstr, "tar");

    let content_length = &hdrs.get_rfc_s(SipRFCHeader::ContentLength).unwrap();
    assert_eq!(content_length.value.vstr, "8");

    let content_type = &hdrs.get_rfc_s(SipRFCHeader::ContentType).unwrap();
    assert_eq!(content_type.value.vstr, "text/html");
    assert_eq!(
        content_type.params().unwrap().get("charset").unwrap(),
        &Some("ISO-8859-4")
    );

    let date_hdr = &hdrs.get_rfc_s(SipRFCHeader::Date).unwrap();
    assert_eq!(date_hdr.value.vstr, "Sat, 15 Oct 2005 04:44:56 GMT");

    let error_info = &hdrs.get_rfc_s(SipRFCHeader::ErrorInfo).unwrap();
    assert_eq!(
        error_info.value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "sip:not-in-service-recording@atlanta.com".as_bytes()
    );
    assert_eq!(
        error_info.value.vstr,
        "<sip:not-in-service-recording@atlanta.com>"
    );

    let expires_hdr = &hdrs.get_rfc_s(SipRFCHeader::Expires).unwrap();
    assert_eq!(expires_hdr.value.vstr, "5");

    let in_reply_hdrs = &hdrs.get_rfc(SipRFCHeader::InReplyTo).unwrap();
    assert_eq!(in_reply_hdrs[0].value.vstr, "70710@saturn.bell-tel.com");
    assert_eq!(
        in_reply_hdrs[0].value.tags().unwrap()[&SipHeaderTagType::ID],
        b"70710"
    );
    assert_eq!(
        in_reply_hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Host],
        b"saturn.bell-tel.com"
    );
    assert_eq!(in_reply_hdrs[1].value.vstr, "17320@saturn.bell-tel.com");
    assert_eq!(
        in_reply_hdrs[1].value.tags().unwrap()[&SipHeaderTagType::ID],
        b"17320"
    );
    assert_eq!(
        in_reply_hdrs[1].value.tags().unwrap()[&SipHeaderTagType::Host],
        b"saturn.bell-tel.com"
    );

    let organization_header = &hdrs.get_rfc_s(SipRFCHeader::Organization).unwrap();
    assert_eq!(organization_header.value.vstr, "Boxes by Bob\r\n nextline");
    assert_eq!(input, "\r\nsomebody".as_bytes());
}
