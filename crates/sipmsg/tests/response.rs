use sipmsg::*;

#[test]
fn status_code_from_bytes_str() {
    assert_eq!(
        SipResponseStatusCode::from_bytes_str("100".as_bytes()),
        SipResponseStatusCode::Trying
    );

    assert_eq!(
        SipResponseStatusCode::from_bytes_str("181".as_bytes()),
        SipResponseStatusCode::CallIsBeingForwarded
    );
}

#[test]
fn status_code_from_str() {
    assert_eq!(
        SipResponseStatusCode::from_str("500"),
        SipResponseStatusCode::ServerInternalError
    );
}

#[test]
fn status_line() {
    match SipResponseStatusLine::parse(b"SIP/2.0 401 Unauthorized\r\n") {
        Ok((left, status_line)) => {
            assert_eq!(left.len(), 0);
            assert_eq!(status_line.sip_version, sipmsg::SipVersion(2, 0));
            assert_eq!(status_line.status_code, SipResponseStatusCode::Unauthorized);
            assert_eq!(status_line.reason_phrase, "Unauthorized");
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn parse_response() {
    let response_msg = "SIP/2.0 401 Unauthorized\r\n\
    Via: SIP/2.0/UDP 192.168.178.69:60686;branch=z9hG4bKPj7IVefnk0j6Wn9oUM78ubmcURGDehvKEc;received=192.168.178.69;rport=60686\r\n\
    From: <sip:12@192.168.178.26>;tag=XOO-LeGIwZmwa2UROKMXEhZGA5mKcY0b\r\n\
    To: <sip:12@192.168.178.26>;tag=as68275e50\r\n\
    Call-ID: p8gpcmxSdWwcM5xV89nm2LkEbcTPUdT1\r\n\
    CSeq: 62833 REGISTER\r\n\
    Server: FPBX-2.11.0(11.6.0)\r\n\
    Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n\
    Supported: replaces, timer\r\n\
    Content-Length: 0\r\n\r\n";
    match SipResponse::parse(response_msg.as_bytes()) {
        Ok((_, response)) => {
            assert_eq!(response.sl.sip_version, SipVersion(2, 0));
            assert_eq!(response.sl.status_code, SipResponseStatusCode::Unauthorized);
            assert_eq!(response.sl.reason_phrase, "Unauthorized");
            assert_eq!(response.headers.len(), 9);

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .value
                    .vstr,
                "SIP/2.0/UDP 192.168.178.69:60686"
            );
            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"branch"),
                Some(&Some("z9hG4bKPj7IVefnk0j6Wn9oUM78ubmcURGDehvKEc"))
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"received"),
                Some(&Some("192.168.178.69"))
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Via)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"rport"),
                Some(&Some("60686"))
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .value
                    .vstr,
                "<sip:12@192.168.178.26>"
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::From)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"tag"),
                Some(&Some("XOO-LeGIwZmwa2UROKMXEhZGA5mKcY0b"))
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::To)
                    .unwrap()
                    .value
                    .vstr,
                "<sip:12@192.168.178.26>"
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::To)
                    .unwrap()
                    .params()
                    .unwrap()
                    .get(&"tag"),
                Some(&Some("as68275e50"))
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::CallID)
                    .unwrap()
                    .value
                    .vstr,
                "p8gpcmxSdWwcM5xV89nm2LkEbcTPUdT1"
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::CSeq)
                    .unwrap()
                    .value
                    .vstr,
                "62833 REGISTER"
            );

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Server)
                    .unwrap()
                    .value
                    .vstr,
                "FPBX-2.11.0(11.6.0)"
            );
            let allow_headers = response.headers.get_rfc(SipRFCHeader::Allow).unwrap();
            assert_eq!(allow_headers.len(), 10);
            assert_eq!(allow_headers[0].name, "Allow");
            assert_eq!(allow_headers[0].value.vstr, "INVITE");
            assert_eq!(allow_headers[1].value.vstr, "ACK");
            assert_eq!(allow_headers[2].value.vstr, "CANCEL");
            assert_eq!(allow_headers[3].value.vstr, "OPTIONS");
            assert_eq!(allow_headers[4].value.vstr, "BYE");
            assert_eq!(allow_headers[5].value.vstr, "REFER");
            assert_eq!(allow_headers[6].value.vstr, "SUBSCRIBE");
            assert_eq!(allow_headers[7].value.vstr, "NOTIFY");
            assert_eq!(allow_headers[8].value.vstr, "INFO");
            assert_eq!(allow_headers[9].value.vstr, "PUBLISH");

            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::Supported)
                    .unwrap()
                    .value
                    .vstr,
                "replaces, timer"
            );
            assert_eq!(
                response
                    .headers
                    .get_rfc_s(SipRFCHeader::ContentLength)
                    .unwrap()
                    .value
                    .vstr,
                "0"
            );
        }
        Err(_e) => panic!(),
    }
}
