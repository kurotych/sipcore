use sipmsg;

mod common;
use common::*;

#[test]
fn status_code_from_bytes_str() {
    assert_eq!(
        sipmsg::StatusCode::from_bytes_str("100".as_bytes()),
        sipmsg::StatusCode::Trying
    );

    assert_eq!(
        sipmsg::StatusCode::from_bytes_str("181".as_bytes()),
        sipmsg::StatusCode::CallIsBeingForwarded
    );
}

#[test]
fn status_code_from_str() {
    assert_eq!(
        sipmsg::StatusCode::from_str("500"),
        sipmsg::StatusCode::ServerInternalError
    );
}

#[test]
fn status_line() {
    match sipmsg::StatusLine::parse(b"SIP/2.0 401 Unauthorized\r\n") {
        Ok((left, status_line)) => {
            assert_eq!(left.len(), 0);
            assert_eq!(status_line.sip_version, sipmsg::SipVersion(2, 0));
            assert_eq!(status_line.status_code, sipmsg::StatusCode::Unauthorized);
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
    match sipmsg::Response::parse(response_msg.as_bytes()) {
        Ok((_, response)) => {
            assert_eq!(response.headers.len(), 9);

            check_header_value(
                &response.headers[0],
                "Via",
                "SIP/2.0/UDP 192.168.178.69:60686",
            );
            assert_eq!(
                response.headers[0].params().unwrap().get(&"branch"),
                Some(&"z9hG4bKPj7IVefnk0j6Wn9oUM78ubmcURGDehvKEc")
            );

            assert_eq!(
                response.headers[0].params().unwrap().get(&"received"),
                Some(&"192.168.178.69")
            );

            assert_eq!(
                response.headers[0].params().unwrap().get(&"rport"),
                Some(&"60686")
            );

            check_header_value(&response.headers[1], "From", "<sip:12@192.168.178.26>");
            assert_eq!(
                response.headers[1].params().unwrap().get(&"tag"),
                Some(&"XOO-LeGIwZmwa2UROKMXEhZGA5mKcY0b")
            );

            check_header_value(&response.headers[2], "To", "<sip:12@192.168.178.26>");
            assert_eq!(
                response.headers[2].params().unwrap().get(&"tag"),
                Some(&"as68275e50")
            );

            check_header_value(
                &response.headers[3],
                "Call-ID",
                "p8gpcmxSdWwcM5xV89nm2LkEbcTPUdT1",
            );

            check_header_value(&response.headers[4], "CSeq", "62833 REGISTER");

            check_header_value(&response.headers[5], "Server", "FPBX-2.11.0(11.6.0)");

            check_header_value(
                &response.headers[6],
                "Allow",
                "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH",
            );

            check_header_value(&response.headers[7], "Supported", "replaces, timer");

            check_header_value(&response.headers[8], "Content-Length", "0");
        }
        Err(_e) => panic!(),
    }
}
