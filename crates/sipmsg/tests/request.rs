use sipmsg::{
    request::{Method, RequestLine},
    SipVersion,
};

fn parse_rl_test(
    rl: &str,
    expected_method: Method,
    expected_uri: &str,
    expected_sip_version: SipVersion,
) {
    match RequestLine::parse(rl.as_bytes()) {
        Ok((_b, rl)) => {
            assert_eq!(rl.method, expected_method);
            assert_eq!(rl.sip_version, expected_sip_version);
            assert_eq!(rl.uri, expected_uri);
        }
        Err(_e) => panic!(),
    }
}

fn check_header_value(
    result_header: &sipmsg::Header,
    exp_h_name: &str,
    exp_h_value: &str,
    exp_h_parameters: Option<&str>,
) {
    assert_eq!(result_header.name, exp_h_name);
    assert_eq!(result_header.value, exp_h_value);
    assert_eq!(result_header.parameters, exp_h_parameters);
}

#[test]
fn parse_request() {
    let invite_msg_buf = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                          Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
                          To: Bob <sip:bob@biloxi.com>\r\n\
                          From: Alice <sip:alice@atlanta.com>;tag=88sja8x\r\n\
                          Max-Forwards: 70\r\n\
                          Call-ID: 987asjd97y7atg\r\n\
                          CSeq: 986759 INVITE\r\n\r\nbody_stuff"
        .as_bytes();

    match sipmsg::Request::parse(invite_msg_buf) {
        Ok((_, parsed_req)) => {
            assert_eq!(parsed_req.rl.method, Method::INVITE);
            assert_eq!(parsed_req.rl.sip_version, SipVersion(2, 0));
            assert_eq!(parsed_req.rl.uri, "sip:bob@biloxi.com");

            assert_eq!(parsed_req.headers.len(), 6);

            check_header_value(
                &parsed_req.headers[0],
                "Via",
                "SIP/2.0/UDP pc33.atlanta.com",
                Some("branch=z9hG4bKkjshdyff"),
            );
            check_header_value(
                &parsed_req.headers[1],
                "To",
                "Bob <sip:bob@biloxi.com>",
                None,
            );
            check_header_value(
                &parsed_req.headers[2],
                "From",
                "Alice <sip:alice@atlanta.com>",
                Some("tag=88sja8x"),
            );
            check_header_value(&parsed_req.headers[3], "Max-Forwards", "70", None);
            check_header_value(&parsed_req.headers[4], "Call-ID", "987asjd97y7atg", None);
            check_header_value(&parsed_req.headers[5], "CSeq", "986759 INVITE", None);

            assert_eq!(parsed_req.body.unwrap(), "body_stuff".as_bytes())
        }
        Err(_) => panic!(),
    }
}

#[test]
fn get_method_type() {
    parse_rl_test(
        "OPTIONS sip:user@example.com SIP/2.0\r\n",
        Method::OPTIONS,
        "sip:user@example.com",
        SipVersion(2, 0),
    );
    parse_rl_test(
        "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n",
        Method::INVITE,
        "sip:vivekg@chair-dnrc.example.com;unknownparam",
        SipVersion(2, 0),
    );
    parse_rl_test(
        "REGISTER sip:[2001:db8::10] SIP/3.1\r\n",
        Method::REGISTER,
        "sip:[2001:db8::10]",
        SipVersion(3, 1),
    );
}

#[test]
fn get_method_type_fail() {
    match RequestLine::parse("OPTI2ONS sip:user@example.com SIP/2.0\r\n".as_bytes()) {
        Ok((_, _)) => panic!(),
        Err(_e) => (),
    }
}
