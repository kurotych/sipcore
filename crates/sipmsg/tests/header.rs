use sipmsg;

#[test]
fn parse_header() {
    match sipmsg::Header::parse("Subject:This is a test\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Subject");
            assert_eq!(hdr.value, "This is a test");
            assert_eq!(input.len(), 0)
        }
        Err(_e) => panic!(),
    }

    match sipmsg::Header::parse("Name: Value;parameter=false\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Name");
            assert_eq!(hdr.value, "Value");
            assert_eq!(hdr.parameters.unwrap(), "parameter=false");
            assert_eq!(input.len(), 0);
        }
        Err(_e) => panic!(),
    }

    match sipmsg::Header::parse("Max-Forwards: 70\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Max-Forwards");
            assert_eq!(hdr.value, "70");
            assert_eq!(input.len(), 0);
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn parse_header_long_folded() {
    assert_eq!(
        sipmsg::Header::parse("Max-Forwards: 70\r\n continue header\r\n".as_bytes()),
        Err(nom::Err::Error((
            " continue header\r\n".as_bytes(),
            nom::error::ErrorKind::Space
        )))
    );
}

#[test]
fn parse_headers() {
    let parse_headers_result = sipmsg::parse_headers(
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
            assert_eq!(hdrs[0].name, "To");
            assert_eq!(hdrs[0].value, "sip:user@example.com");

            assert_eq!(hdrs[1].name, "From");
            assert_eq!(hdrs[1].value, "caller<sip:caller@example.com>");
            assert_eq!(hdrs[1].parameters.unwrap(), "tag=323");

            assert_eq!(hdrs[2].name, "Max-Forwards");
            assert_eq!(hdrs[2].value, "70");
            assert_eq!(hdrs[2].parameters, None);

            assert_eq!(hdrs[3].name, "Call-ID");
            assert_eq!(hdrs[3].value, "lwsdisp.1234abcd@funky.example.com");
            assert_eq!(hdrs[3].parameters, None);

            assert_eq!(hdrs[4].name, "CSeq");
            assert_eq!(hdrs[4].value, "60 OPTIONS");
            assert_eq!(hdrs[4].parameters, None);

            assert_eq!(hdrs[5].name, "Via");
            assert_eq!(hdrs[5].value, "SIP/2.0/UDP funky.example.com");
            assert_eq!(hdrs[5].parameters.unwrap(), "branch=z9hG4bKkdjuw");
            assert_eq!(input, "\r\nsomebody".as_bytes()); //
        }
        Err(_e) => panic!(),
    }
}
