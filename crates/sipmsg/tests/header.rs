use sipmsg::*;

#[test]
fn parse_header() {
    match SipHeader::parse("Subject:This is a test\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Subject");
            assert_eq!(hdrs[0].value.vstr, "This is a test");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Name: Value;parameter=false;param2\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Name");
            assert_eq!(hdrs[0].value.vstr, "Value");
            assert_eq!(
                hdrs[0].params().unwrap().get("parameter"),
                Some((&SipAscii::new("parameter"), &Some("false")))
            );
            assert_eq!(
                hdrs[0].params().unwrap().get(&"param2"),
                Some((&SipAscii::new("param2"), &None))
            );
            assert_eq!(input.len(), 2);
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Max-Forwards: 70\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Max-Forwards");
            assert_eq!(hdrs[0].value.vstr, "70");
            assert_eq!(input.len(), 2);
        }
        Err(_e) => panic!(),
    }

    let res = SipHeader::parse(
        "Authentication-Info: nextnonce=\"47364c23432d2e131a5fb210812c\"\r\n".as_bytes(),
    );
    let (input, (_, hdrs)) = res.unwrap();
    assert_eq!(input, "\r\n".as_bytes());
    assert_eq!(hdrs[0].value.vstr, "nextnonce=\"47364c23432d2e131a5fb210812c\"");
}

#[test]
fn parse_header_without_value() {
    match SipHeader::parse("Accept:  \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept");
            assert_eq!(hdrs[0].value.vstr, "");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn accept_encoding_header() {
    /*
        For testing:
        Accept-Encoding: compress, gzip
        Accept-Encoding:
        Accept-Encoding: *
        Accept-Encoding: compress;q=0.5, gzip;q=1.0
        Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0
        Accept-Encoding: gzip
        Accept-Encoding: gzip, compress, br
        Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1
    */
    match SipHeader::parse("Accept-Encoding:  compress, gzip \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "compress");
            assert_eq!(hdrs[1].name, "Accept-Encoding");
            assert_eq!(hdrs[1].value.vstr, "gzip");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Accept-Encoding:  \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Accept-Encoding: *  \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "*");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Accept-Encoding:compress;q=0.5, gzip;q=1.0\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "compress");
            assert_eq!(
                hdrs[0].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("0.5"))
            );
            assert_eq!(hdrs[1].name, "Accept-Encoding");
            assert_eq!(hdrs[1].value.vstr, "gzip");
            assert_eq!(
                hdrs[1].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("1.0"))
            );
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "gzip");
            assert_eq!(
                hdrs[0].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("1.0"))
            );
            assert_eq!(hdrs[1].name, "Accept-Encoding");
            assert_eq!(hdrs[1].value.vstr, "identity");
            assert_eq!(
                hdrs[1].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("0.5"))
            );

            assert_eq!(hdrs[2].name, "Accept-Encoding");
            assert_eq!(hdrs[2].value.vstr, "*");
            assert_eq!(
                hdrs[2].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("0"))
            );

            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }
    match SipHeader::parse("Accept-Encoding: gzip \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Encoding");
            assert_eq!(hdrs[0].value.vstr, "gzip");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn allow_header() {
    match SipHeader::parse(
        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n"
            .as_bytes(),
    ) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Allow");
            assert_eq!(hdrs[0].value.vstr, "INVITE");
            assert_eq!(hdrs[1].value.vstr, "ACK");
            assert_eq!(hdrs[2].value.vstr, "CANCEL");
            assert_eq!(hdrs[3].value.vstr, "OPTIONS");
            assert_eq!(hdrs[4].value.vstr, "BYE");
            assert_eq!(hdrs[5].value.vstr, "REFER");
            assert_eq!(hdrs[6].value.vstr, "SUBSCRIBE");
            assert_eq!(hdrs[7].value.vstr, "NOTIFY");
            assert_eq!(hdrs[8].value.vstr, "INFO");
            assert_eq!(hdrs[9].value.vstr, "PUBLISH");
            assert_eq!(input, "\r\n".as_bytes());
        }
        Err(_) => panic!(),
    }
}

#[test]
fn alert_info_header() {
    match SipHeader::parse("Alert-Info: <http://www.example.com/sounds/moo.wav> \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Alert-Info");
            assert_eq!(hdrs[0].value.vstr, "http://www.example.com/sounds/moo.wav");
            assert_eq!(input, "\r\n".as_bytes());
        }
        Err(_) => panic!(),
    }
}

#[test]
fn accept_language_header() {
    match SipHeader::parse("Accept-Language: da, en-gb;q=0.8, en;q=0.7 \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept-Language");
            assert_eq!(hdrs[0].value.vstr, "da");
            assert_eq!(hdrs[1].value.vstr, "en-gb");
            assert_eq!(
                hdrs[1].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("0.8"))
            );

            assert_eq!(hdrs[2].value.vstr, "en");
            assert_eq!(
                hdrs[2].params().unwrap().get("q").unwrap(),
                (&SipAscii::new("q"), &Some("0.7"))
            );

            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }
}

// TODO Not supported yet
// #[test]
// fn parse_long_header_field() {
//     let res = SipHeader::parse(
//         "Subject: I know you're there, \r\n pick up the phone\r\n and talk to me!\r\n".as_bytes(),
//     );

//     match res {
//         Ok((input, hdr)) => {
//             assert_eq!(hdr.name, "Subject");
//             assert_eq!(
//                 hdr.value,
//                 "I know you're there, \r\n pick up the phone\r\n and talk to me!"
//             );
//             assert_eq!(input.len(), 2);
//         }
//         Err(_e) => panic!(),
//     }
// }
