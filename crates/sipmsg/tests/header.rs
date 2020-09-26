use sipmsg::*;

#[test]
fn parse_header() {
    let (input, (_, hdrs)) = SipHeader::parse("Subject:This is a test\r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Subject");
    assert_eq!(hdrs[0].value.vstr, "This is a test");
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) =
        SipHeader::parse("Name: Value;parameter=false;param2\r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Name");
    assert_eq!(hdrs[0].value.vstr, "Value");
    assert_eq!(
        hdrs[0].params().unwrap().get("parameter"),
        Some(&Some("false"))
    );
    assert_eq!(
        hdrs[0].params().unwrap().get(&"param2"),
        Some(&None)
    );
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) = SipHeader::parse("Max-Forwards: 70\r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Max-Forwards");
    assert_eq!(hdrs[0].value.vstr, "70");
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) = SipHeader::parse(
        "Authentication-Info: nextnonce=\"47364c23432d2e131a5fb210812c\"\r\n".as_bytes(),
    )
    .unwrap();
    assert_eq!(input, "\r\n".as_bytes());
    assert_eq!(
        hdrs[0].value.vstr,
        "nextnonce=\"47364c23432d2e131a5fb210812c\""
    );
}

#[test]
fn parse_header_without_value() {
    let (input, (_, hdrs)) = SipHeader::parse("Accept:  \r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept");
    assert_eq!(hdrs[0].value.vstr, "");
    assert_eq!(input.len(), 2)
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
    let (input, (_, hdrs)) =
        SipHeader::parse("Accept-Encoding:  compress, gzip \r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "compress");
    assert_eq!(hdrs[1].name, "Accept-Encoding");
    assert_eq!(hdrs[1].value.vstr, "gzip");
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) = SipHeader::parse("Accept-Encoding:  \r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "");
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) = SipHeader::parse("Accept-Encoding: *  \r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "*");
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) =
        SipHeader::parse("Accept-Encoding:compress;q=0.5, gzip;q=1.0\r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "compress");
    assert_eq!(
        hdrs[0].params().unwrap().get("q").unwrap(),
        &Some("0.5")
    );
    assert_eq!(hdrs[1].name, "Accept-Encoding");
    assert_eq!(hdrs[1].value.vstr, "gzip");
    assert_eq!(
        hdrs[1].params().unwrap().get("q").unwrap(),
        &Some("1.0")
    );
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) =
        SipHeader::parse("Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0\r\n".as_bytes())
            .unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "gzip");
    assert_eq!(
        hdrs[0].params().unwrap().get("q").unwrap(),
        &Some("1.0")
    );
    assert_eq!(hdrs[1].name, "Accept-Encoding");
    assert_eq!(hdrs[1].value.vstr, "identity");
    assert_eq!(
        hdrs[1].params().unwrap().get("q").unwrap(),
        &Some("0.5")
    );

    assert_eq!(hdrs[2].name, "Accept-Encoding");
    assert_eq!(hdrs[2].value.vstr, "*");
    assert_eq!(
        hdrs[2].params().unwrap().get("q").unwrap(),
        &Some("0")
    );
    assert_eq!(input.len(), 2);

    let (input, (_, hdrs)) = SipHeader::parse("Accept-Encoding: gzip \r\n".as_bytes()).unwrap();
    assert_eq!(hdrs[0].name, "Accept-Encoding");
    assert_eq!(hdrs[0].value.vstr, "gzip");
    assert_eq!(input.len(), 2)
}

#[test]
fn allow_header() {
    let (input, (_, hdrs)) = SipHeader::parse(
        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n"
            .as_bytes(),
    )
    .unwrap();

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

#[test]
fn alert_info_header() {
    let (input, (_, hdrs)) =
        SipHeader::parse("Alert-Info: <http://www.example.com/sounds/moo.wav> \r\n".as_bytes())
            .unwrap();

    assert_eq!(hdrs[0].name, "Alert-Info");
    assert_eq!(
        hdrs[0].value.vstr,
        "<http://www.example.com/sounds/moo.wav>"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "http://www.example.com/sounds/moo.wav".as_bytes()
    );
    assert_eq!(input, "\r\n".as_bytes());
}

#[test]
fn accept_language_header() {
    let (input, (_, hdrs)) =
        SipHeader::parse("Accept-Language: da, en-gb;q=0.8, en;q=0.7 \r\n".as_bytes()).unwrap();

    assert_eq!(hdrs[0].name, "Accept-Language");
    assert_eq!(hdrs[0].value.vstr, "da");
    assert_eq!(hdrs[1].value.vstr, "en-gb");
    assert_eq!(
        hdrs[1].params().unwrap().get("q").unwrap(),
        &Some("0.8")
    );

    assert_eq!(hdrs[2].value.vstr, "en");
    assert_eq!(
        hdrs[2].params().unwrap().get("q").unwrap(),
        &Some("0.7")
    );

    assert_eq!(input.len(), 2)
}

#[test]
fn authorization_header() {
    let res = SipHeader::parse("Authorization: Digest username=\"bob\", realm=\"atlanta.example.com\"\
    ,nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", opaque=\"\" ,uri=\"sips:ss2.biloxi.example.com\"\r\n".as_bytes());
    let (input, (_, hdrs)) = res.unwrap();
    assert_eq!(
        hdrs[0].value.vstr,
        "Digest username=\"bob\", realm=\"atlanta.example.com\"\
    ,nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", opaque=\"\" ,uri=\"sips:ss2.biloxi.example.com\""
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Username],
        b"bob"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Realm],
        b"atlanta.example.com"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Nonce],
        b"ea9c8e88df84f1cec4341ae6cbe5a359"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Opaque],
        b""
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::DigestUri],
        b"sips:ss2.biloxi.example.com"
    );

    assert_eq!(input, b"\r\n");
}

#[test]
fn call_id_header() {
    let res = SipHeader::parse("i: 3848276298220188511@atlanta.example.com\r\n".as_bytes());
    let (input, (_, hdrs)) = res.unwrap();
    assert_eq!(
        hdrs[0].value.vstr,
        "3848276298220188511@atlanta.example.com"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::ID],
        b"3848276298220188511"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::Host],
        b"atlanta.example.com"
    );
    assert_eq!(input, b"\r\n");

    let res = SipHeader::parse("call-id: 3848276298220188511\r\n".as_bytes());
    let (input, (_, hdrs)) = res.unwrap();
    assert_eq!(hdrs[0].value.vstr, "3848276298220188511");
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::ID],
        b"3848276298220188511"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap().get(&SipHeaderTagType::Host),
        None
    );
    assert_eq!(input, b"\r\n");
}

#[test]
fn callinfo_test() {
    let res = SipHeader::parse(
        "Call-Info: <http://wwww.example.com/alice/photo.jpg> ;purpose=icon,\r\n \
    <http://www.example.com/alice/> ;purpose=info\r\n"
            .as_bytes(),
    );
    let (input, (_, hdrs)) = res.unwrap();
    assert_eq!(
        hdrs[0].value.vstr,
        "<http://wwww.example.com/alice/photo.jpg>"
    );
    assert_eq!(
        hdrs[0].value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "http://wwww.example.com/alice/photo.jpg".as_bytes()
    );

    assert_eq!(
        hdrs[0].params().unwrap().get("purpose"),
        Some(&Some("icon"))
    );

    assert_eq!(hdrs[1].value.vstr, "<http://www.example.com/alice/>");
    assert_eq!(
        hdrs[1].value.tags().unwrap()[&SipHeaderTagType::AbsoluteURI],
        "http://www.example.com/alice/".as_bytes()
    );

    assert_eq!(
        hdrs[1].params().unwrap().get("purpose"),
        Some(&Some("info"))
    );

    assert_eq!(input, b"\r\n");
}

#[test]
fn content_disposition_header() {
    let (input, (_, hdrs)) = SipHeader::parse(
        "Content-Disposition: attachment; filename=smime.p7s; handling=required\r\n".as_bytes(),
    )
    .unwrap();

    assert_eq!(hdrs[0].name, "Content-Disposition");
    assert_eq!(hdrs[0].value.vstr, "attachment");
    assert_eq!(
        hdrs[0].params().unwrap().get("filename").unwrap(),
        &Some("smime.p7s")
    );
    assert_eq!(
        hdrs[0].params().unwrap().get("handling").unwrap(),
        &Some("required")
    );
    assert_eq!(input.len(), 2)
}

#[test]
fn content_type_header() {
    let (input, (_, hdrs)) = SipHeader::parse(
        "Content-Type: application/sdp\r\n".as_bytes(),
    )
    .unwrap();

    assert_eq!(hdrs[0].name, "Content-Type");
    assert_eq!(hdrs[0].value.vstr, "application/sdp");
    assert_eq!(input.len(), 2)
}
