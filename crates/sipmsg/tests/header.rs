use sipmsg::*;

#[test]
fn parse_header() {
    match SipHeader::parse("Subject:This is a test\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Subject");
            assert_eq!(hdr.value, "This is a test");
            assert_eq!(input.len(), 0)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Name: Value;parameter=false;param2\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Name");
            assert_eq!(hdr.value, "Value");
            assert_eq!(hdr.params().unwrap().get(&"parameter"), Some(&"false"));
            assert_eq!(hdr.params().unwrap().get(&"param2"), Some(&""));
            assert_eq!(input.len(), 0);
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Max-Forwards: 70\r\n".as_bytes()) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Max-Forwards");
            assert_eq!(hdr.value, "70");
            assert_eq!(input.len(), 0);
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn parse_long_header_field() {
    match SipHeader::parse(
        "Subject: I know you're there, \r\n pick up the phone\r\n and talk to me!\r\n".as_bytes(),
    ) {
        Ok((input, hdr)) => {
            assert_eq!(hdr.name, "Subject");
            assert_eq!(
                hdr.value,
                "I know you're there, \r\n pick up the phone\r\n and talk to me!"
            );
            assert_eq!(input.len(), 0);
        }
        Err(_e) => panic!(),
    }
}
