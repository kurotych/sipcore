use sipmsg::*;

#[test]
fn parse_header() {
    match SipHeader::parse("Subject:This is a test\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Subject");
            assert_eq!(hdrs[0].value, "This is a test");
            assert_eq!(input.len(), 2)
        }
        Err(_e) => panic!(),
    }

    match SipHeader::parse("Name: Value;parameter=false;param2\r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Name");
            assert_eq!(hdrs[0].value, "Value");
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
            assert_eq!(hdrs[0].value, "70");
            assert_eq!(input.len(), 2);
        }
        Err(_e) => panic!(),
    }
}

#[test]
fn parse_header_without_value() {
    match SipHeader::parse("Accept:  \r\n".as_bytes()) {
        Ok((input, (_, hdrs))) => {
            assert_eq!(hdrs[0].name, "Accept");
            assert_eq!(hdrs[0].value, "");
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
