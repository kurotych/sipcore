use sipmsg::*;
use std::time::Instant;

//#[test]
fn parse_invite() {
    let raw_message = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
To: Bob <bob@biloxi.com>\r\n\
From: Alice <alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Max-Forwards: 70\r\n\
Date: Thu, 21 Feb 2002 13:02:03 GMT\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n"
        .as_bytes();
    let size_of_message = raw_message.len();
    let mut counter = 0;
    let now = Instant::now();
    loop {
        let (_, parsed_req) = SipRequest::parse(raw_message).unwrap();
        assert_eq!(
            parsed_req
                .headers
                .get_rfc_s(SipRFCHeader::Via)
                .unwrap()
                .value
                .vstr,
            "SIP/2.0/UDP pc33.atlanta.com"
        );
        assert_eq!(
            parsed_req
                .headers
                .get_rfc_s(SipRFCHeader::Via)
                .unwrap()
                .params()
                .unwrap()
                .get(&"branch"),
            Some(&Some("z9hG4bKnashds8"))
        );
        counter += 1;
        if now.elapsed().as_secs() == 1 {
            break;
        }
    }
    // uncomment #[test]
    // cargo test --release -- --nocapture parse_invite
    // tested by Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz
    // 63 mbytes per second, count sip messages: 184942
    println!(
        "{} mbytes per second, count sip messages: {}",
        (size_of_message * counter) / 1024 / 1024,
        counter
    );
}
