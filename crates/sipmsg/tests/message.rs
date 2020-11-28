use sipmsg::*;

#[test]
fn parse_message() {
    let invite_msg_buf = "INVITE sip:001234567890@10.135.0.1:5060;user=phone SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt\r\n\
Max-Forwards: 70\r\n\
From: \"Calling User\" <sip:151@10.135.0.1:5060>;tag=m3l2hbp\r\n\
To: <sip:001234567890@10.135.0.1:5060;user=phone>\r\n\
Call-ID: ud04chatv9q@10.135.0.1\r\n\
CSeq: 10691 INVITE\r\n\
Contact: <sip:151@10.135.0.12;line=12071>;+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\"\r\n\
User-Agent: Wildix W-AIR 03.55.00.24 9c7514340722\r\n\
Allow: INVITE, CANCEL, BYE, ACK, REGISTER, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK, UPDATE\r\n\
Content-Disposition: session\r\n\
Supported: replaces,100rel\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n".as_bytes();
    let (_, sip_msg) = SipMessage::parse(invite_msg_buf).unwrap();
    let sip_req = sip_msg.request().unwrap();
    assert_eq!(sip_req.rl.uri.user_info().unwrap().value, "001234567890");
}

#[test]
fn get_message_type() {
    assert_eq!(
        sipmsg::get_sip_message_type("SIP".as_bytes()),
        SipMessageType::Response
    );
    assert_eq!(
        sipmsg::get_sip_message_type(
            "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0".as_bytes()
        ),
        SipMessageType::Request
    );
    assert_eq!(
        sipmsg::get_sip_message_type("OPTIONS sip:user@example.com SIP/2.0".as_bytes()),
        SipMessageType::Request
    );
    assert_eq!(
        sipmsg::get_sip_message_type("MESSAGE sip:kumiko@example.org SIP/2.0".as_bytes()),
        SipMessageType::Request
    );
    assert_eq!(
        sipmsg::get_sip_message_type("NEWMETHOD sip:user@example.com SIP/2.0".as_bytes()),
        SipMessageType::Unknown
    );
}
