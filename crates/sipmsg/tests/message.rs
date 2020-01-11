use sipmsg::{MessageType, get_message_type};
#[test]
fn get_message_type_test() {
    assert_eq!(get_message_type("SIP".as_bytes()), MessageType::Response);
    assert_eq!(
        get_message_type(
            "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0".as_bytes()
        ),
        MessageType::Request
    );
    assert_eq!(
        get_message_type("OPTIONS sip:user@example.com SIP/2.0".as_bytes()),
        MessageType::Request
    );
    assert_eq!(
        get_message_type("MESSAGE sip:kumiko@example.org SIP/2.0".as_bytes()),
        MessageType::Request
    );
    assert_eq!(
        get_message_type("NEWMETHOD sip:user@example.com SIP/2.0".as_bytes()),
        MessageType::Unknown
    );
}
