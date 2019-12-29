#[derive(Debug, PartialEq)]
pub enum MessageType {
    Request,
    Response,
    Unknown,
}

const SIP: &'static [u8] = &['S' as u8, 'I' as u8, 'P' as u8]; // SIP
// First 3 letters of Request Method
const ACK: &'static [u8] = &['A' as u8, 'C' as u8, 'K' as u8]; // ACK
const BYE: &'static [u8] = &['B' as u8, 'Y' as u8, 'E' as u8]; // BYE
const REG: &'static [u8] = &['R' as u8, 'E' as u8, 'G' as u8]; // REGISTER
const CAN: &'static [u8] = &['C' as u8, 'A' as u8, 'N' as u8]; // CANCEL
const INF: &'static [u8] = &['I' as u8, 'N' as u8, 'F' as u8]; // INFO
const INV: &'static [u8] = &['I' as u8, 'N' as u8, 'V' as u8]; // INVITE
const MES: &'static [u8] = &['M' as u8, 'E' as u8, 'S' as u8]; // MESSAGE
const NOT: &'static [u8] = &['N' as u8, 'O' as u8, 'T' as u8]; // NOTIFY
const OPT: &'static [u8] = &['O' as u8, 'P' as u8, 'T' as u8]; // OPTIONS
const PRA: &'static [u8] = &['P' as u8, 'R' as u8, 'A' as u8]; // PRACK
const PUB: &'static [u8] = &['P' as u8, 'U' as u8, 'B' as u8]; // PUBLISH
const REF: &'static [u8] = &['R' as u8, 'E' as u8, 'F' as u8]; // REFER
const SUB: &'static [u8] = &['S' as u8, 'U' as u8, 'B' as u8]; // SUBSCRIBE
const UPD: &'static [u8] = &['U' as u8, 'P' as u8, 'D' as u8]; // UPDATE

/// Fast determinates message type and minimal validate for further transmission to suitable parser.
/// Does not validate full first line, just first 3 bytes.
pub fn get_message_type(mt: &[u8]) -> MessageType {
    if mt.len() < 3 {
        MessageType::Unknown
    } else {
        match &mt[0..3] {
            SIP => MessageType::Response,
            ACK => MessageType::Request,
            BYE => MessageType::Request,
            REG => MessageType::Request,
            CAN => MessageType::Request,
            INF => MessageType::Request,
            INV => MessageType::Request,
            MES => MessageType::Request,
            NOT => MessageType::Request,
            OPT => MessageType::Request,
            PRA => MessageType::Request,
            PUB => MessageType::Request,
            REF => MessageType::Request,
            SUB => MessageType::Request,
            UPD => MessageType::Request,
            _ => MessageType::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::message::get_message_type;
    use crate::message::MessageType;
    #[test]
    fn get_message_type_test() {
        assert_eq!(get_message_type("SIP".as_bytes()), MessageType::Response);
        assert_eq!(get_message_type("INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0".as_bytes()), MessageType::Request);
        assert_eq!(get_message_type("OPTIONS sip:user@example.com SIP/2.0".as_bytes()), MessageType::Request);
        assert_eq!(get_message_type("MESSAGE sip:kumiko@example.org SIP/2.0".as_bytes()), MessageType::Request);
        assert_eq!(get_message_type("NEWMETHOD sip:user@example.com SIP/2.0".as_bytes()), MessageType::Unknown);
    }
}
