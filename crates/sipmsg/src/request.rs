use nom::bytes::streaming::take_while_m_n;
use nom::character::is_alphabetic;

use core::str;

pub struct Request {}

impl Request {
    pub fn new() -> Request {
        Request {}
    }
}

// INVITE sip:user@example.com SIP/2.0
pub struct RequestLine {
    pub method: Method,
}

const MAX_METHOD_LENGTH: usize = 10;

impl RequestLine {
    pub fn parse(rl: &[u8]) -> nom::IResult<&[u8], RequestLine> {
        match parse_method(rl) {
            Ok((_i, m)) => Ok((rl, RequestLine { method: m })),
            Err(e) => Err(e),
        }
    }
}

fn parse_method(rl: &[u8]) -> nom::IResult<&[u8], Method> {
    let (rl, method) = take_while_m_n(3, MAX_METHOD_LENGTH, is_alphabetic)(rl)?;

    match str::from_utf8(method) {
        Ok(s) => match Method::from_str(s) {
            Some(s) => Ok((rl, s)),
            None => Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                rl,
                nom::error::ErrorKind::TakeWhileMN,
            ))),
        },
        Err(_e) => Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
            rl,
            nom::error::ErrorKind::TakeWhileMN,
        ))),
    }
}

/// SIP-Version
/// ex. `SIP/2.0 -> SipVersion(2, 0)`
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct SipVersion(pub u8, pub u8);

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Method {
    ACK,
    BYE,
    CANCEL,
    INFO,
    INVITE,
    MESSAGE,
    NOTIFY,
    OPTIONS,
    PRACK,
    PUBLISH,
    REFER,
    REGISTER,
    SUBSCRIBE,
    UPDATE,
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            &Method::ACK => "ACK",
            &Method::BYE => "BYE",
            &Method::CANCEL => "CANCEL",
            &Method::INFO => "INFO",
            &Method::INVITE => "INVITE",
            &Method::MESSAGE => "MESSAGE",
            &Method::NOTIFY => "NOTIFY",
            &Method::OPTIONS => "OPTIONS",
            &Method::PRACK => "PRACK",
            &Method::PUBLISH => "PUBLISH",
            &Method::REFER => "REFER",
            &Method::REGISTER => "REGISTER",
            &Method::SUBSCRIBE => "SUBSCRIBE",
            &Method::UPDATE => "UPDATE",
        }
    }

    pub fn from_str(s: &str) -> Option<Method> {
        match s {
            "ACK" => Some(Method::ACK),
            "BYE" => Some(Method::BYE),
            "CANCEL" => Some(Method::CANCEL),
            "INFO" => Some(Method::INFO),
            "INVITE" => Some(Method::INVITE),
            "MESSAGE" => Some(Method::MESSAGE),
            "NOTIFY" => Some(Method::NOTIFY),
            "OPTIONS" => Some(Method::OPTIONS),
            "PRACK" => Some(Method::PRACK),
            "PUBLISH" => Some(Method::PUBLISH),
            "REFER" => Some(Method::REFER),
            "REGISTER" => Some(Method::REGISTER),
            "SUBSCRIBE" => Some(Method::SUBSCRIBE),
            "UPDATE" => Some(Method::UPDATE),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::request::Method;
    use crate::request::RequestLine;

    fn parse_rl_test(rl: &str, expected: Method) {
        match RequestLine::parse(rl.as_bytes()) {
            Ok((_b, rl)) => {
                assert_eq!(rl.method, expected);
            }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn get_method_type() {
        parse_rl_test("OPTIONS sip:user@example.com SIP/2.0", Method::OPTIONS);
        parse_rl_test(
            "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0",
            Method::INVITE,
        );
    }

    #[test]
    fn get_method_type_fail() {
        match RequestLine::parse("OPTI2ONS sip:user@example.com SIP/2.0".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_e) => (),
        }
    }
}
