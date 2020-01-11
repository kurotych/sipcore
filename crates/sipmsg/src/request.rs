use nom::{
    bytes::complete::{tag, take_while1},
    character::{complete, is_alphabetic},
    sequence::tuple,
};

use crate::header::*;
use alloc::vec::Vec;

use core::{str, u8};

pub struct Request<'a> {
    // The request line
    pub rl: RequestLine<'a>,
    /// The request headers.
    pub headers: Vec<Header<'a>>,
    /// Body
    pub body: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    fn new(rl: RequestLine<'a>, headers: Vec<Header<'a>>, body: Option<&'a [u8]>) -> Request<'a> {
        Request {
            rl: rl,
            headers: headers,
            body: body,
        }
    }

    pub fn parse(buf_input: &'a [u8]) -> nom::IResult<&[u8], Request> {
        let (input, rl) = RequestLine::parse(buf_input)?;

        let (input, headers) = parse_headers(input)?;
        // TODO check header Content-Length
        let (body, _) = tag("\r\n")(input)?;

        Ok((buf_input, Request::new(rl, headers, Some(body))))
    }
}

/// SIP-Version
/// ex. `SIP/2.0 -> SipVersion(2, 0)`
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct SipVersion(pub u8, pub u8);

/// Ex: INVITE sip:user@example.com SIP/2.0
/// The Request line and u8 buffer shoud have the same life time
pub struct RequestLine<'a> {
    pub method: Method,
    pub uri: &'a str,
    pub sip_version: SipVersion,
}

impl<'a> RequestLine<'a> {
    pub fn parse(rl: &[u8]) -> nom::IResult<&[u8], RequestLine> {
        let method = take_while1(is_alphabetic);
        let uri = take_while1(|c| c != b' ' as u8);
        let (input, (method, _, uri, _, _, major_version, _, minor_version, _)) = tuple((
            method,
            complete::space1,
            uri,
            complete::space1,
            tag("SIP/"),
            complete::digit1,
            complete::char('.'),
            complete::digit1,
            complete::crlf,
        ))(rl)?;

        let sip_version = SipVersion(
            u8::from_str_radix(str::from_utf8(major_version).unwrap(), 10).unwrap(),
            u8::from_str_radix(str::from_utf8(minor_version).unwrap(), 10).unwrap(),
        );

        match RequestLine::parse_method(method) {
            Some(m) => Ok((
                input,
                RequestLine {
                    method: m,
                    uri: str::from_utf8(uri).unwrap(),
                    sip_version: sip_version,
                },
            )),
            None => Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                rl,
                nom::error::ErrorKind::IsA,
            ))),
        }
    }

    fn parse_method(method: &[u8]) -> Option<Method> {
        match str::from_utf8(method) {
            Ok(s) => Method::from_str(s),
            Err(_) => None,
        }
    }
}

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
    use crate::request;
    use crate::request::Method;
    use crate::request::Request;
    use crate::request::RequestLine;
    use crate::request::SipVersion;

    fn parse_rl_test(
        rl: &str,
        expected_method: Method,
        expected_uri: &str,
        expected_sip_version: SipVersion,
    ) {
        match RequestLine::parse(rl.as_bytes()) {
            Ok((_b, rl)) => {
                assert_eq!(rl.method, expected_method);
                assert_eq!(rl.sip_version, expected_sip_version);
                assert_eq!(rl.uri, expected_uri);
            }
            Err(_e) => panic!(),
        }
    }

    fn check_header_value(
        result_header: &request::Header,
        exp_h_name: &str,
        exp_h_value: &str,
        exp_h_parameters: Option<&str>,
    ) {
        assert_eq!(result_header.name, exp_h_name);
        assert_eq!(result_header.value, exp_h_value);
        assert_eq!(result_header.parameters, exp_h_parameters);
    }

    #[test]
    fn parse_request() {
        let invite_msg_buf = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                              Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
                              To: Bob <sip:bob@biloxi.com>\r\n\
                              From: Alice <sip:alice@atlanta.com>;tag=88sja8x\r\n\
                              Max-Forwards: 70\r\n\
                              Call-ID: 987asjd97y7atg\r\n\
                              CSeq: 986759 INVITE\r\n\r\nbody_stuff"
            .as_bytes();

        match Request::parse(invite_msg_buf) {
            Ok((_, parsed_req)) => {
                assert_eq!(parsed_req.rl.method, Method::INVITE);
                assert_eq!(parsed_req.rl.sip_version, SipVersion(2, 0));
                assert_eq!(parsed_req.rl.uri, "sip:bob@biloxi.com");

                assert_eq!(parsed_req.headers.len(), 6);

                check_header_value(
                    &parsed_req.headers[0],
                    "Via",
                    "SIP/2.0/UDP pc33.atlanta.com",
                    Some("branch=z9hG4bKkjshdyff"),
                );
                check_header_value(
                    &parsed_req.headers[1],
                    "To",
                    "Bob <sip:bob@biloxi.com>",
                    None,
                );
                check_header_value(
                    &parsed_req.headers[2],
                    "From",
                    "Alice <sip:alice@atlanta.com>",
                    Some("tag=88sja8x"),
                );
                check_header_value(&parsed_req.headers[3], "Max-Forwards", "70", None);
                check_header_value(&parsed_req.headers[4], "Call-ID", "987asjd97y7atg", None);
                check_header_value(&parsed_req.headers[5], "CSeq", "986759 INVITE", None);

                assert_eq!(parsed_req.body.unwrap(), "body_stuff".as_bytes())
            }
            Err(_) => panic!(),
        }
    }

    #[test]
    fn get_method_type() {
        parse_rl_test(
            "OPTIONS sip:user@example.com SIP/2.0\r\n",
            Method::OPTIONS,
            "sip:user@example.com",
            SipVersion(2, 0),
        );
        parse_rl_test(
            "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n",
            Method::INVITE,
            "sip:vivekg@chair-dnrc.example.com;unknownparam",
            SipVersion(2, 0),
        );
        parse_rl_test(
            "REGISTER sip:[2001:db8::10] SIP/3.1\r\n",
            Method::REGISTER,
            "sip:[2001:db8::10]",
            SipVersion(3, 1),
        );
    }

    #[test]
    fn get_method_type_fail() {
        match RequestLine::parse("OPTI2ONS sip:user@example.com SIP/2.0\r\n".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_e) => (),
        }
    }
}
