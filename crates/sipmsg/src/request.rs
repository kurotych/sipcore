use crate::common::{errorparse::SipParseError, traits::NomParser};
use nom::{
    bytes::complete::{tag, take_while1},
    character::{complete, is_alphabetic},
    sequence::tuple,
};

use crate::headers::*;
use crate::message::*;

use core::{str, u8};

/// [rfc3261 section-7.1](https://tools.ietf.org/html/rfc3261#section-7.1)
pub struct Request<'a> {
    /// The request line. Example: `OPTIONS sip:user@example.com SIP/2.0`
    pub rl: RequestLine<'a>,
    /// The request headers.
    pub headers: SipHeaders<'a>,
    /// The body of message
    pub body: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    fn new(rl: RequestLine<'a>, headers: SipHeaders<'a>, body: Option<&'a [u8]>) -> Request<'a> {
        Request {
            rl: rl,
            headers: headers,
            body: body,
        }
    }
}

impl<'a> NomParser<'a> for Request<'a> {
    type ParseResult = Request<'a>;

    fn parse(buf_input: &'a [u8]) -> nom::IResult<&[u8], Request, SipParseError> {
        let (input, rl) = RequestLine::parse(buf_input)?;

        let (input, headers) = SipHeaders::parse(input)?;
        // TODO check header Content-Length and fix buf_input return
        let (body, _) = tag("\r\n")(input)?;
        Ok((buf_input, Request::new(rl, headers, Some(body))))
    }
}

/// Ex: `INVITE sip:user@example.com SIP/2.0`
/// The Request line and u8 buffer shoud have the same life time
pub struct RequestLine<'a> {
    pub method: Method,
    pub uri: SipUri<'a>,
    pub sip_version: SipVersion,
}

impl<'a> NomParser<'a> for RequestLine<'a> {
    type ParseResult = RequestLine<'a>;

    fn parse(rl: &[u8]) -> nom::IResult<&[u8], RequestLine, SipParseError> {
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

        let (_, sip_uri) = SipUri::parse(uri)?;

        let sip_version = SipVersion(
            u8::from_str_radix(str::from_utf8(major_version).unwrap(), 10).unwrap(),
            u8::from_str_radix(str::from_utf8(minor_version).unwrap(), 10).unwrap(),
        );

        match RequestLine::parse_method(method) {
            Some(m) => Ok((
                input,
                RequestLine {
                    method: m,
                    uri: sip_uri,
                    sip_version: sip_version,
                },
            )),
            None => return sip_parse_error!(1, "Error cast from_utf8"),
        }
    }
}

impl<'a> RequestLine<'a> {
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
