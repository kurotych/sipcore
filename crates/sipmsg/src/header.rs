use nom::{
    bytes::complete::{is_not, take, take_until, take_while1},
    character::complete,
    sequence::tuple,
};

use alloc::vec::Vec;
use core::str;

const CRLF: &[u8] = &[0x0d, 0x0a]; // /r/n

#[derive(PartialEq, Debug)]
/// https://tools.ietf.org/html/rfc3261#section-7.3
pub struct Header<'a> {
    /// Sip header name
    pub name: &'a str,
    /// Sip header value
    pub value: &'a str,

    // TODO make better representation type
    /// Sip parameters
    pub parameters: Option<&'a str>,
}

pub fn parse_headers(input: &[u8]) -> nom::IResult<&[u8], Vec<Header>> {
    let mut headers = Vec::with_capacity(15); // 15 just random number
    let mut inp2 = input;
    loop {
        match Header::parse(inp2) {
            Ok((inp, header)) => {
                headers.push(header);
                inp2 = inp;
            }
            Err(e) => return Err(e),
        }
        if inp2.len() > 1 && &inp2[0..2] == CRLF {
            // end of headers and start of body part
            break;
        }
    }
    Ok((inp2, headers))
}

// https://tools.ietf.org/html/rfc2822#section-2.2
// A field name MUST be composed of printable US-ASCII characters (i.e.,
// characters that have values between 33 and 126, inclusive), except colon.
pub fn is_alphabetic_or_hyphen(chr: u8) -> bool {
    // 58 == ':' (colon)
    chr != 58 && chr >= 33 && chr <= 126
}

impl<'a> Header<'a> {
    // This function O(n + h * 2) make it O(n + h)
    // where h - header_field, n - header name
    // first full iteration is 'tuple' second in 'is_not'
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Header> {
        let (input, (name, _, _, _, header_field, _)) = tuple((
            take_while1(is_alphabetic_or_hyphen),
            complete::space0,
            complete::char(':'),
            complete::space0,
            take_until("\r\n"),
            take(2usize), // skip /r/n
        ))(input)?;

        if input.len() > 0 && (input[0] == 32 || input[0] == 9) {
            // is WSP?
            // TODO mark
            // Long header fields not supported yet.
            // https://tools.ietf.org/html/rfc2822#section-2.2.3
            return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                input,
                nom::error::ErrorKind::Space,
            )));
        }

        match is_not(";")(header_field) {
            Ok((params, header_value)) => {
                let mut parameters: Option<&str> = None;
                if params.len() != 0 {
                    let (params, _) = take(1usize)(params)?; // skip ;
                    unsafe {
                        parameters = Some(str::from_utf8_unchecked(params));
                    }
                }
                return Ok((
                    input,
                    Header {
                        name: unsafe { str::from_utf8_unchecked(name) },
                        value: unsafe { str::from_utf8_unchecked(header_value) },
                        parameters: parameters,
                    },
                ));
            }
            Err(e) => return Err(e),
        }
    }
}