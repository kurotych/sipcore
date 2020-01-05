use nom:: {
    branch::alt,
    bytes::complete::{take, take_until, take_while1},
    character::{complete, is_alphabetic},
    sequence::tuple
};

use alloc::vec::Vec;
use core::str;

const CRLF: &[u8] = &[0x0d, 0x0a]; // /r/n

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

/// Struct to keep and manipulate with headers
pub struct Headers<'a> {
    pub headers: Vec<Header<'a>>,
}

impl<'a> Header<'a> {
    /// Parses parameters part of header, should start from: ";"
    fn parse_parameters(input: &[u8]) -> nom::IResult<&[u8], &str> {
        let (input, _) = nom::character::complete::char(';')(input)?;

        unsafe {
            let (input, params) = take_until("\r\n")(input)?;
            let param_str = str::from_utf8_unchecked(params);
            Ok((input, param_str))
        }
    }

    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Header> {
        let name = take_while1(is_alphabetic);

        let (input, (name, _, _, _)) = tuple((
            name,
            complete::space0,
            complete::char(':'),
            complete::space0,
        ))(input)?;

        // parse value
        let (input, header_value) = alt((take_until(";"), take_until("\r\n")))(input)?;

        let mut parameters: Option<&str> = None;
        if input != CRLF {
            // there are parameters
            match Header::parse_parameters(input) {
                Ok((_, params)) => parameters = Some(params),
                Err(e) => return Err(e),
            }
        } else {
            // skip /r/n
            take(2usize)(input)?;
        }
        Ok((
            input,
            Header {
                name: unsafe { str::from_utf8_unchecked(name) },
                value: unsafe { str::from_utf8_unchecked(header_value) },
                parameters: parameters,
            },
        ))
    }
}

mod tests {
    

    #[test]
    pub fn parse_header() {
        match crate::Header::parse("Subject:This is a test\r\n".as_bytes()) {
            Ok((_b, hdr)) => {
                assert_eq!(hdr.name, "Subject");
                assert_eq!(hdr.value, "This is a test");
            }
            Err(_e) => panic!(),
        }

        match crate::Header::parse("Name: Value;parameter=false\r\n".as_bytes()) {
            Ok((_b, hdr)) => {
                assert_eq!(hdr.name, "Name");
                assert_eq!(hdr.value, "Value");
                assert_eq!(hdr.parameters.unwrap(), "parameter=false");
            }
            Err(_e) => panic!(),
        }
    }
}
