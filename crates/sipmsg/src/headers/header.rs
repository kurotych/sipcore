use crate::bnfcore::*;
use crate::errorparse::SipParseError;
use crate::parameters::Parameters;
use crate::traits::{NomParser, SipMessageHeaderParser};

use alloc::collections::btree_map::BTreeMap;
use core::str;
use nom::{
    bytes::complete::{is_not, take, take_while1},
    character::complete,
    sequence::tuple,
};
use unicase::Ascii;

pub type HeaderPerameters<'a> = BTreeMap<&'a str, &'a str>;

#[derive(PartialEq, Debug)]
/// [rfc3261 section-7.3](https://tools.ietf.org/html/rfc3261#section-7.3)
pub struct Header<'a> {
    /// Sip header name
    pub name: Ascii<&'a str>,
    /// Sip header value
    pub value: &'a str,

    /// Sip parameters
    parameters: Option<HeaderPerameters<'a>>,
}

impl<'a> Header<'a> {
    pub fn new(
        name: &'a str,
        value: &'a str,
        parameters: Option<HeaderPerameters<'a>>,
    ) -> Header<'a> {
        Header {
            name: { Ascii::new(name) },
            value: value,
            parameters: parameters,
        }
    }

    pub fn params(&self) -> Option<&HeaderPerameters<'a>> {
        self.parameters.as_ref()
    }

    fn take_header_field(input: &'a [u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        let mut idx = 0;
        while idx < input.len() - 1 {
            if is_crlf(&input[idx..]) {
                if idx + 2 == input.len() || input[idx + 2] != b' ' {
                    return Ok((&input[idx + 2..], &input[..idx]));
                }
            }
            idx += 1;
        }
        return sip_parse_error!(1, "Header field parse error");
    }

    pub fn take_header_name(input: &'a [u8]) -> nom::IResult<&[u8], &'a str, SipParseError> {
        let (input_rest, (header_name, _, _, _)) = tuple((
            take_while1(is_token_char),
            complete::space0,
            complete::char(':'),
            complete::space0,
        ))(input)?;
        match str::from_utf8(header_name) {
            Ok(hdr_str) => Ok((input_rest, hdr_str)),
            Err(_) => sip_parse_error!(1, "Bad header name"),
        }
    }
}

impl<'a> NomParser<'a> for Header<'a> {
    type ParseResult = Header<'a>;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, header_name) = Header::take_header_name(input)?;
        let (input, (value, parameters)) = Header::parse_value(input)?;
        Ok((input, Header::new(header_name, value, parameters)))
    }
}

impl<'a> SipMessageHeaderParser<'a> for Header<'a> {
    fn parse_value(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str, Option<BTreeMap<&'a str, &'a str>>), SipParseError> {
        let (input, header_field) = Header::take_header_field(input)?;

        match is_not(";")(header_field) {
            Ok((params, header_value)) => {
                let mut result_parameters: Option<BTreeMap<&str, &str>> = None;
                if params.len() != 0 {
                    let (params, _) = take(1usize)(params)?; // skip first ;
                    match Parameters::parse(params) {
                        Ok((_, parameters)) => {
                            result_parameters = core::prelude::v1::Some(parameters);
                        }
                        Err(e) => return Err(e),
                    }
                }
                // safely convert header value to utf8 string
                let utf8_header_value: &str;
                match str::from_utf8(header_value) {
                    Ok(utf8_val) => utf8_header_value = utf8_val,
                    Err(_) => {
                        return sip_parse_error!(2);
                    }
                }

                return Ok((input, (utf8_header_value, result_parameters)));
            }
            Err(e) => return Err(e),
        }
    }
}
