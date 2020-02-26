use crate::bnfcore::*;
use crate::errorparse::SipParseError;
use crate::parameters::Parameters;
use crate::traits::NomParser;

use nom::{
    bytes::complete::{is_not, take, take_until, take_while1},
    character::complete,
    sequence::tuple,
};

use alloc::collections::btree_map::BTreeMap;
use core::str;

use unicase::Ascii;

#[derive(PartialEq, Debug)]
/// [rfc3261 section-7.3](https://tools.ietf.org/html/rfc3261#section-7.3)
pub struct Header<'a> {
    /// Sip header name
    pub name: Ascii<&'a str>,
    /// Sip header value
    pub value: &'a str,

    // TODO make better representation type
    /// Sip parameters
    parameters: Option<BTreeMap<&'a str, &'a str>>,
}

impl<'a> Header<'a> {
    pub fn params(&self) -> Option<&BTreeMap<&'a str, &'a str>> {
        self.parameters.as_ref()
    }
}

impl<'a> NomParser<'a> for Header<'a> {
    type ParseResult = Header<'a>;

    // This function O(n + h * 2) make it O(n + h)
    // where h - header_field, n - header name
    // first full iteration is 'tuple' second in 'is_not'
    /// According to bnf representation from RFC:
    /// extension-header  =  header-name HCOLON header-value
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, (name, _, _, _, header_field, _)) = tuple((
            take_while1(is_token_char),
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
            return sip_parse_error!(1, "Long header fields not supported yet");
        }

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

                return Ok((
                    input,
                    Header {
                        name: unsafe { Ascii::new(str::from_utf8_unchecked(name)) },
                        value: utf8_header_value,
                        parameters: result_parameters,
                    },
                ));
            }
            Err(e) => return Err(e),
        }
    }
}
