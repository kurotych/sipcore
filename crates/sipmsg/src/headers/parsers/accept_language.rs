use crate::{
    common::{bnfcore::is_alpha, errorparse::SipParseError},
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::{bytes::complete::take_while1, character::complete::space0};

/// Accept-Language  =  "Accept-Language" HCOLON
//                      [ language *(COMMA language) ]
// language         =  language-range *(SEMI accept-param)
// language-range   =  ( ( 1*8ALPHA *( "-" 1*8ALPHA ) ) / "*" )
pub struct AcceptLanguageParser;

impl SipHeaderParser for AcceptLanguageParser {
    fn take_value(initial_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        if !initial_input.is_empty() && initial_input[0] == b'*' {
            let (input, _) = space0(initial_input)?;
            let (_, hdr_val) = HeaderValue::new(&input[..1], HeaderValueType::SimpleString, None)?;
            return Ok((&input[1..], hdr_val));
        }
        let (input, left_part) = take_while1(is_alpha)(initial_input)?;
        if !input.is_empty() && input[0] != b'-' {
            let (_, hdr_val) = HeaderValue::new(left_part, HeaderValueType::SimpleString, None)?;
            return Ok((input, hdr_val));
        }
        if left_part.len() < 1 || left_part.len() > 8 {
            return sip_parse_error!(1, "Invalid length of left part of AcceptLanguage Header");
        }

        let (input, _) = nom::character::complete::char('-')(input)?; // skip -
        let (input, right_part) = take_while1(is_alpha)(input)?;

        if right_part.len() < 1 || right_part.len() > 8 {
            return sip_parse_error!(2, "Invalid length of right part of AcceptLanguage Header");
        }
        let offset = left_part.len() + right_part.len() + 1 /*`-`*/;
        let (_, hdr_val) = HeaderValue::new(
            &initial_input[..offset],
            HeaderValueType::SimpleString,
            None,
        )?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // Accept-Language: da, en-gb;q=0.8, en;q=0.7
    #[test]
    fn accept_language_value() {
        match AcceptLanguageParser::take_value("en-gb;q=0.8\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, ";q=0.8\r\n".as_bytes());
                assert_eq!(val.vstr, "en-gb");
            }
            Err(_) => {
                panic!();
            }
        }
        match AcceptLanguageParser::take_value("da\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val.vstr, "da");
            }
            Err(_) => {
                panic!();
            }
        }

        match AcceptLanguageParser::take_value("*\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val.vstr, "*");
            }
            Err(_) => {
                panic!();
            }
        }
    }
}
