use crate::common::{bnfcore::is_alpha, errorparse::SipParseError};
use crate::headers::traits::SipHeaderParser;
use nom::{bytes::complete::take_while1, character::complete::space0};

// Accept-Language  =  "Accept-Language" HCOLON
//                      [ language *(COMMA language) ]
// language         =  language-range *(SEMI accept-param)
// language-range   =  ( ( 1*8ALPHA *( "-" 1*8ALPHA ) ) / "*" )
pub struct AcceptLanguageHeader;

impl AcceptLanguageHeader {}

impl SipHeaderParser for AcceptLanguageHeader {
    fn take_value(initial_input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        if !initial_input.is_empty() && initial_input[0] == b'*' {
            let (input, _) = space0(initial_input)?;
            return Ok((&input[1..], &input[..1]));
        }
        let (input, left_part) = take_while1(is_alpha)(initial_input)?;
        if !input.is_empty() && input[0] != b'-' {
            return Ok((input, left_part));
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
        Ok((input, &initial_input[..offset]))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // Accept-Language: da, en-gb;q=0.8, en;q=0.7
    #[test]
    fn accept_language_value() {
        match AcceptLanguageHeader::take_value("en-gb;q=0.8\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, ";q=0.8\r\n".as_bytes());
                assert_eq!(val, "en-gb".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
        match AcceptLanguageHeader::take_value("da\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "da".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }

        match AcceptLanguageHeader::take_value("*\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "*".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
    }
}
