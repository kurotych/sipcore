use crate::common::{bnfcore::is_token_char, errorparse::SipParseError};
use crate::headers::traits::SipHeaderParser;
use nom::{bytes::complete::take_while1, character::complete::space0};

// Accept-Encoding  =  "Accept-Encoding" HCOLON
//                      [ encoding *(COMMA encoding) ]
// encoding         =  codings *(SEMI accept-param)
// codings          =  content-coding / "*"
// content-coding   =  token

pub struct AcceptEncodingHeader;

impl AcceptEncodingHeader {}

impl SipHeaderParser for AcceptEncodingHeader {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        if !input.is_empty() && input[0] == b'*' {
            let (input, _) = space0(input)?;
            return Ok((&input[1..], &input[..1]));
        }
        let (input, value) = take_while1(is_token_char)(input)?;
        Ok((input, value))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accept_encoding_value() {
        match AcceptEncodingHeader::take_value("*\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "*".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
        match AcceptEncodingHeader::take_value("gzip\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "gzip".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
    }
}
