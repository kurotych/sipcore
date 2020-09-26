use crate::{
    common::{bnfcore::is_token_char, errorparse::SipParseError, nom_wrappers::take_sws},
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::{bytes::complete::take_while1};

/// Accept-Encoding  =  "Accept-Encoding" HCOLON
//                      [ encoding *(COMMA encoding) ]
// encoding         =  codings *(SEMI accept-param)
// codings          =  content-coding / "*"
// content-coding   =  token
pub struct AcceptEncodingParser;

impl SipHeaderParser for AcceptEncodingParser {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        if !input.is_empty() && input[0] == b'*' {
            let (input, _) = take_sws(input)?;
            let (_, hdr_val) =
                HeaderValue::new(&input[..1], HeaderValueType::TokenValue, None, None)?;
            return Ok((&input[1..], hdr_val));
        }
        let (input, value) = take_while1(is_token_char)(input)?;
        let (_, hdr_val) = HeaderValue::new(value, HeaderValueType::TokenValue, None, None)?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accept_encoding_value() {
        let (input, val) = AcceptEncodingParser::take_value("*\r\n".as_bytes()).unwrap();
        assert_eq!(input, "\r\n".as_bytes());
        assert_eq!(val.vstr, "*");

        let (input, val) = AcceptEncodingParser::take_value("gzip \r\n".as_bytes()).unwrap();
        assert_eq!(input, " \r\n".as_bytes());
        assert_eq!(val.vstr, "gzip");
    }
}
