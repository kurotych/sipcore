use nom::character::complete::space0;
use crate::common::bnfcore::is_wsp;
use crate::{
    common::{errorparse::SipParseError, take_sws_token},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};

use nom::bytes::complete::take_while1;

/// Alert-Info   =  "Alert-Info" HCOLON alert-param *(COMMA alert-param)
// alert-param  =  LAQUOT absoluteURI RAQUOT *( SEMI generic-param )
pub struct AlertInfoParser;

impl SipHeaderParser for AlertInfoParser {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        // let uri = take_while1(|c| !is_wsp(c) && c != b'>');
        let (input, _) = take_sws_token::laquot(source_input)?;
        let laquout_len = source_input.len() - input.len();
        let (input, uri) = take_while1(|c| !is_wsp(c) && c != b'>')(input)?;
        let (input, spaces_before_raquot) = space0(input)?;


        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::PureValue, uri);

        let (input, _) = take_sws_token::raquot(input)?;
        // 1 for '>' char
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..uri.len() + laquout_len + 1 + spaces_before_raquot.len()],
            HeaderValueType::SimpleString,
            Some(tags),
            None,
        )?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_parse_test() {
        let (input, val) = AlertInfoParser::take_value(
            "< http://www.example.com/sounds/moo.wav  >   \r\n".as_bytes(),
        )
        .unwrap();

        assert_eq!(input, "\r\n".as_bytes());
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::PureValue],
            "http://www.example.com/sounds/moo.wav".as_bytes()
        );
        assert_eq!(val.vstr, "< http://www.example.com/sounds/moo.wav  >");

        match AlertInfoParser::take_value("random word\r\n".as_bytes()) {
            Ok((_, _)) => {
                panic!();
            }
            Err(_) => {}
        }
    }
}
