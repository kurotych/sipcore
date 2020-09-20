use crate::{
    common::{
        bnfcore::{is_token_char, is_wsp},
        errorparse::SipParseError,
    },
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_while1;

pub struct ExtensionParser;

// THIS MUST BE REMOVED. It just for testing.
fn is_token_char_or_wsp(c: u8) -> bool {
    is_token_char(c)
        || is_wsp(c)
        || c == b':'
        || c == b'@'
        || c == b'<'
        || c == b'>'
        || c == b'-'
        || c == b'/'
        || c == b'('
        || c == b')'
        || c == b','
        || c == b'['
        || c == b']'
}

impl SipHeaderParser for ExtensionParser {
    // TODO
    // extension-header  =  header-name HCOLON header-value
    // header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (inp, res_val) = take_while1(is_token_char_or_wsp)(input)?;
        let (_, hdr_val) = HeaderValue::new(res_val, HeaderValueType::SimpleString, None, None)?;
        Ok((inp, hdr_val))
    }
}
