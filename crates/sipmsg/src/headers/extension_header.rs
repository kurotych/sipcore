use crate::common::{
    bnfcore::{is_token_char, is_wsp},
    errorparse::SipParseError,
};
use crate::headers::traits::SipHeaderParser;
use nom::bytes::complete::take_while1;

pub struct ExtensionHeader;

// UTF8-CONT       =  %x80-BF

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

impl SipHeaderParser for ExtensionHeader {
    // TODO
    // extension-header  =  header-name HCOLON header-value
    // header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        take_while1(is_token_char_or_wsp)(input)
    }
}
