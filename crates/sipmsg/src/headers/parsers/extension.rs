use crate::{
    common::errorparse::SipParseError,
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_until;

pub struct ExtensionParser;

impl SipHeaderParser for ExtensionParser {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (inp, res_val) = take_until("\r\n")(input)?;
        let (_, hdr_val) = HeaderValue::new(res_val, HeaderValueType::TokenValue, None, None)?;
        Ok((inp, hdr_val))
    }
}
