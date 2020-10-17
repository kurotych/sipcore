use crate::common::bnfcore::is_wsp;
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
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let mut taken_bytes = 0;
        loop {
            let (inp, res_val) = take_until("\r\n")(&source_input[taken_bytes..])?;
            taken_bytes += res_val.len();
            if inp.len() > 3 && is_wsp(inp[2]) {
                taken_bytes += 3;
                continue;
            }
            break;
        }

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..taken_bytes],
            HeaderValueType::TokenValue,
            None,
            None,
        )?;
        Ok((&source_input[taken_bytes..], hdr_val))
    }
}
