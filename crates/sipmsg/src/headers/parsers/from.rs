use crate::{
    common::errorparse::SipParseError,
    headers::{
        header::{HeaderValue, HeaderValueType},
        name_addr,
        traits::SipHeaderParser,
    },
};

pub struct From;

impl SipHeaderParser for From {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, (vstr_val, tags, sipuri)) = name_addr::take(source_input)?;
        let (_, hdr_val) =
            HeaderValue::new(vstr_val, HeaderValueType::NameAddr, Some(tags), sipuri)?;
        Ok((input, hdr_val))
    }
}
