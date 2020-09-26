use crate::{
    common::{bnfcore::is_digit, errorparse::SipParseError},
    headers::header::{HeaderValue, HeaderValueType},
};
use nom::bytes::complete::take_while1;

pub fn take(input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
    let (inp, res_val) = take_while1(is_digit)(input)?;
    let (_, hdr_val) = HeaderValue::new(res_val, HeaderValueType::Digit, None, None)?;
    Ok((inp, hdr_val))
}
