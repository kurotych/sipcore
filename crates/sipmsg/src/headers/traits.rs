use crate::common::errorparse::SipParseError;
use alloc::collections::BTreeMap;
use nom;

pub type HeaderParameters<'a> = BTreeMap<&'a str, &'a str>;

pub trait SipMessageHeaderParser<'a> {
    // It should returns COMMA in first parameter if it header with multiple value
    fn parse_value(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<HeaderParameters>), SipParseError>;
}
