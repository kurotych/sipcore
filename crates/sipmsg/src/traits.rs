use crate::errorparse::SipParseError;
use alloc::collections::BTreeMap;
use nom;

pub trait NomParser<'a> {
    type ParseResult;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError>;
}

pub trait SipMessageHeaderParser<'a> {
    // It should returns COMMA in first parameter if it header with multiple value
    fn parse_value(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<BTreeMap<&'a str, &'a str>>), SipParseError>;
}
