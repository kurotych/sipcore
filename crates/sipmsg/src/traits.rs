use alloc::collections::BTreeMap;
use crate::errorparse::SipParseError;
use nom;

pub trait NomParser<'a> {
    type ParseResult;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError>;
}

pub trait SipMessageHeaderParser<'a> {
    fn value_params_parse(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<BTreeMap<&'a str, &'a str>>), SipParseError>;
}
