use crate::common::errorparse::SipParseError;
use crate::headers::SipHeaderParameters;
use nom;

pub trait NomParser<'a> {
    type ParseResult;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError>;
}

pub trait SipMessageHeaderParser<'a> {
    // It should returns COMMA in first parameter if it header with multiple value
    fn parse_value(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<SipHeaderParameters>), SipParseError>;
}
