use crate::common::errorparse::SipParseError;

pub trait NomParser<'a> {
    type ParseResult;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError>;
}
