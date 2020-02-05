use crate::errorparse::SipParseError;
use nom;

pub trait NomParser<'a> {
    type ParseResult;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError>;
}
