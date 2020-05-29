use crate::common::errorparse::SipParseError;
use crate::headers::GenericParams;
use nom;

pub trait SipMessageHeaderParser<'a> {
    // It should returns COMMA in first parameter if it header with multiple value
    fn parse_value(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<GenericParams<'a>>), SipParseError>;
}
