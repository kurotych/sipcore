/// When tokens are used or separators are used between elements,
/// whitespace is often allowed before or after these characters:

///    STAR    =  SWS "*" SWS ; asterisk
///    SLASH   =  SWS "/" SWS ; slash
///    EQUAL   =  SWS "=" SWS ; equal
///    LPAREN  =  SWS "(" SWS ; left parenthesis
///    RPAREN  =  SWS ")" SWS ; right parenthesis
///    RAQUOT  =  ">" SWS ; right angle quote
///    LAQUOT  =  SWS "<"; left angle quote
///    COMMA   =  SWS "," SWS ; comma
///    SEMI    =  SWS ";" SWS ; semicolon
///    COLON   =  SWS ":" SWS ; colon
///    LDQUOT  =  SWS DQUOTE; open double quotation mark
///    RDQUOT  =  DQUOTE SWS ; close double quotation mark
use crate::common::{
    errorparse::SipParseError,
    nom_wrappers::{take_sws, take_while_trim_sws},
};
use nom::{bytes::complete::tag, sequence::tuple};

macro_rules! take_func {
    ($inp: expr, $chr:expr) => {
        take_while_trim_sws($inp, |c: u8| c == $chr)
    };
}

pub fn star(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'*')
}
pub fn slash(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'/')
}
pub fn equal(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'=')
}
pub fn lparen(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'(')
}
pub fn rparen(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b')')
}
pub fn raquot(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'>')
}
pub fn laquot(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b'<')
}
pub fn comma(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b',')
}
pub fn semi(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b';')
}
pub fn colon(input: &[u8]) -> nom::IResult<&[u8], (&[u8], &[u8], &[u8]), SipParseError> {
    take_func!(input, b':')
}
pub fn ldquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let (input, (result, _)) = tuple((take_sws, tag("\"")))(input)?;
    Ok((input, result))
}
pub fn rdquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let (input, (_, result)) = tuple((tag("\""), take_sws))(input)?;
    Ok((input, result))
}
