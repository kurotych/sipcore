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

use nom::{bytes::complete::take_while1, character::complete, sequence::tuple};
use crate::common::{errorparse::SipParseError, nom_wrappers::take_while_trim_spaces};

macro_rules! take_func {
    ($inp: expr, $chr:expr) => {
        take_while_trim_spaces($inp, |c: u8| c == $chr)
    };
}

pub fn star(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'*')
}
pub fn slash(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'/')
}
pub fn equal(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'=')
}
pub fn lparen(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'(')
}
pub fn rparen(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b')')
}
pub fn raquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'>')
}
pub fn laquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b'<')
}
pub fn comma(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b',')
}
pub fn semi(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b';')
}
pub fn colon(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_func!(input, b':')
}
pub fn ldquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_while_trim_spaces_left(input, |x: u8| x == b'"')
}
pub fn rdquot(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
    take_while_trim_spaces_right(input, |x: u8| x == b'"')
}

pub fn take_while_trim_spaces_left(
    input: &[u8],
    cond_fun: fn(c: u8) -> bool,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let (input, (_, result)) = tuple((complete::space0, take_while1(cond_fun)))(input)?;
    Ok((input, result))
}

pub fn take_while_trim_spaces_right(
    input: &[u8],
    cond_fun: fn(c: u8) -> bool,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let (input, (result, _)) = tuple((take_while1(cond_fun), complete::space0))(input)?;
    Ok((input, result))
}

// #[derive(Debug, PartialEq)]
// pub enum SwsTokenType {
//     STAR,
//     SLASH,
//     EQUAL,
//     LPAREN,
//     RPAREN,
//     RAQUOT,
//     LAQUOT,
//     COMMA,
//     SEMI,
//     COLON,
//     LDQUOT,
//     RDQUOT,
// }

// impl SwsTokenType {
//     pub fn as_char(&self) -> char {
//         match self {
//             &SwsTokenType::STAR => '*',
//             &SwsTokenType::SLASH => '/',
//             &SwsTokenType::EQUAL => '=',
//             &SwsTokenType::LPAREN => '(',
//             &SwsTokenType::RPAREN => ')',
//             &SwsTokenType::RAQUOT => '>',
//             &SwsTokenType::LAQUOT => '<',
//             &SwsTokenType::COMMA => ',',
//             &SwsTokenType::SEMI => ';',
//             &SwsTokenType::COLON => ':',
//             &SwsTokenType::LDQUOT => '"',
//             &SwsTokenType::RDQUOT => '"',
//         }
//     }
// }
