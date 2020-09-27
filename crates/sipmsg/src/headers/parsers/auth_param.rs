use crate::{
    common::{bnfcore::is_token_char, errorparse::SipParseError, nom_wrappers, take_sws_token},
};
use nom::bytes::complete::take_while1;

pub fn take(
    input: &[u8],
) -> nom::IResult<
    &[u8],
    (
        &[u8], /* param name */
        &[u8], /* param_value without qoutes */
    ),
    SipParseError,
> {
    let (input, param_name) = take_while1(is_token_char)(input)?;
    let (input, _) = take_sws_token::equal(input)?;
    if input[0] == b'"' {
        let (input, (_, param_value, _)) = nom_wrappers::take_qutoed_string(input)?;
        return Ok((input, (param_name, param_value)));
    } else {
        let (input, param_value) = take_while1(is_token_char)(input)?;
        return Ok((input, (param_name, param_value)));
    }
}
