use crate::common::bnfcore::is_escaped;
use crate::errorparse::SipParseError;
use core::str::from_utf8;
use nom::{bytes::complete::take_while1, character::complete, sequence::tuple};

pub fn take_while_with_escaped(
    input: &[u8],
    is_fun: fn(c: u8) -> bool,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let mut idx = 0;
    while idx < input.len() {
        if is_fun(input[idx]) {
            idx += 1;
            continue;
        } else if is_escaped(&input[idx..]) {
            idx += 3;
            continue;
        }
        break;
    }

    Ok((&input[idx..], &input[..idx]))
}

/// trim start and end spaces
/// assert_eq(take_while_trim_spaces(" ab c", is_char), Ok(("ab", "c")));
pub fn take_while_trim_spaces(
    input: &[u8],
    cond_fun: fn(c: u8) -> bool,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    let (input, (_, result, _)) =
        tuple((complete::space0, take_while1(cond_fun), complete::space0))(input)?;
    Ok((input, result))
}

pub fn from_utf8_nom(v: &[u8]) -> nom::IResult<&str, &str, SipParseError> {
    match from_utf8(v) {
        Ok(res_str) => Ok(("", res_str)),
        Err(_) => sip_parse_error!(1, "Error: from_utf8_nom failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::bnfcore::*;

    fn test_take_while_trim_spaces_case(
        test_string: &str,
        expected_result: &str,
        expected_rest: &str,
    ) {
        match take_while_trim_spaces(test_string.as_bytes(), is_token_char) {
            Ok((input, result)) => {
                assert_eq!(input, expected_rest.as_bytes());
                assert_eq!(result, expected_result.as_bytes());
            }
            Err(_) => panic!(),
        }
    }

    #[test]
    fn test_take_while_trim_spaces() {
        test_take_while_trim_spaces_case(" qqq s", "qqq", "s");
        test_take_while_trim_spaces_case("qqq s", "qqq", "s");
        test_take_while_trim_spaces_case(" q ", "q", "");
        test_take_while_trim_spaces_case("s", "s", "");
    }

    #[test]
    #[should_panic]
    fn test_take_while_trim_spaces_panic() {
        test_take_while_trim_spaces_case("", "", "");
    }

    #[test]
    fn take_while_with_escaped_test() {
        match take_while_with_escaped("project%20x&priority=urgent".as_bytes(), is_alpha) {
            Ok((remainder, result)) => {
                assert_eq!(result, "project%20x".as_bytes());
                assert_eq!(remainder, "&priority=urgent".as_bytes())
            }
            Err(_) => panic!(),
        }
        match take_while_with_escaped("project%2Gx&priority=urgent".as_bytes(), is_alpha) {
            Ok((remainder, result)) => {
                assert_eq!(result, "project".as_bytes());
                assert_eq!(remainder, "%2Gx&priority=urgent".as_bytes())
            }
            Err(_) => panic!(),
        }
        match take_while_with_escaped("p".as_bytes(), is_alpha) {
            Ok((remainder, result)) => {
                assert_eq!(result, "p".as_bytes());
                assert_eq!(remainder.len(), 0);
            }
            Err(_) => panic!(),
        }
        match take_while_with_escaped("123123X".as_bytes(), is_digit) {
            Ok((remainder, result)) => {
                assert_eq!(result, "123123".as_bytes());
                assert_eq!(remainder, "X".as_bytes());
            }
            Err(_) => panic!(),
        }
        match take_while_with_escaped("abc".as_bytes(), is_digit) {
            Ok((remainder, result)) => {
                assert_eq!(result, "".as_bytes());
                assert_eq!(remainder, "abc".as_bytes());
            }
            Err(_) => panic!(),
        }
    }
}
