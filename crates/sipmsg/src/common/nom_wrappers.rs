use crate::common::bnfcore::is_escaped;
use crate::errorparse::SipParseError;
use core::str::from_utf8;
use nom;

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
