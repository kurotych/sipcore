/// Helper functions for parsing with nom Interface
use nom;

use crate::bnfcore::is_escaped;

type IsFun = fn(c: u8) -> bool;

pub fn take_while_with_escaped(input: &[u8], is_fun: IsFun) -> nom::IResult<&[u8], &[u8]> {
    let mut idx = 0;
    while idx < input.len() {
        if is_fun(input[idx]) {
            idx += 1;
            continue;
        } else if is_escaped(&input[idx..]) {
            idx += 3;
            continue;
        }
        return Ok((&input[idx..], &input[..idx]));
    }

    Ok((&b""[..], &input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bnfcore::*;

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
