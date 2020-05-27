use crate::common::{
    bnfcore::is_token_char,
    errorparse::SipParseError,
    nom_wrappers::{from_utf8_nom, take_while_trim_spaces},
    traits::NomParser,
};
use unicase::Ascii;

pub struct GenericParam<'a> {
    /// Sip header name
    pub name: Ascii<&'a str>,
    /// Sip header value
    pub value: Option<&'a str>,
}

impl<'a> NomParser<'a> for GenericParam<'a> {
    type ParseResult = Self;
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, parameter_name) = take_while_trim_spaces(input, is_token_char)?;

        let (_, param_name) = from_utf8_nom(parameter_name)?;
        if param_name.is_empty() {
            return sip_parse_error!(1, "generic-param parse error");
        }

        if input.is_empty() || input[0] != b'=' {
            let gp = GenericParam {
                name: Ascii::new(param_name),
                value: None,
            };
            return Ok((input, gp));
        }

        if input.len() == 1 {
            return sip_parse_error!(2, "generic-param parse error");
        }

        let (input, parameter_value) =
            take_while_trim_spaces(&input[1..] /* skip '=' */, is_token_char)?;

        let (_, parameter_value) = from_utf8_nom(parameter_value)?;

        Ok((
            input,
            GenericParam {
                name: Ascii::new(param_name),
                value: Some(parameter_value),
            },
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn patameter_test(
        input_str: &str,
        expected_name: &str,
        expected_value: Option<&str>,
        expected_len: usize,
    ) {
        match GenericParam::parse(input_str.as_bytes()) {
            Ok((i, gp)) => {
                assert_eq!(gp.name, expected_name);
                assert_eq!(gp.value, expected_value);
                assert_eq!(i.len(), expected_len);
            }
            Err(_) => panic!(),
        }
    }
    #[test]
    fn patameter_correct_parse_test() {
        patameter_test("a", "a", None, 0);
        patameter_test("ab", "ab", None, 0);
        patameter_test("a=b", "a", Some("b"), 0);
        patameter_test("a=bc;", "a", Some("bc"), 1);
        patameter_test("a\r\n", "a", None, 2);
        patameter_test("a\r\n", "a", None, 2);
        patameter_test("a=b\r\n", "a", Some("b"), 2);
        patameter_test("a=b;123", "a", Some("b"), 4);
        patameter_test(" a  \r\n", "a", None, 2);
        patameter_test(" aw = b \r\n", "aw", Some("b"), 2);
        patameter_test(" aw = b; \r\n", "aw", Some("b"), 4);
    }

    #[test]
    #[should_panic]
    fn parameter_incorrect_parse_test() {
        patameter_test("a=", "a", None, 0);
    }
}
