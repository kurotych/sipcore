use crate::common::{
    bnfcore::is_token_char,
    errorparse::SipParseError,
    nom_wrappers::{from_utf8_nom, take_while_trim_spaces},
    traits::NomParser,
};
use alloc::collections::btree_map::BTreeMap;
use nom::multi::many0;
use unicase::Ascii;

// generic-param  =  token [ EQUAL gen-value ]
pub struct GenericParam<'a> {
    /// Sip header name
    pub name: Ascii<&'a str>,
    /// Sip header value
    pub value: Option<&'a str>,
}

impl<'a> NomParser<'a> for GenericParam<'a> {
    type ParseResult = (Ascii<&'a str>, Option<&'a str>);
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, parameter_name) = take_while_trim_spaces(input, is_token_char)?;

        let (_, param_name) = from_utf8_nom(parameter_name)?;

        if input.is_empty() || input[0] != b'=' {
            return Ok((input, (Ascii::new(param_name), None)));
        }

        if input.len() == 1 {
            return sip_parse_error!(2, "generic-param parse error");
        }

        let (input, parameter_value) =
            take_while_trim_spaces(&input[1..] /* skip '=' */, is_token_char)?;

        let (_, parameter_value) = from_utf8_nom(parameter_value)?;

        Ok((input, (Ascii::new(param_name), Some(parameter_value))))
    }
}

type GenericParams<'a> = BTreeMap<Ascii<&'a str>, Option<&'a str>>;

pub struct GenericParamsParser;

fn many_params_parser(
    input: &[u8],
) -> nom::IResult<&[u8], (Ascii<&str>, Option<&str>), SipParseError> {
    if input.len() < 2 || input[0] != b';' {
        return sip_parse_error!(1, "GenericParamsParser parse error");
    }
    GenericParam::parse(&input[1..])
}

impl<'a> NomParser<'a> for GenericParamsParser {
    type ParseResult = GenericParams<'a>;
    // input should start from ';'
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, vec_res) = many0(many_params_parser)(input)?;
        Ok((input, vec_res.into_iter().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patameters_correct_parse_test() {
        match GenericParamsParser::parse(";a=b\r\n".as_bytes()) {
            Ok((inp, value)) => {
                assert_eq!(value.get(&Ascii::new("a")), Some(&Some("b")));
                assert_eq!(value.get(&Ascii::new("b")), None);
                assert_eq!(inp.len(), 2)
            }
            Err(_) => panic!(),
        }

        match GenericParamsParser::parse(";a;n=q;c\r\n".as_bytes()) {
            Ok((inp, value)) => {
                assert_eq!(value.get(&Ascii::new("a")), Some(&None));
                assert_eq!(value.get(&Ascii::new("n")), Some(&Some("q")));
                assert_eq!(value.get(&Ascii::new("c")), Some(&None));
                assert_eq!(value.get(&Ascii::new("qq")), None);
                assert_eq!(inp.len(), 2)
            }
            Err(_) => panic!(),
        }
    }

    fn parameter_test(
        input_str: &str,
        expected_name: &str,
        expected_value: Option<&str>,
        expected_len: usize,
    ) {
        match GenericParam::parse(input_str.as_bytes()) {
            Ok((i, (name, value))) => {
                assert_eq!(name, expected_name);
                assert_eq!(value, expected_value);
                assert_eq!(i.len(), expected_len);
            }
            Err(_) => panic!(),
        }
    }
    #[test]
    fn parameter_correct_parse_test() {
        parameter_test("a", "a", None, 0);
        parameter_test("ab", "ab", None, 0);
        parameter_test("a=b", "a", Some("b"), 0);
        parameter_test("a=bc;", "a", Some("bc"), 1);
        parameter_test("a\r\n", "a", None, 2);
        parameter_test("a\r\n", "a", None, 2);
        parameter_test("a=b\r\n", "a", Some("b"), 2);
        parameter_test("a=b;123", "a", Some("b"), 4);
        parameter_test(" a  \r\n", "a", None, 2);
        parameter_test(" aw = b \r\n", "aw", Some("b"), 2);
        parameter_test(" aw = b; \r\n", "aw", Some("b"), 4);
    }
    #[test]
    #[should_panic]
    fn parameter_incorrect_parse_test() {
        parameter_test("", "", None, 0);
        parameter_test("a=", "", None, 0);
        parameter_test("a=/", "", None, 0);
        parameter_test("a/", "", None, 0);
    }
}
