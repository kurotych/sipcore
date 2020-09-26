use crate::common::{
    bnfcore::is_token_char,
    errorparse::SipParseError,
    nom_wrappers::{from_utf8_nom, take_while_trim_sws},
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
        let (input, (_, parameter_name, _)) = take_while_trim_sws(input, is_token_char)?;

        let (_, param_name) = from_utf8_nom(parameter_name)?;

        if input.is_empty() || input[0] != b'=' {
            return Ok((input, (Ascii::new(param_name), None)));
        }

        if input.len() == 1 {
            return sip_parse_error!(2, "generic-param parse error");
        }

        let (input, (_, parameter_value, _)) =
            take_while_trim_sws(&input[1..] /* skip '=' */, is_token_char)?;

        let (_, parameter_value) = from_utf8_nom(parameter_value)?;

        Ok((input, (Ascii::new(param_name), Some(parameter_value))))
    }
}

#[derive(PartialEq, Debug)]
pub struct GenericParams<'a> {
    params: BTreeMap<Ascii<&'a str>, Option<&'a str>>,
}

impl<'a> GenericParams<'a> {
    pub fn get(&self, key: &'a str) -> Option<&Option<&'a str>> {
        let key = Ascii::new(key);
        self.params.get(&key)
    }

    pub fn contains(&self, key: &'a str) -> bool {
        let key = Ascii::new(key);
        self.params.contains_key(&key)
    }
}

fn many_params_parser(
    input: &[u8],
) -> nom::IResult<&[u8], (Ascii<&str>, Option<&str>), SipParseError> {
    if input.len() < 2 || input[0] != b';' {
        return sip_parse_error!(1, "GenericParamsParser parse error");
    }
    GenericParam::parse(&input[1..])
}

impl<'a> NomParser<'a> for GenericParams<'a> {
    type ParseResult = GenericParams<'a>;
    // input should start from ';'
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, vec_res) = many0(many_params_parser)(input)?;
        Ok((
            input,
            GenericParams {
                params: vec_res.into_iter().collect(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_eq_gp(gparams: &GenericParams, key: &str, val: Option<&str>) {
        assert_eq!(gparams.get(key), Some(&val));
    }
    #[test]
    fn patameters_contains_test() {
        match GenericParams::parse(";a=b\r\n".as_bytes()) {
            Ok((inp, gparams)) => {
                assert_eq!(gparams.contains("a"), true);
                assert_eq!(gparams.contains("b"), false);
                assert_eq!(gparams.contains("c"), false);
                assert_eq!(inp.len(), 2)
            }
            Err(_) => panic!(),
        }
    }

    #[test]
    fn patameters_correct_parse_test() {
        match GenericParams::parse(";a=b\r\n".as_bytes()) {
            Ok((inp, gparams)) => {
                assert_eq_gp(&gparams, "a", Some("b"));
                assert_eq!(inp.len(), 2)
            }
            Err(_) => panic!(),
        }

        match GenericParams::parse(";a;n=q;c\r\n".as_bytes()) {
            Ok((inp, gparams)) => {
                assert_eq_gp(&gparams, "a", None);
                assert_eq_gp(&gparams, "n", Some("q"));
                assert_eq_gp(&gparams, "c", None);
                assert_eq!(gparams.get("qq"), None);
                assert_eq!(inp.len(), 2)
            }
            Err(_) => panic!(),
        }

        match GenericParams::parse("; aw ;d =es;sam;mark= a; wam = kram; q = 0.3\r\n".as_bytes()) {
            Ok((i, gparams)) => {
                assert_eq_gp(&gparams, "aw", None);
                assert_eq_gp(&gparams, "d", Some("es"));
                assert_eq_gp(&gparams, "sam", None);
                assert_eq_gp(&gparams, "mark", Some("a"));
                assert_eq_gp(&gparams, "wam", Some("kram"));
                assert_eq_gp(&gparams, "q", Some("0.3"));
                assert_eq!(i.len(), 2)
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
        let res = GenericParam::parse(input_str.as_bytes());
        let (i, (name, value)) = res.unwrap();
        assert_eq!(name, expected_name);
        assert_eq!(value, expected_value);
        assert_eq!(i.len(), expected_len);
    }

    fn fail_parameter_test(input_str: &str) {
        match GenericParam::parse(input_str.as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
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
        parameter_test("q=0.001", "q", Some("0.001"), 0);
    }

    #[test]
    fn parameter_incorrect_parse_test() {
        fail_parameter_test("");
        fail_parameter_test("a=");
        fail_parameter_test("a=/");
    }
}
