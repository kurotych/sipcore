use crate::common::{
    bnfcore::is_token_char,
    errorparse::SipParseError,
    hostport::HostPort,
    nom_wrappers::{from_utf8_nom, take_quoted_string, take_sws, take_while_trim_sws},
    take_sws_token,
};
use alloc::collections::btree_map::BTreeMap;
use nom::{bytes::complete::take_while, multi::many0};
use unicase::Ascii;

pub struct GenericParam<'a> {
    /// Parameter name
    pub name: Ascii<&'a str>,
    /// Param value, without quotes and "[" if it ipv6
    pub value: Option<&'a str>,
    // TODO add raw representation param
    // It needs at least to dump quoted params as is
}

impl<'a> GenericParam<'a> {
    fn parse(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (Ascii<&'a str>, Option<&'a str>), SipParseError> {
        let (input, (_, parameter_name, _)) = take_while_trim_sws(input, is_token_char)?;

        let (_, param_name) = from_utf8_nom(parameter_name)?;
        if input.is_empty() || input[0] != b'=' {
            return Ok((input, (Ascii::new(param_name), None)));
        }
        let (input, _) = take_sws_token::equal(input)?;

        if input.is_empty() {
            return sip_parse_error!(2, "generic-param parse error");
        }

        let (input, parameter_value) = if input[0] == b'"' {
            let (input, (_, param_val, _)) = take_quoted_string(input).unwrap();
            (input, param_val)
        } else if input[0] == b'[' {
            HostPort::take_ipv6_host(input)?
        } else {
            take_while(is_token_char)(input)?
        };

        let (input, _) = take_sws(input)?;
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

    pub fn parse(input: &'a [u8]) -> nom::IResult<&[u8], GenericParams<'a>, SipParseError> {
        let (input, vec_res) = many0(many_params_parser)(input)?;
        Ok((
            input,
            GenericParams {
                params: vec_res.into_iter().collect(),
            },
        ))
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
#[cfg(test)]
mod tests {
    use super::*;

    fn assert_eq_gp(gparams: &GenericParams, key: &str, val: Option<&str>) {
        assert_eq!(gparams.get(key), Some(&val));
    }
    #[test]
    fn patameters_contains_test() {
        let (inp, params) = GenericParams::parse(";a=b\r\n".as_bytes()).unwrap();
        assert_eq!(params.contains("a"), true);
        assert_eq!(params.contains("b"), false);
        assert_eq!(params.contains("c"), false);
        assert_eq!(inp.len(), 2)
    }

    #[test]
    fn patameters_correct_parse_test() {
        let (inp, params) = GenericParams::parse(";a=b\r\n".as_bytes()).unwrap();
        assert_eq_gp(&params, "a", Some("b"));
        assert_eq!(inp.len(), 2);

        let (inp, params) = GenericParams::parse(";a;n=q;c\r\n".as_bytes()).unwrap();
        assert_eq_gp(&params, "a", None);
        assert_eq_gp(&params, "n", Some("q"));
        assert_eq_gp(&params, "c", None);
        assert_eq!(params.get("qq"), None);
        assert_eq!(inp.len(), 2);

        let (inp, params) =
            GenericParams::parse("; aw ;d =es;sam;mark= a; wam = kram; q = 0.3\r\n".as_bytes())
                .unwrap();
        assert_eq_gp(&params, "aw", None);
        assert_eq_gp(&params, "d", Some("es"));
        assert_eq_gp(&params, "sam", None);
        assert_eq_gp(&params, "mark", Some("a"));
        assert_eq_gp(&params, "wam", Some("kram"));
        assert_eq_gp(&params, "q", Some("0.3"));
        assert_eq!(inp.len(), 2);
    }

    fn parameter_test(
        input_str: &str,
        expected_name: &str,
        expected_value: Option<&str>,
        expected_len: usize,
    ) {
        let (i, (name, value)) = GenericParam::parse(input_str.as_bytes()).unwrap();
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
        parameter_test(" a\r\n", "a", None, 2);
        parameter_test(" aw = b\r\n", "aw", Some("b"), 2);
        parameter_test(" aw = b; \r\n", "aw", Some("b"), 4);
        parameter_test("q=0.001", "q", Some("0.001"), 0);
        parameter_test(
            "+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000A95A0E128>\"",
            "+sip.instance",
            Some("<urn:uuid:00000000-0000-1000-8000-000A95A0E128>"),
            0,
        );
        parameter_test(
            "received=[2001:db8::9:255]",
            "received",
            Some("2001:db8::9:255"),
            0,
        );
        // According to rfc we should take until it is not token char
        // It seems validation of next chars it is not deal of this class.
        // But i'm not sure
        parameter_test("a=bla$bla", "a", Some("bla"), 4);
    }

    #[test]
    fn parameter_incorrect_parse_test() {
        fail_parameter_test("");
        fail_parameter_test("a=");
    }
}
