use crate::{
    common::{
        bnfcore::is_alpha, errorparse::SipParseError, nom_wrappers::take_qutoed_string,
        take_sws_token,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_while;

pub struct AuthenticationInfoParser;

impl AuthenticationInfoParser {
    fn is_info_name_allowed(value_name: &[u8]) -> bool {
        match value_name {
            b"nextnonce" => return true,
            b"qop" => true,
            b"rspauth" => true,
            b"cnonce" => true,
            b"nc" => true,
            _ => return false,
        }
    }
}

impl SipHeaderParser for AuthenticationInfoParser {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, info_name) = take_while(is_alpha)(source_input)?;
        if !AuthenticationInfoParser::is_info_name_allowed(info_name) {
            return sip_parse_error!(1, "AuthentificatiionInfo value name is invalid");
        }
        let (input, (_, _, _)) = take_sws_token::equal(input)?;
        let (input, (_, value, spaces_after_rdquot)) = take_qutoed_string(input).unwrap();

        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::AinfoType, info_name);
        tags.insert(HeaderTagType::AinfoValue, value);

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len() - spaces_after_rdquot.len()],
            HeaderValueType::SimpleString,
            Some(tags),
            None,
        )?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn auth_info_parser_test() {
        let val = AuthenticationInfoParser::take_value(
            "nextnonce=\"47364c23432d2e131a5fb210812c\"  \r\n".as_bytes(),
        );
        let (input, val) = val.unwrap();
        assert_eq!(input, "\r\n".as_bytes());
        assert_eq!(val.vstr, "nextnonce=\"47364c23432d2e131a5fb210812c\"");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AinfoType],
            "nextnonce".as_bytes()
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AinfoValue],
            "47364c23432d2e131a5fb210812c".as_bytes()
        );
    }
}
