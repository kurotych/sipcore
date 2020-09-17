use crate::{
    common::{errorparse::SipParseError, take_sws_token},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_while;

/// Call-Info   =  "Call-Info" HCOLON info *(COMMA info)
/// info        =  LAQUOT absoluteURI RAQUOT *( SEMI info-param)
/// info-param  =  ( "purpose" EQUAL ( "icon" / "info"
///                                  / "card" / token ) ) / generic-param
pub struct CallInfo;

impl SipHeaderParser for CallInfo {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, _) = take_sws_token::laquot(source_input)?;
        let (input, uri) = take_while(|c: u8| c != b'>')(input)?;
        let (input, _) = take_sws_token::raquot(input)?;
        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::AbsoluteURI, uri);

        let (_, hdr_val) = HeaderValue::new(uri, HeaderValueType::CallInfo, Some(tags))?;

        return Ok((input, hdr_val));
    }
}

#[cfg(test)]
mod test {
    fn call_info_test_case(source_input: &str, expected_string_value: &str, expected_uri: &str) {
        let val = CallInfo::take_value(source_input.as_bytes());
        let (input, val) = val.unwrap();
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AbsoluteURI],
            expected_uri.as_bytes()
        );
        assert_eq!(val.vstr, expected_string_value);
        assert_eq!(input, b"\r\n");
    }

    use super::*;
    #[test]
    fn callinfo_parser_test() {
        call_info_test_case(
            "<http://wwww.example.com/alice/photo.jpg>\r\n",
            "http://wwww.example.com/alice/photo.jpg",
            "http://wwww.example.com/alice/photo.jpg",
        );
    }
}
