use crate::{
    common::{bnfcore::is_word_char, errorparse::SipParseError},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::{take, take_while1};

/// Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
/// callid   =  word [ "@" word ]
pub struct CallID;

impl SipHeaderParser for CallID {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let mut tags = HeaderTags::new();

        let (input, id) = take_while1(is_word_char)(source_input)?;
        tags.insert(HeaderTagType::ID, id);
        if !input.is_empty() && input[0] == b'@' {
            let (input, _) = take(1usize)(input)?;
            let (input, host) = take_while1(is_word_char)(input)?;
            tags.insert(HeaderTagType::Host, host);

            let (_, hdr_val) = HeaderValue::new(
                &source_input[..id.len() + host.len() + 1 /* 1 - is '@' */],
                HeaderValueType::CallID,
                Some(tags),
                None,
            )?;

            return Ok((input, hdr_val));
        }
        let (_, hdr_val) = HeaderValue::new(id, HeaderValueType::CallID, Some(tags), None)?;

        return Ok((input, hdr_val));
    }
}

#[cfg(test)]
mod test {
    fn call_id_test_case(
        source_input: &str,
        expected_string_value: &str,
        expected_id_value: &str,
        expected_host_value: Option<&str>,
    ) {
        let val = CallID::take_value(source_input.as_bytes());
        let (input, val) = val.unwrap();
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::ID],
            expected_id_value.as_bytes()
        );
        if expected_host_value != None {
            assert_eq!(
                val.tags().unwrap()[&HeaderTagType::Host],
                expected_host_value.unwrap().as_bytes()
            );
        }
        assert_eq!(val.vstr, expected_string_value);
        assert_eq!(input, b"\r\n");
    }

    use super::*;
    #[test]
    fn authorization_parser_test() {
        call_id_test_case(
            "3848276298220188511@atlanta.example.com\r\n",
            "3848276298220188511@atlanta.example.com",
            "3848276298220188511",
            Some("atlanta.example.com"),
        );

        call_id_test_case(
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@foo.bar.com\r\n",
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@foo.bar.com",
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            Some("foo.bar.com"),
        );

        call_id_test_case(
            "a84b4c76e66710\r\n",
            "a84b4c76e66710",
            "a84b4c76e66710",
            None,
        );
    }
}
