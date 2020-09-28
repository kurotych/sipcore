use crate::{
    common::{
        bnfcore::is_digit, errorparse::SipParseError, nom_wrappers::take_sws, take_sws_token,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::{take_until, take_while1};

pub struct RetryAfter;

impl SipHeaderParser for RetryAfter {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, seconds) = take_while1(is_digit)(source_input)?;
        let (input, _) = take_sws(input)?;
        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::Seconds, seconds);
        if !input.is_empty() && input[0] == b'(' {
            let (input, _) = take_sws_token::lparen(input)?;
            let (input, comment) = take_until(")")(input)?;
            let input = &input[1..]; // skio )
            tags.insert(HeaderTagType::Comment, comment);
            let (_, hdr_val) = HeaderValue::new(
                &source_input[..source_input.len() - input.len()],
                HeaderValueType::RetryAfter,
                Some(tags),
                None,
            )?;
            return Ok((input, hdr_val));
        }
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len()],
            HeaderValueType::RetryAfter,
            Some(tags),
            None,
        )?;
        return Ok((input, hdr_val));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_retryafter_value() {
        let (input, val) = RetryAfter::take_value("120 (I'm in a meeting)\r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "120 (I'm in a meeting)");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Comment],
            "I'm in a meeting".as_bytes()
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Seconds],
            "120".as_bytes()
        );
        assert_eq!(input, b"\r\n");
    }
}
