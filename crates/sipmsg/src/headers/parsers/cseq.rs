use crate::common::nom_wrappers::take_sws;
use crate::common::{
    bnfcore::{is_digit, is_token_char},
    errorparse::SipParseError,
};
use crate::headers::{
    header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
    traits::SipHeaderParser,
};

use nom::bytes::complete::take_while1;

/// CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
pub struct CSeq;

impl SipHeaderParser for CSeq {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let mut tags = HeaderTags::new();
        let (input, number) = take_while1(is_digit)(source_input)?;
        let (input, _) = take_sws(input)?;
        let (input, method) = take_while1(is_token_char)(input)?;
        tags.insert(HeaderTagType::Number, number);
        tags.insert(HeaderTagType::Method, method);

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len()],
            HeaderValueType::CSeq,
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
    fn test_cseq_value() {
        let (input, val) = CSeq::take_value("4711 INVITE\r\n".as_bytes()).unwrap();
        assert_eq!(input, "\r\n".as_bytes());
        assert_eq!(val.vstr, "4711 INVITE");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Number],
            "4711".as_bytes()
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Method],
            "INVITE".as_bytes()
        );
    }
}
