use crate::{
    common::{bnfcore::is_digit, errorparse::SipParseError},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser
    }
};
use nom::bytes::complete::take_while1;

pub struct MimeVersion;

impl SipHeaderParser for MimeVersion {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (inp, major) = take_while1(is_digit)(source_input)?;
        let (inp, _) = nom::character::complete::char('.')(inp)?;
        let (inp, minor) = take_while1(is_digit)(inp)?;
        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::Major, major);
        tags.insert(HeaderTagType::Minor, minor);
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - inp.len()],
            HeaderValueType::Digit,
            Some(tags),
            None,
        )?;
        Ok((inp, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mime_value() {
        let (input, val) = MimeVersion::take_value("1.2 \r\n".as_bytes()).unwrap();
        assert_eq!(input, " \r\n".as_bytes());
        assert_eq!(val.vstr, "1.2");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Major],
            "1".as_bytes()
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Minor],
            "2".as_bytes()
        );
    }
}

