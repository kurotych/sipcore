use crate::common::{
    bnfcore::{is_token_char},
    errorparse::SipParseError,
};
use crate::headers::{
    header::{HeaderValue, HeaderValueType},
    traits::SipHeaderParser,
};
use nom::bytes::complete::take_while1;


// Content-Disposition: attachment; filename=smime.p7s; handling=required
// Content-Disposition: session
// Content-Disposition: session;handling=optional

pub struct ContentDisposition;

impl SipHeaderParser for ContentDisposition {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, value) = take_while1(is_token_char)(source_input)?;
        let (_, hdr_val) = HeaderValue::new(value, HeaderValueType::TokenValue, None, None)?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_disposition_parse_test() {
        let (input, val) =
            ContentDisposition::take_value("session;handling=optional \r\n".as_bytes()).unwrap();
        assert_eq!(input, ";handling=optional \r\n".as_bytes());
        assert_eq!(val.vstr, "session");
    }
}

