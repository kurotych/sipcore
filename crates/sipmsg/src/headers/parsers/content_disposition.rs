use crate::{
    common::errorparse::SipParseError,
    headers::{header::HeaderValue, parsers::token_header, traits::SipHeaderParser},
};

// Content-Disposition: attachment; filename=smime.p7s; handling=required
// Content-Disposition: session
// Content-Disposition: session;handling=optional

pub struct ContentDisposition;

impl SipHeaderParser for ContentDisposition {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        token_header::take(source_input)
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
