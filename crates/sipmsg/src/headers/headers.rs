use crate::bnfcore::is_crlf;
/// Contained of SIP message headers
use crate::errorparse::SipParseError;
use crate::header::Header;
use crate::traits::NomParser;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::VecDeque;
use unicase::Ascii;

pub struct Headers<'a> {
    headers: BTreeMap<Ascii<&'a str>, VecDeque<Header<'a>>>,
}

impl<'a> Headers<'a> {
    pub fn get(&self, key: &'a str) -> Option<&VecDeque<Header<'a>>> {
        self.headers.get(&Ascii::new(key))
    }

    /// get single value
    /// Returns some value if header by key should be present only one time
    pub fn get_s(&self, key: &'a str) -> Option<&Header<'a>> {
        match self.headers.get(&Ascii::new(key)) {
            Some(s) => {
                if s.len() == 1 {
                    return Some(&s[0]);
                } else {
                    return None;
                };
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }
}

impl<'a> NomParser<'a> for Headers<'a> {
    type ParseResult = Headers<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let mut headers = BTreeMap::<Ascii<&'a str>, VecDeque<Header<'a>>>::new();
        let mut inp2 = input;
        loop {
            match Header::parse(inp2) {
                Ok((inp, header)) => {
                    if headers.contains_key(&header.name) {
                        headers.get_mut(&header.name).unwrap().push_front(header)
                    } else {
                        let mut vec: VecDeque<Header<'a>> = VecDeque::new();
                        vec.push_front(header);
                        headers.insert(vec[0].name, vec);
                    }
                    inp2 = inp;
                }
                Err(e) => return Err(e),
            }
            if is_crlf(inp2) {
                // end of headers and start of body part
                break;
            }
        }
        Ok((inp2, Headers { headers: headers }))
    }
}

/// Headers that defined in rfc3261
pub enum SipRFCHeader {
    Accept,
    AcceptEncoding,
    AlertInfo,
    Allow,
    AuthenticationInfo,
    Authorization,
    CallID,
    CallInfo,
    Contact,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentType,
    CSeq,
    Date,
    ErrorInfo,
    Expires,
    From,
    InReplyTo,
    MaxForwards,
    MimeVersion,
    MinExpires,
    Organization,
    Priority,
    ProxyAuthenticate,
    ProxyAuthorization,
    ProxyRequire,
    RecordRoute,
    ReplyTo,
    Require,
    RetryAfter,
    Route,
    Server,
    Subject,
    Supported,
    Timestamp,
    To,
    Unsupported,
    UserAgent,
    Via,
    Warning,
    WWWAuthenticate
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_parse_test() {
        let parse_headers_result = Headers::parse(
            "To: sip:user@example.com\r\n\
             Route: <sip:192.0.2.254:5060>\r\n\
             Route: <sip:[2001:db8::1]>\r\n\
             Max-Forwards: 70\r\n\
             Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
             CSeq: 60 OPTIONS\r\n\
             Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
                .as_bytes(),
        );

        match parse_headers_result {
            Ok((_, hdrs)) => {
                assert_eq!(
                    hdrs.get("Route").unwrap()[1].value,
                    "<sip:192.0.2.254:5060>"
                );
                assert_eq!(hdrs.get("rouTe").unwrap()[0].value, "<sip:[2001:db8::1]>");
                assert_eq!(hdrs.get("route").unwrap().len(), 2);
            }
            Err(_) => panic!(),
        }
    }
}
