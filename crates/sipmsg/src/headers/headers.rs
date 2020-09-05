use crate::{
    common::{bnfcore::is_crlf, errorparse::SipParseError, traits::NomParser},
    headers::{SipHeader, SipRFCHeader},
};
use alloc::collections::{btree_map::BTreeMap, VecDeque};
use core::str;
use nom::bytes::complete::tag;
use unicase::Ascii;

pub struct Headers<'a> {
    ext_headers: Option<BTreeMap<Ascii<&'a str>, VecDeque<SipHeader<'a>>>>,
    rfc_headers: BTreeMap<SipRFCHeader, VecDeque<SipHeader<'a>>>,
}

impl<'a> Headers<'a> {
    pub fn get_ext(&self, key: &'a str) -> Option<&VecDeque<SipHeader<'a>>> {
        match &self.ext_headers {
            Some(hdrs) => hdrs.get(&Ascii::new(key)),
            None => None,
        }
    }

    /// Get headers that defined in rfc
    pub fn get_rfc(&self, hdr: SipRFCHeader) -> Option<&VecDeque<SipHeader<'a>>> {
        self.rfc_headers.get(&hdr)
    }

    /// get single value
    /// Returns some value if header by key should be present only one time
    pub fn get_ext_s(&self, key: &'a str) -> Option<&SipHeader<'a>> {
        match &self.ext_headers {
            Some(hdrs) => match hdrs.get(&Ascii::new(key)) {
                Some(s) => {
                    if s.len() == 1 {
                        return Some(&s[0]);
                    } else {
                        return None;
                    };
                }
                None => None,
            },
            None => None,
        }
    }

    /// Get header that defined in rfc
    pub fn get_rfc_s(&self, hdr: SipRFCHeader) -> Option<&SipHeader<'a>> {
        match self.rfc_headers.get(&hdr) {
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

    /// Returns length of unique headers
    // TODO rename to unique_len and add total_len
    pub fn len(&self) -> usize {
        match &self.ext_headers {
            Some(ext_headers) => ext_headers.len() + self.rfc_headers.len(),
            None => self.rfc_headers.len(),
        }
    }

    fn new() -> Headers<'a> {
        Headers {
            ext_headers: None,
            rfc_headers: BTreeMap::<SipRFCHeader, VecDeque<SipHeader<'a>>>::new(),
        }
    }

    fn add_rfc_header(
        &mut self,
        header_type: SipRFCHeader,
        mut vec_headers: VecDeque<SipHeader<'a>>,
    ) {
        if self.rfc_headers.contains_key(&header_type) {
            self.rfc_headers
                .get_mut(&header_type)
                .unwrap()
                .append(&mut vec_headers)
        } else {
            self.rfc_headers.insert(header_type, vec_headers);
        }
    }

    fn add_extension_header(&mut self, mut vec_headers: VecDeque<SipHeader<'a>>) {
        if self.ext_headers == None {
            self.ext_headers = Some(BTreeMap::<Ascii<&'a str>, VecDeque<SipHeader<'a>>>::new());
        }

        if self
            .ext_headers
            .as_ref()
            .unwrap()
            .contains_key(&vec_headers[0].name)
        {
            self.ext_headers
                .as_mut()
                .unwrap()
                .get_mut(&vec_headers[0].name)
                .unwrap()
                .append(&mut vec_headers)
        } else {
            self.ext_headers
                .as_mut()
                .unwrap()
                .insert(vec_headers[0].name, vec_headers);
        }
    }
}

impl<'a> NomParser<'a> for Headers<'a> {
    type ParseResult = Headers<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let mut headers_result = Headers::new();
        let mut inp2 = input;
        loop {
            let (input, (rfc_type, vec_headers)) = SipHeader::parse(inp2)?;
            match rfc_type {
                Some(hdr_type) => {
                    headers_result.add_rfc_header(hdr_type, vec_headers);
                }
                None => {
                    headers_result.add_extension_header(vec_headers);
                }
            }
            let (input, _) = tag("\r\n")(input)?; // move to header parse
            inp2 = input; // skip crlf of header field
            if is_crlf(inp2) {
                // end of headers and start of body part
                break;
            }
        }
        Ok((inp2, headers_result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_parse_test() {
        let parse_headers_result = Headers::parse(
            "Accept: application/sdp, application/pkcs7-mime, application/h.245;q=0.1\r\n\
             To: sip:user@example.com\r\n\
             Route: <sip:192.0.2.254:5060>\r\n\
             Route: <sip:[2001:db8::1]>\r\n\
             Max-Forwards: 70\r\n\
             Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
             CSeq: 60 OPTIONS\r\n\
             Extention-Header: Value\r\n\
             Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
                .as_bytes(),
        );

        match parse_headers_result {
            Ok((_, hdrs)) => {
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Accept).unwrap()[0].value.vstr,
                    "application/sdp"
                );
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Accept).unwrap()[1].value.vstr,
                    "application/pkcs7-mime"
                );
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Accept).unwrap()[2].value.vstr,
                    "application/h.245"
                );
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Accept).unwrap()[2]
                        .params()
                        .unwrap()
                        .get(&"q"),
                    Some((&Ascii::new("q"), &Some("0.1")))
                );

                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Route).unwrap()[0].value.vstr,
                    "<sip:192.0.2.254:5060>"
                );
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Route).unwrap()[1].value.vstr,
                    "<sip:[2001:db8::1]>"
                );
                assert_eq!(
                    hdrs.get_ext("extention-header").unwrap()[0].value.vstr,
                    "Value"
                );
                assert_eq!(hdrs.get_rfc(SipRFCHeader::Route).unwrap().len(), 2);
            }
            Err(_) => panic!(),
        }
    }
}
