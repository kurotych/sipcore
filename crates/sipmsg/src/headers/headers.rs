use crate::bnfcore::is_crlf;
use crate::common::errorparse::SipParseError;
use crate::headers::{SipHeader, SipHeaderParameters, SipRFCHeader};
use crate::traits::{NomParser, SipMessageHeaderParser};

use alloc::collections::{btree_map::BTreeMap, VecDeque};
use core::str;
use unicase::Ascii;

type HeaderParser<'a> =
    fn(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], (&'a str /*value*/, Option<SipHeaderParameters>), SipParseError>;

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
    pub fn len(&self) -> usize {
        match &self.ext_headers {
            Some(ext_headers) => ext_headers.len() + self.rfc_headers.len(),
            None => self.rfc_headers.len(),
        }
    }

    pub fn find_parser(header_name: &'a str) -> (Option<SipRFCHeader>, HeaderParser<'a>) {
        match SipRFCHeader::from_str(&header_name) {
            Some(rfc_header) => match rfc_header {
                // For implement new parser add row RfCHeader => (Some(rfc_header), RFCHeaderType::parse)
                _ => (Some(rfc_header), SipHeader::parse_value),
            },
            None => (None, SipHeader::parse_value),
        }
    }
}

impl<'a> NomParser<'a> for Headers<'a> {
    type ParseResult = Headers<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let mut rfc_headers = BTreeMap::<SipRFCHeader, VecDeque<SipHeader<'a>>>::new();
        let mut ext_headers = BTreeMap::<Ascii<&'a str>, VecDeque<SipHeader<'a>>>::new();
        let mut inp2 = input;

        loop {
            // TODO COMMA
            let (input, header_name) = SipHeader::take_header_name(inp2)?;
            let (rfc_header, parser) = Headers::find_parser(&header_name);
            let (input, (value, parameters)) = parser(input)?;
            let sh = SipHeader::new(header_name, value, parameters);
            match rfc_header {
                Some(hdr) => {
                    // Add to rfc_headers
                    if rfc_headers.contains_key(&hdr) {
                        rfc_headers.get_mut(&hdr).unwrap().push_front(sh)
                    } else {
                        let mut vec: VecDeque<SipHeader<'a>> = VecDeque::new();
                        vec.push_front(sh);
                        rfc_headers.insert(hdr, vec);
                    }
                }
                None => {
                    // Add to ext_headers
                    if ext_headers.contains_key(&sh.name) {
                        ext_headers.get_mut(&sh.name).unwrap().push_front(sh)
                    } else {
                        let mut vec: VecDeque<SipHeader<'a>> = VecDeque::new();
                        vec.push_front(sh);
                        ext_headers.insert(vec[0].name, vec);
                    }
                }
            }
            inp2 = input;
            if is_crlf(inp2) {
                // end of headers and start of body part
                break;
            }
        }
        Ok((
            inp2,
            Headers {
                rfc_headers: rfc_headers,
                ext_headers: if ext_headers.len() == 0 {
                    None
                } else {
                    Some(ext_headers)
                },
            },
        ))
    }
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
             Extention-Header: Value\r\n\
             Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\nsomebody"
                .as_bytes(),
        );

        match parse_headers_result {
            Ok((_, hdrs)) => {
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Route).unwrap()[1].value,
                    "<sip:192.0.2.254:5060>"
                );
                assert_eq!(
                    hdrs.get_rfc(SipRFCHeader::Route).unwrap()[0].value,
                    "<sip:[2001:db8::1]>"
                );
                assert_eq!(hdrs.get_ext("extention-header").unwrap()[0].value, "Value");
                assert_eq!(hdrs.get_rfc(SipRFCHeader::Route).unwrap().len(), 2);
            }
            Err(_) => panic!(),
        }
    }
}
