use nom::{
    bytes::complete::{is_not, take, take_until, take_while1},
    character::complete,
    sequence::tuple,
};

use alloc::vec::Vec;
use core::str;

const CRLF: &[u8] = &[0x0d, 0x0a]; // /r/n

/// https://tools.ietf.org/html/rfc3261#section-7.3
pub struct Header<'a> {
    /// Sip header name
    pub name: &'a str,
    /// Sip header value
    pub value: &'a str,

    // TODO make better representation type
    /// Sip parameters
    pub parameters: Option<&'a str>,
}

pub fn parse_headers(input: &[u8]) -> nom::IResult<&[u8], Vec<Header>> {
    let mut headers = Vec::with_capacity(15); // 15 just random number
    let mut inp2 = input;
    loop {
        match Header::parse(inp2) {
            Ok((inp, header)) => {
                headers.push(header);
                inp2 = inp;
            }
            Err(e) => return Err(e),
        }
        if inp2 == CRLF {
            // end of headers and start of body part
            break;
        }
    }
    Ok((inp2, headers))
}

// https://tools.ietf.org/html/rfc2822#section-2.2
// A field name MUST be composed of printable US-ASCII characters (i.e.,
// characters that have values between 33 and 126, inclusive), except colon.
pub fn is_alphabetic_or_hyphen(chr: u8) -> bool {
    // 58 == ':' (colon)
    chr != 58 && chr >= 33 && chr <= 126
}

impl<'a> Header<'a> {
    // This function O(n + h * 2) make it O(n + h)
    // where h - header_field, n - header name
    // first full iteration is 'tuple' second in 'is_not'
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Header> {
        let (input, (name, _, _, _, header_field, _)) = tuple((
            take_while1(is_alphabetic_or_hyphen),
            complete::space0,
            complete::char(':'),
            complete::space0,
            take_until("\r\n"),
            take(2usize), // skip /r/n
        ))(input)?;

        match is_not(";")(header_field) {
            Ok((params, header_value)) => {
                let mut parameters: Option<&str> = None;
                if params.len() != 0 {
                    let (params, _) = take(1usize)(params)?; // skip ;
                    unsafe {
                        parameters = Some(str::from_utf8_unchecked(params));
                    }
                }
                return Ok((
                    input,
                    Header {
                        name: unsafe { str::from_utf8_unchecked(name) },
                        value: unsafe { str::from_utf8_unchecked(header_value) },
                        parameters: parameters,
                    },
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

mod tests {
    #[test]
    fn parse_header() {
        match crate::Header::parse("Subject:This is a test\r\n".as_bytes()) {
            Ok((input, hdr)) => {
                assert_eq!(hdr.name, "Subject");
                assert_eq!(hdr.value, "This is a test");
                assert_eq!(input.len(), 0)
            }
            Err(_e) => panic!(),
        }

        match crate::Header::parse("Name: Value;parameter=false\r\n".as_bytes()) {
            Ok((input, hdr)) => {
                assert_eq!(hdr.name, "Name");
                assert_eq!(hdr.value, "Value");
                assert_eq!(hdr.parameters.unwrap(), "parameter=false");
                assert_eq!(input.len(), 0);
            }
            Err(_e) => panic!(),
        }

        match crate::Header::parse("Max-Forwards: 70\r\n".as_bytes()) {
            Ok((input, hdr)) => {
                assert_eq!(hdr.name, "Max-Forwards");
                assert_eq!(hdr.value, "70");
                assert_eq!(input.len(), 0);
            }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn parse_headers_test() {
        let parse_headers_result = crate::parse_headers(
            "To: sip:user@example.com\r\n\
             From: caller<sip:caller@example.com>;tag=323\r\n\
             Max-Forwards: 70\r\n\
             Call-ID: lwsdisp.1234abcd@funky.example.com\r\n\
             CSeq: 60 OPTIONS\r\n\
             Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n\r\n"
                .as_bytes(),
        );

        match parse_headers_result {
            Ok((input, hdrs)) => {
                assert_eq!(hdrs.len(), 6);
                assert_eq!(hdrs[0].name, "To");
                assert_eq!(hdrs[0].value, "sip:user@example.com");

                assert_eq!(hdrs[1].name, "From");
                assert_eq!(hdrs[1].value, "caller<sip:caller@example.com>");
                assert_eq!(hdrs[1].parameters.unwrap(), "tag=323");

                assert_eq!(hdrs[2].name, "Max-Forwards");
                assert_eq!(hdrs[2].value, "70");
                assert_eq!(hdrs[2].parameters, None);

                assert_eq!(hdrs[3].name, "Call-ID");
                assert_eq!(hdrs[3].value, "lwsdisp.1234abcd@funky.example.com");
                assert_eq!(hdrs[3].parameters, None);

                assert_eq!(hdrs[4].name, "CSeq");
                assert_eq!(hdrs[4].value, "60 OPTIONS");
                assert_eq!(hdrs[4].parameters, None);

                assert_eq!(hdrs[5].name, "Via");
                assert_eq!(hdrs[5].value, "SIP/2.0/UDP funky.example.com");
                assert_eq!(hdrs[5].parameters.unwrap(), "branch=z9hG4bKkdjuw");
                assert_eq!(input, crate::header::CRLF); //
            }
            Err(_e) => panic!(),
        }
    }
}
