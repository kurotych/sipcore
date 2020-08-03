use crate::{
    common::bnfcore::is_unreserved, common::hostport::HostPort,
    common::nom_wrappers::from_utf8_nom, common::nom_wrappers::take_while_with_escaped,
    common::traits::NomParser, errorparse::SipParseError, headers::GenericParams,
    userinfo::UserInfo,
};
use alloc::collections::btree_map::BTreeMap;
use nom::bytes::complete::{take, take_till, take_until};

use core::str;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum RequestUriScheme {
    SIP,
    SIPS,
}

impl RequestUriScheme {
    pub fn from_bytes(s: &[u8]) -> Result<RequestUriScheme, nom::Err<SipParseError>> {
        match s {
            b"sip" => Ok(Self::SIP),
            b"sips" => Ok(Self::SIPS),
            _ => sip_parse_error!(101, "Can't parse sipuri scheme"),
        }
    }
}

/// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
#[inline]
fn is_hnv_unreserved_char(c: u8) -> bool {
    c == b'[' || c == b']' || c == b'/' || c == b'?' || c == b':' || c == b'+' || c == b'$'
}

#[inline]
fn is_hnv_char(c: u8) -> bool {
    is_unreserved(c) || is_hnv_unreserved_char(c)
}

// header          =  hname "=" hvalue
// hname           =  1*( hnv-unreserved / unreserved / escaped )
// hvalue          =  *( hnv-unreserved / unreserved / escaped )
// headers         =  "?" header *( "&" header )
pub struct SipUriHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl<'a> SipUriHeader<'a> {
    fn parse_header(input: &[u8]) -> nom::IResult<&[u8], SipUriHeader, SipParseError> {
        let (input, hname) = take_while_with_escaped(input, is_hnv_char)?;
        if input.len() == 0 || input[0] != b'=' {
            let (_, hname_str) = from_utf8_nom(hname)?;
            return Ok((
                input,
                SipUriHeader {
                    name: hname_str,
                    value: "",
                },
            ));
        }

        let (input, _) = take(1usize)(input)?; // skip =

        let (input, hvalue) = take_while_with_escaped(input, is_hnv_char)?;
        let (_, hname_str) = from_utf8_nom(hname)?;
        let (_, hvalue_str) = from_utf8_nom(hvalue)?;
        Ok((
            input,
            SipUriHeader {
                name: hname_str,
                value: hvalue_str,
            },
        ))
    }
}

impl<'a> NomParser<'a> for SipUriHeader<'a> {
    type ParseResult = BTreeMap<&'a str, &'a str>;

    // Returns: headers =  "?" header *( "&" header )
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, c) = take(1usize)(input)?;
        if c[0] != b'?' {
            return sip_parse_error!(1, "The first character of headers must be '?'");
        }

        let mut result = BTreeMap::new();
        let mut inp2 = input;
        loop {
            let (input, sip_uri_header) = SipUriHeader::parse_header(inp2)?;
            result.insert(sip_uri_header.name, sip_uri_header.value);
            if input.len() == 0 || input[0] != b'&' {
                inp2 = input;
                break;
            }
            let (input, _) = take(1usize)(input)?;
            inp2 = input;
        }

        Ok((inp2, result))
    }
}

// URI  =  SIP-URI / SIPS-URI
// SIP-URI          =  "sip:" [ userinfo ] hostport
// uri-parameters [ headers ]
// SIPS-URI         =  "sips:" [ userinfo ] hostport
// uri-parameters [ headers ]
// userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
// hostport         =  host [ ":" port ]
/// Its general form, in the case of a SIP URI, is: sip:user:password@host:port;uri-parameters?headers
pub struct SipUri<'a> {
    pub scheme: RequestUriScheme,
    user_info: Option<UserInfo<'a>>,
    pub hostport: HostPort<'a>,
    // Temporary use parsing from generic-parameters.rs
    // TODO make according RFC
    parameters: Option<GenericParams<'a>>,
    headers: Option<BTreeMap<&'a str, &'a str>>,
}

impl<'a> SipUri<'a> {
    pub fn user_info(&self) -> Option<&UserInfo<'a>> {
        self.user_info.as_ref()
    }

    pub fn params(&self) -> Option<&GenericParams<'a>> {
        self.parameters.as_ref()
    }

    pub fn headers(&self) -> Option<&BTreeMap<&'a str, &'a str>> {
        self.headers.as_ref()
    }

    fn try_parse_params(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], Option<GenericParams<'a>>, SipParseError> {
        if input[0] != b';' {
            return Ok((input, None));
        }
        match GenericParams::parse(input) {
            Ok((input, params)) => {
                return Ok((input, Some(params)));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    fn try_parse_headers(
        input: &'a [u8],
    ) -> nom::IResult<&[u8], Option<BTreeMap<&'a str, &'a str>>, SipParseError> {
        if input[0] != b'?' {
            return Ok((input, None));
        }
        match SipUriHeader::parse(input) {
            Ok((input, headers)) => {
                return Ok((input, Some(headers)));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

impl<'a> NomParser<'a> for SipUri<'a> {
    type ParseResult = SipUri<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self::ParseResult, SipParseError> {
        let (input, uri_scheme) = take_until(":")(input)?;
        let (input, _) = take(1usize)(input)?; // skip ':'
        let scheme = RequestUriScheme::from_bytes(uri_scheme)?;
        let (right_with_ampersat, before_ampersat) = take_till(|c| c == b'@')(input)?;
        // If right_with_apersat is empty there is no user info
        let userinfo = if right_with_ampersat.is_empty() {
            None
        } else {
            Some(UserInfo::from_bytes(before_ampersat)?)
        };
        // if: right_with_apersat is empty we take whole string to further parsing
        // else: otherwise need to skip userinfo part
        let input = if right_with_ampersat.is_empty() {
            before_ampersat
        } else {
            &right_with_ampersat[1..] /* skip '@' */
        };

        let (input, hostport) = HostPort::parse(input)?;

        let (input, params) = if input.is_empty() {
            (input, None)
        } else {
            SipUri::try_parse_params(input)?
        };

        let (input, headers) = if input.is_empty() {
            (input, None)
        } else {
            SipUri::try_parse_headers(input)?
        };

        Ok((
            input,
            SipUri {
                scheme: scheme,
                user_info: userinfo,
                hostport: hostport,
                parameters: params,
                headers: headers,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicase::Ascii;

    #[test]
    fn test_sip_uri_parse() {
        let (rest, sip_uri) = SipUri::parse("sip:atlanta.com".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.hostport.host, "atlanta.com");

        let (rest, sip_uri) = SipUri::parse("sip:alice@atlanta.com".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.user_info().unwrap().value, "alice");
        assert_eq!(sip_uri.hostport.host, "atlanta.com");

        let (rest, sip_uri) =
            SipUri::parse("sip:alice:secretword@atlanta.com;transport=tcp".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.user_info().unwrap().value, "alice");
        assert_eq!(sip_uri.user_info().unwrap().password, Some("secretword"));
        assert_eq!(sip_uri.hostport.host, "atlanta.com");
        assert_eq!(sip_uri.hostport.port, None);
        assert_eq!(
            sip_uri.params().unwrap().get(&"transport"),
            Some((&Ascii::new("transport"), &Some("tcp")))
        );

        let (rest, sip_uri) =
            SipUri::parse("sip:+1-212-555-1212:1234@gateway.com;user=phone".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.user_info().unwrap().value, "+1-212-555-1212");
        assert_eq!(sip_uri.user_info().unwrap().password, Some("1234"));
        assert_eq!(sip_uri.hostport.host, "gateway.com");
        assert_eq!(sip_uri.hostport.port, None);
        assert_eq!(
            sip_uri.params().unwrap().get(&"user"),
            Some((&Ascii::new("user"), &Some("phone")))
        );

        let (rest, sip_uri) = SipUri::parse("sips:1212@gateway.com".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIPS);
        assert_eq!(sip_uri.user_info().unwrap().value, "1212");
        assert_eq!(sip_uri.hostport.host, "gateway.com");

        let (rest, sip_uri) = SipUri::parse("sip:alice@192.0.2.4:8888".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.user_info().unwrap().value, "alice");
        assert_eq!(sip_uri.hostport.host, "192.0.2.4");
        assert_eq!(sip_uri.hostport.port, Some(8888));

        let (rest, sip_uri) =
            SipUri::parse("sip:alice;day=tuesday@atlanta.com".as_bytes()).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.user_info().unwrap().value, "alice;day=tuesday");
        assert_eq!(sip_uri.hostport.host, "atlanta.com");

        let (rest, sip_uri) =
            SipUri::parse("sips:alice@atlanta.com?subject=project%20x&priority=urgent".as_bytes())
                .unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(
            sip_uri.headers().unwrap().get(&"subject"),
            Some(&"project%20x")
        );
        assert_eq!(sip_uri.headers().unwrap().get(&"priority"), Some(&"urgent"));
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIPS);
        assert_eq!(sip_uri.user_info().unwrap().value, "alice");
        assert_eq!(sip_uri.hostport.host, "atlanta.com");

        let (rest, sip_uri) =
            SipUri::parse("sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com".as_bytes())
                .unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(
            sip_uri.headers().unwrap().get(&"to"),
            Some(&"alice%40atlanta.com")
        );
        assert_eq!(
            sip_uri.params().unwrap().get(&"method"),
            Some((&Ascii::new("method"), &Some("REGISTER")))
        );
        assert_eq!(sip_uri.scheme, RequestUriScheme::SIP);
        assert_eq!(sip_uri.hostport.host, "atlanta.com");
        match sip_uri.user_info() {
            Some(_) => panic!(),
            None => {} // ok
        }
    }
}
