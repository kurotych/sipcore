use crate::bnfcore::is_alphanum;
use crate::bnfcore::is_digit;
use crate::errorparse::SipParseError;
use crate::traits::NomParser;
use core::str;

use nom::{bytes::complete::take_while1, Err::Error};

// domainlabel      =  alphanum / alphanum *( alphanum / "-" ) alphanum
// toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
// hostname         =  *( domainlabel "." ) toplabel [ "." ]
// host             =  hostname / IPv4address / IPv6reference
// hostport         =  host [ ":" port ]
pub struct HostPort<'a> {
    pub host: &'a str, // hostname / IPv4address / IPv6reference
    pub port: Option<u16>,
}

fn is_alphanum_or_hyphen(c: u8) -> bool {
    is_alphanum(c) || c == b'-' || c == b'.'
}

impl<'a> NomParser<'a> for HostPort<'a> {
    type ParseResult = HostPort<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], HostPort, SipParseError> {
        let (rest, host) = take_while1(is_alphanum_or_hyphen)(input)?;

        if rest.len() == 0 || rest.len() > 2 && rest[0] != b':' {
            return Ok((
                rest,
                HostPort {
                    host: unsafe { str::from_utf8_unchecked(host) },
                    port: None,
                },
            ));
        }

        let (rest, port_str) = take_while1(is_digit)(&rest[1..])?;

        match str::from_utf8(port_str) {
            Ok(port_str) => match u16::from_str_radix(port_str, 10) {
                Ok(port) => {
                    return Ok((
                        rest,
                        HostPort {
                            host: unsafe { str::from_utf8_unchecked(host) },
                            port: Some(port),
                        },
                    ));
                }
                Err(_) => {
                    return Err(Error(SipParseError::new(
                        2,
                        Some("Convert str to port is failed"),
                    )));
                }
            },
            Err(_) => {
                return Err(Error(SipParseError::new(
                    3,
                    Some("Convert bytes to utf8 is failed"),
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_port_test_case(
        input: &str,
        expected_host: &str,
        expected_port: Option<u16>,
        expected_rest: &str,
    ) {
        let (rest, hostport) = HostPort::parse(input.as_bytes()).unwrap();
        assert_eq!(rest, expected_rest.as_bytes());
        assert_eq!(hostport.host, expected_host);
        assert_eq!(hostport.port, expected_port);
    }

    #[test]
    fn host_parse_simple() {
        host_port_test_case("127.0.0.1", "127.0.0.1", None, "");
        host_port_test_case("127.0.0.1:8080", "127.0.0.1", Some(8080), "");
        host_port_test_case("google.com", "google.com", None, "");
    }

    #[test]
    fn host_parse_with_rest() {
        host_port_test_case(
            "atlanta.com;transport=tcp",
            "atlanta.com",
            None,
            ";transport=tcp",
        );
        host_port_test_case(
            "123.222.111.222:8081;transport=tcp",
            "123.222.111.222",
            Some(8081),
            ";transport=tcp",
        );
        host_port_test_case(
            "atlanta.com:80?subject=project%20x&priority=urgent",
            "atlanta.com",
            Some(80),
            "?subject=project%20x&priority=urgent",
        );
    }
}
