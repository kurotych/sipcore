use crate::bnfcore::*;
use crate::errorparse::SipParseError;
use crate::traits::NomParser;
use core::str;
use nom::bytes::complete::{take, take_until, take_while1};

// domainlabel      =  alphanum / alphanum *( alphanum / "-" ) alphanum
// toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
// hostname         =  *( domainlabel "." ) toplabel [ "." ]
// host             =  hostname / IPv4address / IPv6reference
// hostport         =  host [ ":" port ]
pub struct HostPort<'a> {
    pub host: &'a str, // hostname / IPv4address / IPv6reference
    pub port: Option<u16>,
}

fn host_char_allowed(c: u8) -> bool {
    is_alphanum(c) || c == b'-' || c == b'.'
}

impl<'a> HostPort<'a> {
    fn take_ipv6_host(input: &'a [u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        let (input, _) = take(1usize)(input)?; // skip '['
        let (input, ipv6_host) = take_until("]")(input)?;
        let (input, _) = take(1usize)(input)?; // skip ']'
        Ok((input, ipv6_host))
    }
}

impl<'a> NomParser<'a> for HostPort<'a> {
    type ParseResult = HostPort<'a>;

    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], HostPort, SipParseError> {
        if input.is_empty() {
            return sip_parse_error!(1);
        }

        let (rest, host) = if input[0] != b'[' {
            take_while1(host_char_allowed)(input)?
        } else {
            HostPort::take_ipv6_host(input)?
        };
        if rest.len() == 0 || (rest.len() > 2 && rest[0] != b':') {
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
                    return sip_parse_error!(2);
                }
            },
            Err(_) => {
                return sip_parse_error!(3, "Convert bytes to utf8 is failed");
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
        host_port_test_case("[2001:db8::10]", "2001:db8::10", None, "");
        host_port_test_case("[2001:db8::10]:8080", "2001:db8::10", Some(8080), "");
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
        host_port_test_case(
            "[2001:db8::10]:8080;transport=tcp",
            "2001:db8::10",
            Some(8080),
            ";transport=tcp",
        );

    }
}
