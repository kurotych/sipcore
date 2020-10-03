use crate::{
    common::{
        bnfcore::is_token_char, errorparse::SipParseError, hostport::HostPort,
        nom_wrappers::take_lws, take_sws_token,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};

use nom::bytes::complete::take_while1;

// Via               =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
// via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
// via-params        =  via-ttl / via-maddr
//                      / via-received / via-branch
//                      / via-extension
// via-ttl           =  "ttl" EQUAL ttl
// via-maddr         =  "maddr" EQUAL host
// via-received      =  "received" EQUAL (IPv4address / IPv6address)
// via-branch        =  "branch" EQUAL token
// via-extension     =  generic-param
// sent-protocol     =  protocol-name SLASH protocol-version
//                      SLASH transport
// protocol-name     =  "SIP" / token
// protocol-version  =  token
// transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
//                      / other-transport
// sent-by           =  host [ COLON port ]
// ttl               =  1*3DIGIT ; 0 to 255
pub struct Via;

impl SipHeaderParser for Via {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, protocol_name) = take_while1(is_token_char)(source_input)?;
        let (input, _) = take_sws_token::slash(input)?;
        let (input, protocol_version) = take_while1(is_token_char)(input)?;
        let (input, _) = take_sws_token::slash(input)?;
        let (input, protocol_transport) = take_while1(is_token_char)(input)?;
        let (input, _) = take_lws(input)?;
        let (input, (host, port)) = HostPort::take_hostport(input)?;
        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::ProtocolName, protocol_name);
        tags.insert(HeaderTagType::ProtocolVersion, protocol_version);
        tags.insert(HeaderTagType::ProtocolTransport, protocol_transport);
        tags.insert(HeaderTagType::Host, host);
        if port != None {
            tags.insert(HeaderTagType::Port, port.unwrap());
        }

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len()],
            HeaderValueType::Via,
            Some(tags),
            None,
        )?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_via_value() {
        let (input, val) =
            Via::take_value("SIP/2.0/UDP bobspc.biloxi.com:5060;received=192.0.2.4\r\n".as_bytes())
                .unwrap();
        assert_eq!(val.vstr, "SIP/2.0/UDP bobspc.biloxi.com:5060");
        assert_eq!(input, b";received=192.0.2.4\r\n");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::ProtocolName], b"SIP");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::ProtocolVersion], b"2.0");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::ProtocolTransport],
            b"UDP"
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Host],
            b"bobspc.biloxi.com"
        );
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Port], b"5060");
    }
}
