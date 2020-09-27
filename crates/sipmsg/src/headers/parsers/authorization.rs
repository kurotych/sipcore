use crate::{
    common::errorparse::SipParseError,
    headers::{
        header::{HeaderValue, HeaderValueType},
        auth_params,
        traits::SipHeaderParser,
    },
};

// Authorization     =  "Authorization" HCOLON credentials
// credentials       =  ("Digest" LWS digest-response) / other-response
// other-response not supported
pub struct Authorization;

// tags: username / realm / nonce / digest-uri
//       / dresponse / algorithm / cnonce
//       / opaque / message-qop / nonce-count / auth-param

// Authorization: Digest username="bob",
// realm="biloxi.com",
// nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
// uri="sip:bob@biloxi.com",
// qop="auth",
// nc=00000001, 8LHEX
// cnonce="0a4f113b",
// response="6629fae49393a05397450978507c4ef1",
// opaque="5ccc069c403ebaf9f0171e9517f40e41"

impl SipHeaderParser for Authorization {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, (vstr, tags)) = auth_params::take(source_input)?;
        let (_, hdr_val) =
            HeaderValue::new(vstr, HeaderValueType::AuthorizationDigest, Some(tags), None)?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::headers::header::HeaderTagType;
    #[test]
    fn authorization_parser_test_unknown_schema() {
        let (input, val) =
            Authorization::take_value("NoOneKnowsThisScheme opaque-data=here\r\n".as_bytes())
                .unwrap();
        assert_eq!(val.vstr, "NoOneKnowsThisScheme opaque-data=here");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AuthSchema],
            b"NoOneKnowsThisScheme"
        );
        assert_eq!(input, b"\r\n");
    }

    #[test]
    fn authorization_parser_test() {
        let val = Authorization::take_value(
            b"Digest username=\"bob\", \r\n realm=\"biloxi.com\", unkownparam=value,  nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\" , \r\n \
            \turi=\"sip:bob@biloxi.com\", qop=auth, nc=00000001,unkownqparam=\"value\", cnonce=\"0a4f113b\", \
            response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"  \r\n"
        );
        let (input, val) = val.unwrap();
        assert_eq!(val.vstr, "Digest username=\"bob\", \r\n realm=\"biloxi.com\", unkownparam=value,  nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\" , \r\n \
        \turi=\"sip:bob@biloxi.com\", qop=auth, nc=00000001,unkownqparam=\"value\", cnonce=\"0a4f113b\", \
        response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"  ");
        assert_eq!(input, b"\r\n");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Username], b"bob");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Realm], b"biloxi.com");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::DigestUri],
            b"sip:bob@biloxi.com"
        );
        assert_eq!(val.tags().unwrap()[&HeaderTagType::QopValue], b"auth");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::NonceCount], b"00000001");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Cnonce], b"0a4f113b");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Dresponse],
            b"6629fae49393a05397450978507c4ef1"
        );
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::Opaque],
            b"5ccc069c403ebaf9f0171e9517f40e41"
        );
    }
}
