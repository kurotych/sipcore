use crate::{
    common::{
        bnfcore::{is_alpha, is_lhex, is_token_char},
        errorparse::SipParseError,
        nom_wrappers::{take_qutoed_string, take_sws},
        take_sws_token,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use core::str::from_utf8;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::space1;
use unicase::Ascii;

// Authorization     =  "Authorization" HCOLON credentials
// credentials       =  ("Digest" LWS digest-response) / other-response
// other-response not supported
pub struct Authorization;

// tags: username / realm / nonce / digest-uri
//       / dresponse / algorithm / cnonce
//       / opaque / message-qop / nonce-count / auth-param

impl Authorization {
    fn val_to_tag(value: &[u8]) -> Option<HeaderTagType> {
        let val = from_utf8(value).unwrap();

        let aval = Ascii::new(val);
        macro_rules! match_str {
            ($input_str:expr, $enum_result:expr) => {
                if aval == $input_str {
                    return Some($enum_result);
                }
            };
        }
        match_str!("username", HeaderTagType::Username);
        match_str!("realm", HeaderTagType::Realm);
        match_str!("nonce", HeaderTagType::Nonce);
        match_str!("uri", HeaderTagType::DigestUri);
        match_str!("response", HeaderTagType::Dresponse);
        match_str!("algorithm", HeaderTagType::Algorithm);
        match_str!("cnonce", HeaderTagType::Cnonce);
        match_str!("opaque", HeaderTagType::Opaque);
        match_str!("qop", HeaderTagType::QopValue);
        match_str!("nc", HeaderTagType::NonceCount);
        None
    }
}

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
        let (input, _) = tag("Digest")(source_input)?;
        let (input, _) = space1(input)?; // LWS
        let mut tags = HeaderTags::new();
        let mut input_tmp = input;
        loop {
            let (input, value_type) = take_while(is_alpha)(input_tmp)?;
            let (input, _) = take_sws_token::equal(input)?;
            let tag_type = Authorization::val_to_tag(value_type);
            if tag_type.is_none() {
                return sip_parse_error!(1, "Authorization value name is invalid");
            }
            let tt = tag_type.unwrap();
            if tt == HeaderTagType::NonceCount {
                let (input, nc_val) = take_while(is_lhex)(input)?;
                if nc_val.len() != 8 {
                    return sip_parse_error!(2, "Invalid nonce len");
                }
                tags.insert(HeaderTagType::NonceCount, nc_val);
                input_tmp = input;
            } else if tt == HeaderTagType::QopValue || tt == HeaderTagType::Algorithm {
                let (input, val) = take_while(is_token_char)(input)?;
                tags.insert(tt, val);
                input_tmp = input;
            } else {
                let (input, val) = take_qutoed_string(input)?;
                tags.insert(tt, val);
                input_tmp = input;
            }
            let (input, _) = take_sws(input_tmp)?;
            if !input.is_empty() && input[0] == b',' {
                let (input, _) = take_sws_token::comma(input)?;
                input_tmp = input;
            } else {
                break;
            }
        }

        let hdr_len = source_input.len() - input_tmp.len();
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..hdr_len],
            HeaderValueType::AuthorizationDigest,
            Some(tags),
        )?;
        Ok((input_tmp, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn authorization_parser_test() {
        let val = Authorization::take_value(
            b"Digest username=\"bob\", \r\n realm=\"biloxi.com\",  nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\" , \r\n \
            \turi=\"sip:bob@biloxi.com\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
            response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"  \r\n"
        );
        let (input, val) = val.unwrap();
        assert_eq!(val.vstr, "Digest username=\"bob\", \r\n realm=\"biloxi.com\",  nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\" , \r\n \
        \turi=\"sip:bob@biloxi.com\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
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
