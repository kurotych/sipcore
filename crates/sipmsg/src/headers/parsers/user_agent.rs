use crate::{
    common::{
        bnfcore::{is_crlf, is_token_char},
        errorparse::SipParseError,
        nom_wrappers::take_sws,
        take_sws_token,
    },
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::{take_until, take_while1};

// User-Agent  =  "User-Agent" HCOLON server-val *(LWS server-val)
// server-val       =  product / comment
// product          =  token [SLASH product-version]
// product-version  =  token
pub struct UserAgent;

impl SipHeaderParser for UserAgent {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let mut tmp_input = source_input;
        loop {
            if tmp_input.len() < 2 || is_crlf(tmp_input) {
                break;
            }

            if tmp_input[0] == b'(' {
                let (input, _) = take_sws_token::lparen(tmp_input)?;
                let (input, _) = take_until(")")(input)?;
                let (input, _) = take_sws_token::rparen(input)?;
                tmp_input = input;
                continue;
            }

            if tmp_input[0] == b'/' {
                let (input, _) = take_sws_token::slash(tmp_input)?;
                let (input, _) = take_while1(is_token_char)(input)?;
                let (input, _) = take_sws(input)?;
                tmp_input = input;
                continue;
            }

            let (input, _) = take_while1(is_token_char)(tmp_input)?;
            let (input, _) = take_sws(input)?;
            tmp_input = input;
        }

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - tmp_input.len()],
            HeaderValueType::UserAgent,
            None,
            None,
        )?;
        Ok((tmp_input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_server_value() {
        let (input, val) = UserAgent::take_value("HomeServer v2\r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "HomeServer v2");
        assert_eq!(input, b"\r\n");
    }
}
