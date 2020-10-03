use crate::{
    common::{bnfcore::is_token_char, errorparse::SipParseError, nom_wrappers::take_quoted_string},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::{
    bytes::complete::take_while1,
    character::{complete::space1, is_digit},
};

// Warning        =  "Warning" HCOLON warning-value *(COMMA warning-value)
// warning-value  =  warn-code SP warn-agent SP warn-text
// warn-code      =  3DIGIT
// warn-agent     =  hostport / pseudonym
// warn-text      =  quoted-string
// pseudonym      =  token
pub struct Warning;

impl SipHeaderParser for Warning {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, warn_code) = take_while1(is_digit)(source_input)?;
        if warn_code.len() != 3 {
            return sip_parse_error!(1, "Invalid warning code");
        }
        let (input, _) = space1(input)?;
        let (input, warn_agent) = take_while1(is_token_char)(input)?;
        let (input, _) = space1(input)?;
        let (input, (_, warn_text, _)) = take_quoted_string(input)?;

        let mut tags = HeaderTags::new();
        tags.insert(HeaderTagType::WarnCode, warn_code);
        tags.insert(HeaderTagType::WarnAgent, warn_agent);
        tags.insert(HeaderTagType::WarnText, warn_text);

        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len()],
            HeaderValueType::Warning,
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
    fn test_warn_value() {
        let (input, val) =
            Warning::take_value("370 devnull \"Choose a bigger pipe\"\r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "370 devnull \"Choose a bigger pipe\"");
        assert_eq!(input, b"\r\n");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::WarnCode], b"370");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::WarnAgent], b"devnull");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::WarnText],
            b"Choose a bigger pipe"
        );

        let (input, val) = Warning::take_value(
            "307 isi.edu \"Session parameter 'foo' not understood\"\r\n".as_bytes(),
        )
        .unwrap();
        assert_eq!(input, b"\r\n");
        assert_eq!(
            val.vstr,
            "307 isi.edu \"Session parameter 'foo' not understood\""
        );
        assert_eq!(val.tags().unwrap()[&HeaderTagType::WarnCode], b"307");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::WarnAgent], b"isi.edu");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::WarnText],
            "Session parameter 'foo' not understood".as_bytes()
        );
    }
}
