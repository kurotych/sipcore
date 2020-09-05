use crate::{
    common::{
        bnfcore::is_alpha, errorparse::SipParseError, nom_wrappers::from_utf8_nom,
        sip_method::SipMethod,
    },
    headers::{
        header::{HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_while1;

/// Allow  =  "Allow" HCOLON [Method *(COMMA Method)]
pub struct AllowParser;

impl SipHeaderParser for AllowParser {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, value) = take_while1(is_alpha)(input)?;
        // TODO is create validatation without casting to string
        // and calling from_str method
        let (_, val_str) = from_utf8_nom(value)?;
        let res = SipMethod::from_str(val_str);
        if res.is_none() == true {
            return sip_parse_error!(1, "Invalid Method name");
        }
        let (_, hdr_val) = HeaderValue::new(value, HeaderValueType::SimpleString, None)?;
        Ok((input, hdr_val))
    }
}
#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn header_parse_test() {
        match AllowParser::take_value("INVITE\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val.vstr, "INVITE");
            }
            Err(_) => {
                panic!();
            }
        }
        match AllowParser::take_value("UNKMETHOD\r\n".as_bytes()) {
            Ok((_, _)) => {
                panic!();
            }
            Err(_) => {}
        }
    }
}
