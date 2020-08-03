use crate::common::{
    bnfcore::is_alpha, errorparse::SipParseError, nom_wrappers::from_utf8_nom, sip_method::SipMethod,
};
use crate::headers::traits::SipHeaderParser;
use nom::bytes::complete::take_while1;

pub struct AllowHeader;
// Allow  =  "Allow" HCOLON [Method *(COMMA Method)]

impl SipHeaderParser for AllowHeader {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        let (input, value) = take_while1(is_alpha)(input)?;
        // TODO is create validatation without casting to string
        // and calling from_str method
        let (_, val_str) = from_utf8_nom(value)?;
        let res = SipMethod::from_str(val_str);
        if res.is_none() == true {
            return sip_parse_error!(1, "Invalid Method name");
        }
        Ok((input, value))
    }
}
#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn header_parse_test() {
        match AllowHeader::take_value(
            "INVITE\r\n".as_bytes(),
        ) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "INVITE".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
        match AllowHeader::take_value("UNKMETHOD\r\n".as_bytes()) {
            Ok((_, _)) => {
                panic!();
            }
            Err(_) => {}
        }
    }
}
