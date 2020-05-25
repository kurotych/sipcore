use crate::errorparse::SipParseError;
use core::str::from_utf8;
use nom;

pub fn from_utf8_nom(v: &[u8]) -> nom::IResult<&str, &str, SipParseError> {
    match from_utf8(v) {
        Ok(res_str) => Ok(("", res_str)),
        Err(_) => sip_parse_error!(1, "Error: from_utf8_nom failed"),
    }
}
