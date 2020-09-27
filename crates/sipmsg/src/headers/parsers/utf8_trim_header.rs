use crate::{
    common::{bnfcore::is_wsp, errorparse::SipParseError, nom_wrappers::take_sws},
    headers::header::{HeaderValue, HeaderValueType},
};
use nom::bytes::complete::take_until;

pub fn take(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
    let mut tmp_input = source_input;
    loop {
        let (input, _) = take_until("\r\n")(tmp_input)?;
        if input.len() > 3 && is_wsp(input[2]) {
            let (input, _) = take_sws(input)?;
            tmp_input = input;
            continue;
        }
        tmp_input = input;
        break;
    }
    let (_, hdr_val) = HeaderValue::new(
        &source_input[..source_input.len() - tmp_input.len()],
        HeaderValueType::Utf8Text,
        None,
        None,
    )?;
    Ok((tmp_input, hdr_val))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_utf8text_value() {
        let (input, val) = take("Boxes by Bob\r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "Boxes by Bob");
        assert_eq!(input, b"\r\n");
        let (input, val) = take("Boxes by Bob\r\n nextline\r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "Boxes by Bob\r\n nextline");
        assert_eq!(input, b"\r\n");
    }
}
