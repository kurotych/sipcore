use crate::{
    common::{
        bnfcore::{is_crlf, is_digit},
        errorparse::SipParseError,
        nom_wrappers::take_sws,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};
use nom::bytes::complete::take_while1;

pub struct Timestamp;

impl SipHeaderParser for Timestamp {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, _int_part_time) = take_while1(is_digit)(source_input)?;
        if input.is_empty() {
            return sip_parse_error!(1, "Invalid Timestamp Header");
        }
        let mut tags = HeaderTags::new();

        let input = if input[0] == b'.' {
            let (input, _) = take_while1(is_digit)(&input[1..])?; // take fractional_part_time
            input
        } else {
            input
        };
        tags.insert(
            HeaderTagType::TimveVal,
            &source_input[..source_input.len() - input.len()],
        );
        let (start_possible_delay_val, _) = take_sws(input)?;
        let mut tmp_inp = start_possible_delay_val;
        if !is_crlf(input) {
            let (input, _) = take_while1(is_digit)(tmp_inp)?;
            if !input.is_empty() && input[0] == b'.' {
                let (input, _) = take_while1(is_digit)(&input[1..])?;
                tmp_inp = input;
            } else {
                tmp_inp = input;
            }
            tags.insert(
                HeaderTagType::Delay,
                &start_possible_delay_val[..start_possible_delay_val.len() - tmp_inp.len()],
            );
        };
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - tmp_inp.len()],
            HeaderValueType::Timestamp,
            Some(tags),
            None,
        )?;
        Ok((tmp_inp, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_timestamp_value() {
        let (input, val) = Timestamp::take_value(b"1.2\r\n").unwrap();
        assert_eq!(input, b"\r\n");
        assert_eq!(val.vstr, "1.2");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::TimveVal],
            "1.2".as_bytes()
        );
        let (input, val) = Timestamp::take_value(b"12.34 0.5\r\n").unwrap();
        assert_eq!(input, b"\r\n");
        assert_eq!(val.vstr, "12.34 0.5");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::TimveVal], b"12.34");
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Delay], b"0.5");
    }
}
