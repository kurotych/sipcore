use crate::common::nom_wrappers::take_sws;
use crate::headers::header::HeaderTags;
use crate::{
    common::{bnfcore::is_token_char, errorparse::SipParseError, nom_wrappers, take_sws_token},
    headers::header::HeaderTagType,
};
use alloc::str::from_utf8;
use nom::bytes::complete::take_while1;
use unicase::Ascii;

pub fn param_name_to_tag(value: &[u8]) -> Option<HeaderTagType> {
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
    match_str!("domain", HeaderTagType::Domain);
    match_str!("stale", HeaderTagType::Stale);
    None
}

pub fn take<'a>(
    source_input: &'a [u8],
) -> nom::IResult<&[u8], (&[u8] /*vstr*/, HeaderTags<'a>), SipParseError> {
    let (input, auth_schema) = take_while1(is_token_char)(source_input)?;
    let mut tags = HeaderTags::new();
    tags.insert(HeaderTagType::AuthSchema, auth_schema);
    let (input, _) = take_sws(input)?; // LWS
    let mut input_tmp = input;
    // I use this value in end of fucntion. But compiler throw warning:
    // "value assigned to `count_wsps_after_last_value` is never read"
    // So, lets name it _* do supress warning
    let mut _count_wsps_after_last_value = 0;
    loop {
        let (input, param_name) = take_while1(is_token_char)(input_tmp)?;
        let (input, _) = take_sws_token::equal(input)?;

        let (input, (param_name, param_value)) = if input[0] == b'"' {
            let (input, (_, param_value, wsps)) = nom_wrappers::take_quoted_string(input)?;
            _count_wsps_after_last_value = wsps.len();
            (input, (param_name, param_value))
        } else {
            let (input, param_value) = take_while1(is_token_char)(input)?;
            _count_wsps_after_last_value = 0;
            (input, (param_name, param_value))
        };

        let tag_type = param_name_to_tag(param_name);
        if !tag_type.is_none() {
            let tt = tag_type.unwrap();
            if tt == HeaderTagType::NonceCount {
                if param_value.len() != 8 {
                    return sip_parse_error!(2, "Invalid nonce len");
                }
            }
            tags.insert(tt, param_value);
        }
        input_tmp = input;

        if !input.is_empty() && input[0] == b',' {
            let (input, _) = take_sws_token::comma(input)?;
            input_tmp = input;
        } else {
            break;
        }
    }
    let hdr_len = source_input.len() - input_tmp.len() - _count_wsps_after_last_value;
    Ok((input_tmp, (&source_input[..hdr_len], tags)))
}

// fn take_param(
//     input: &[u8],
// ) -> nom::IResult<
//     &[u8],
//     (
//         &[u8], /* param name */
//         &[u8], /* param_value without qoutes */
//     ),
//     SipParseError,
// > {
//     let (input, param_name) = take_while1(is_token_char)(input)?;
//     let (input, _) = take_sws_token::equal(input)?;
//     if input[0] == b'"' {
//         let (input, (_, param_value, _)) = nom_wrappers::take_quoted_string(input)?;
//         return Ok((input, (param_name, param_value)));
//     } else {
//         let (input, param_value) = take_while1(is_token_char)(input)?;
//         return Ok((input, (param_name, param_value)));
//     }
// }
