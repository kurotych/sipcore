use crate::{
    common::{bnfcore::is_token_char, errorparse::SipParseError, take_sws_token, nom_wrappers},
    headers::{
        header::{HeaderTagType, HeaderTags},
    },
};

use nom::{
    bytes::complete::{take_while1},
    character::complete,
    sequence::tuple,
};

use crate::SipUri;

#[derive(PartialEq, Debug)]
pub enum NameAddrValueType {
    QuotedDisplayName,
    TokenDisplayName,
    SipURI,
    AquoutedSipURI,
}

fn predict_value_type(input: &[u8]) -> NameAddrValueType {
    if input[0] == b'"' {
        return NameAddrValueType::QuotedDisplayName;
    }

    if input[0] == b'<' {
        return NameAddrValueType::AquoutedSipURI;
    }

    if &input[..3] != b"sip" {
        return NameAddrValueType::TokenDisplayName;
    }

    if input[3] == b':' || &input[3..5] == b"s:" {
        return NameAddrValueType::SipURI; // this is start of URI, display name isn't present
    }

    return NameAddrValueType::TokenDisplayName;
}

fn take_display_name(
    source_input: &[u8],
    display_name_type: NameAddrValueType,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    if display_name_type == NameAddrValueType::QuotedDisplayName {
        let (input, (_, display_name, _)) = nom_wrappers::take_quoted_string(source_input)?;
        return Ok((input, display_name));
    } else if display_name_type == NameAddrValueType::TokenDisplayName {
        let (input, display_name) = take_while1(is_token_char)(source_input)?;
        let (input, _) = complete::space0(input)?;
        return Ok((input, display_name));
    }
    sip_parse_error!(
        666,
        "Parsing of contact is failed. Something wrong we should never be here"
    )
}

pub fn take<'a>(
    source_input: &'a [u8],
) -> nom::IResult<&'a [u8], (&[u8], HeaderTags<'a>, Option<SipUri>), SipParseError<'a>> {
    if source_input.len() < 5 {
        return sip_parse_error!(2, "name-addr header value is too short");
    }
    let mut tags = HeaderTags::new();
    let next_value_type = predict_value_type(source_input);
    let input = if next_value_type == NameAddrValueType::QuotedDisplayName
        || next_value_type == NameAddrValueType::TokenDisplayName
    {
        let (input, display_name) = take_display_name(source_input, next_value_type)?;
        tags.insert(HeaderTagType::DisplayName, display_name);
        input
    } else {
        source_input
    };

    if input.is_empty() {
        return sip_parse_error!(3, "Contact header value is invalid");
    }

    let (input, is_quoted_uri) = if input[0] == b'<' {
        let (input, _) = take_sws_token::laquot(input)?;
        (input, true)
    } else {
        (input, false)
    };

    if source_input.len() < 5 {
        return sip_parse_error!(2, "Contact header value is too short");
    }

    let is_sip_uri = &input[..4] == b"sip:" || &input[..5] == b"sips:";
    if !is_sip_uri && !is_quoted_uri {
        return sip_parse_error!(4, "Absolute uri in contact header without <> not supported");
    }

    if is_sip_uri {
        let (input, sipuri) = SipUri::parse_ext(input, is_quoted_uri)?;
        let mut count_wsps_after_raquout = 0;
        let input = if is_quoted_uri {
            let (input, wsps_after) = take_sws_token::raquot(input)?;
            count_wsps_after_raquout = wsps_after.len();
            input
        } else {
            input
        };
        return Ok((
            input,
            (
                &source_input[..source_input.len() - input.len() - count_wsps_after_raquout],
                tags,
                Some(sipuri),
            ),
        ));
    }

    // this is absolute uri
    let uri_taker = take_while1(|c| c != b'>');
    let (input, (uri, spaces_after_raquot)) = tuple((uri_taker, take_sws_token::raquot))(input)?;
    tags.insert(HeaderTagType::AbsoluteURI, uri);

    Ok((
        input,
        (
            &source_input[..source_input.len() - input.len() - spaces_after_raquot.len()],
            tags,
            None,
        ),
    ))
}
