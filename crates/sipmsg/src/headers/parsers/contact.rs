use crate::{
    common::{
        bnfcore::{is_token_char, is_wsp},
        errorparse::SipParseError,
        take_sws_token,
    },
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        traits::SipHeaderParser,
    },
};

use nom::{
    bytes::complete::{take_while, take_while1},
    character::complete,
    sequence::tuple,
};

use crate::SipUri;

/*
Contact        =  ("Contact" / "m" ) HCOLON
                  ( STAR / (contact-param *(COMMA contact-param)))
contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
display-name   =  *(token LWS)/ quoted-string

contact-params     =  c-p-q / c-p-expires
                      / contact-extension
c-p-q              =  "q" EQUAL qvalue
c-p-expires        =  "expires" EQUAL delta-seconds
contact-extension  =  generic-param
*/

// A Contact header field value can contain a display name, a URI with
// URI parameters, and header parameters.

/*
 Examples:
      Contact: "Mr. Watson" <sip:watson@worcester.bell-telephone.com>
         ;q=0.7; expires=3600,
         "Mr. Watson" <mailto:watson@bell-telephone.com> ;q=0.1
      m: <sips:bob@192.0.2.4>;expires=60
      Contact: <sip:carol@chicago.com>
      Contact: "" <sip:carol@chicago.com>
      Contact: <sip:151@10.135.0.12;line=12071>;+sip.instance="<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>"
      Contact: Caller <mailto:carol@chicago.com>
      Contact: A <mailto:carol@chicago.com>
      Contact: sip:j.user@host.company.com
      Contact: "Caller" <sip:caller@[2001:db8::20]>
      Contact: sip:+19725552222@gw1.example.net;unknownparam  -- header paramater
      Contact: <sip:+19725552222@gw1.example.net;unknownparam> -- url parameter
*/

pub struct Contact;

#[derive(PartialEq, Debug)]
enum ContactValueType {
    QuotedDisplayName,
    TokenDisplayName,
    SipURI,
    AquoutedSipURI,
}

fn predict_value_type(input: &[u8]) -> ContactValueType {
    if input[0] == b'"' {
        return ContactValueType::QuotedDisplayName;
    }

    if input[0] == b'<' {
        return ContactValueType::AquoutedSipURI;
    }

    if &input[..3] != b"sip" {
        return ContactValueType::TokenDisplayName;
    }

    if input[3] == b':' || &input[3..5] == b"s:" {
        return ContactValueType::SipURI; // this is start of URI, display name isn't present
    }

    return ContactValueType::TokenDisplayName;
}

fn take_display_name(
    source_input: &[u8],
    display_name_type: ContactValueType,
) -> nom::IResult<&[u8], &[u8], SipParseError> {
    if display_name_type == ContactValueType::QuotedDisplayName {
        let (input, _) = take_sws_token::ldquot(source_input)?;
        let (input, display_name) = take_while(|c: u8| c != b'"')(input)?;
        let (input, _) = take_sws_token::rdquot(input)?;
        return Ok((input, display_name));
    } else if display_name_type == ContactValueType::TokenDisplayName {
        let (input, display_name) = take_while1(is_token_char)(source_input)?;
        let (input, _) = complete::space0(input)?;
        return Ok((input, display_name));
    }
    sip_parse_error!(
        666,
        "Parsing of contact is failed. Something wrong we should never be here"
    )
}

fn make_star_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
    let mut tags = HeaderTags::new();
    tags.insert(HeaderTagType::Star, &source_input[..1]);
    let (input, _) = take_sws_token::star(source_input)?;
    let (_, hdr_val) = HeaderValue::new(
        &source_input[..1],
        HeaderValueType::Contact,
        Some(tags),
        None,
    )?;
    Ok((input, hdr_val))
}

impl SipHeaderParser for Contact {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        if source_input.is_empty() {
            return sip_parse_error!(1, "Contact header value is empty");
        }

        let mut tags = HeaderTags::new();
        if source_input[0] == b'*' {
            // This is: Contact: *\r\n
            return make_star_value(source_input);
        }

        if source_input.len() < 5 {
            return sip_parse_error!(2, "Contact header value is too short");
        }
        let next_value_type = predict_value_type(source_input);
        let input = if next_value_type == ContactValueType::QuotedDisplayName
            || next_value_type == ContactValueType::TokenDisplayName
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
                let (input, (_, _, wsps_after)) = take_sws_token::raquot(input)?;
                count_wsps_after_raquout = wsps_after.len();
                input
            } else {
                input
            };
            let (_, hdr_val) = HeaderValue::new(
                &source_input[..source_input.len() - input.len() - count_wsps_after_raquout],
                HeaderValueType::Contact,
                Some(tags),
                Some(sipuri),
            )?;
            return Ok((input, hdr_val));
        }

        // this is absolute uri
        let uri = take_while1(|c| !is_wsp(c) && c != b'>');
        let (input, (uri, _ /* RAQUOT */)) = tuple((uri, take_sws_token::raquot))(input)?;
        let (_, hdr_val) = HeaderValue::new(uri, HeaderValueType::Contact, Some(tags), None)?;
        return Ok((input, hdr_val));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::headers::sipuri;
    use unicase::Ascii;
    #[test]
    fn contact_parser_test() {
        let (_, val) = Contact::take_value("* \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::Star], b"*");

        let (input, val) = Contact::take_value(
            "\"Mr. Watson\"  <sip:watson@worcester.bell-telephone.com> ;q=0.7; expires=3600 \r\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::DisplayName],
            b"Mr. Watson"
        );
        assert_eq!(val.sip_uri().unwrap().scheme, sipuri::RequestUriScheme::SIP);
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "watson");
        assert_eq!(
            val.sip_uri().unwrap().hostport.host,
            "worcester.bell-telephone.com"
        );
        assert_eq!(
            val.vstr,
            "\"Mr. Watson\"  <sip:watson@worcester.bell-telephone.com>"
        );
        assert_eq!(input, b";q=0.7; expires=3600 \r\n");
        /*---------------------------------------------*/
        let (input, val) =
            Contact::take_value("< sips:bob@192.0.2.4  > ;expires=60 \r\n".as_bytes()).unwrap();
        assert_eq!(
            val.sip_uri().unwrap().scheme,
            sipuri::RequestUriScheme::SIPS
        );
        assert_eq!(val.tags().unwrap().get(&HeaderTagType::DisplayName), None);
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "bob");
        assert_eq!(val.vstr, "< sips:bob@192.0.2.4  >");
        assert_eq!(input, b";expires=60 \r\n");
        /*---------------------------------------------*/
        let (_, val) = Contact::take_value("\"\" <sip:carol@chicago.com> \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"");
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "carol");
        /*---------------------------------------------*/

        let (input, val) = Contact::take_value(
            "\"Mr. Watson\" <   sip:watson@worcester.bell-telephone.com  >  \r\n".as_bytes(),
        )
        .unwrap();

        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::DisplayName],
            b"Mr. Watson"
        );
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "watson");
        assert_eq!(
            val.sip_uri().unwrap().hostport.host,
            "worcester.bell-telephone.com"
        );
        assert_eq!(
            val.vstr,
            "\"Mr. Watson\" <   sip:watson@worcester.bell-telephone.com  >"
        );

        assert_eq!(input, b"\r\n");
        /*---------------------------------------------*/
        let (input, val) = Contact::take_value(
            "<sip:151@10.135.0.12;line=12071>;+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\" \r\n".as_bytes(),
        )
        .unwrap();
        assert_eq!(val.tags().unwrap().get(&HeaderTagType::DisplayName), None);
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "151");

        assert_eq!(
            val.sip_uri().unwrap().params().unwrap().get(&"line"),
            Some((&Ascii::new("line"), &Some("12071")))
        );
        assert_eq!(
            input,
            ";+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\" \r\n".as_bytes()
        );
        /*---------------------------------------------*/
        let (_, val) =
            Contact::take_value("Caller <mailto:carol@chicago.com> \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"Caller");
        assert_eq!(val.vstr, "mailto:carol@chicago.com");

        let (_, val) = Contact::take_value("A <sip:carol@chicago.com> \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"A");
        assert_eq!(val.sip_uri().unwrap().hostport.host, "chicago.com");
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "carol");
        /*---------------------------------------------*/
        let (_, val) = Contact::take_value("sip:j.user@host.company.com\r\n".as_bytes()).unwrap();
        assert_eq!(val.sip_uri().unwrap().scheme, sipuri::RequestUriScheme::SIP);
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "j.user");
        assert_eq!(val.sip_uri().unwrap().hostport.host, "host.company.com");
        /*---------------------------------------------*/
        let (inp, val) =
            Contact::take_value("\"Caller\" <sip:caller@[2001:db8::20]> \r\n".as_bytes()).unwrap();
        assert_eq!(val.sip_uri().unwrap().scheme, sipuri::RequestUriScheme::SIP);
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"Caller");
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "caller");
        assert_eq!(val.sip_uri().unwrap().hostport.host, "2001:db8::20");
        assert_eq!(inp, "\r\n".as_bytes());
        /*---------------------------------------------*/
        let (inp, val) =
            Contact::take_value("sip:+19725552222@gw1.example.net;unknownparam\r\n".as_bytes())
                .unwrap();
        assert_eq!(
            val.sip_uri().unwrap().user_info().unwrap().value,
            "+19725552222"
        );
        assert_eq!(val.sip_uri().unwrap().hostport.host, "gw1.example.net");
        assert_eq!(inp, ";unknownparam\r\n".as_bytes());
        /*---------------------------------------------*/
        let (inp, val) =
            Contact::take_value("<sip:+19725552222@gw1.example.net;unknownparam>\r\n".as_bytes())
                .unwrap();
        assert_eq!(
            val.sip_uri().unwrap().user_info().unwrap().value,
            "+19725552222"
        );
        assert_eq!(val.sip_uri().unwrap().hostport.host, "gw1.example.net");
        assert_eq!(
            val.sip_uri()
                .unwrap()
                .params()
                .unwrap()
                .get(&"unknownparam"),
            Some((&Ascii::new("unknownparam"), &None))
        );

        assert_eq!(inp, "\r\n".as_bytes());
    }
}
