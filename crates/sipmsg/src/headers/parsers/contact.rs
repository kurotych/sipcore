use crate::{
    common::{errorparse::SipParseError, take_sws_token},
    headers::{
        header::{HeaderTagType, HeaderTags, HeaderValue, HeaderValueType},
        name_addr,
        traits::SipHeaderParser,
    },
};

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

        if source_input[0] == b'*' {
            // This is: Contact: *\r\n
            return make_star_value(source_input);
        }
        let (input, (vstr_val, tags, sipuri)) = name_addr::take(source_input)?;
        let (_, hdr_val) =
            HeaderValue::new(vstr_val, HeaderValueType::Contact, Some(tags), sipuri)?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::headers::sipuri;
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
            Contact::take_value("<sips:bob@192.0.2.4> ;expires=60 \r\n".as_bytes()).unwrap();
        assert_eq!(
            val.sip_uri().unwrap().scheme,
            sipuri::RequestUriScheme::SIPS
        );
        assert_eq!(val.tags().unwrap().get(&HeaderTagType::DisplayName), None);
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "bob");
        assert_eq!(val.vstr, "<sips:bob@192.0.2.4>");
        assert_eq!(input, b";expires=60 \r\n");
        /*---------------------------------------------*/
        let (_, val) = Contact::take_value("\"\" <sip:carol@chicago.com> \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"");
        assert_eq!(val.sip_uri().unwrap().user_info().unwrap().value, "carol");
        /*---------------------------------------------*/

        let (input, val) = Contact::take_value(
            "\"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>  \r\n".as_bytes(),
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
            "\"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>"
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
            Some(&Some("12071"))
        );
        assert_eq!(
            input,
            ";+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\" \r\n".as_bytes()
        );
        /*---------------------------------------------*/
        let (_, val) =
            Contact::take_value("Caller <mailto:carol@chicago.com> \r\n".as_bytes()).unwrap();
        assert_eq!(val.tags().unwrap()[&HeaderTagType::DisplayName], b"Caller");
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AbsoluteURI],
            "mailto:carol@chicago.com".as_bytes()
        );
        assert_eq!(val.vstr, "Caller <mailto:carol@chicago.com>");

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
            Some(&None)
        );

        assert_eq!(inp, "\r\n".as_bytes());
        /************************************************/
        let (inp, val) =
            Contact::take_value("<http://www.example.com/sounds/moo.wav>  ;param\r\n".as_bytes())
                .unwrap();
        assert_eq!(
            val.tags().unwrap()[&HeaderTagType::AbsoluteURI],
            "http://www.example.com/sounds/moo.wav".as_bytes()
        );
        assert_eq!(val.vstr, "<http://www.example.com/sounds/moo.wav>");
        assert_eq!(inp, ";param\r\n".as_bytes());
    }
}
