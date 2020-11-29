use crate::{SipHeader, SipHeaders, SipMessage, SipRFCHeader, SipRequest, SipResponse};

struct SipMsgSerializer {
    internal_buffer: [u8; 5000],
}

/*
https://tools.ietf.org/html/rfc3261#section-7.3.1
The relative order of header fields with different field names is not
   significant.  However, it is RECOMMENDED that header fields which are
   needed for proxy processing (Via, Route, Record-Route, Proxy-Require,
   Max-Forwards, and Proxy-Authorization, for example)
*/

// First element - highest priority
static PRIORITY_HEADERS: &'static [SipRFCHeader] = &[
    SipRFCHeader::Via,
    SipRFCHeader::Route,
    SipRFCHeader::RecordRoute,
    SipRFCHeader::MaxForwards,
    SipRFCHeader::ProxyRequire,
    SipRFCHeader::ProxyAuthorization,
];

/// The default maximum SIP message size on Cisco UCM Release 8.6.1
/// and earlier versions is 5000 bytes. The default on Cisco UCM Release 8.6.2
/// and later versions is 11000 bytes.
const MAX_SIP_MESSAGE_SIZE: usize = 5000;

impl SipMsgSerializer {
    pub fn new() -> SipMsgSerializer {
        let ib: [u8; MAX_SIP_MESSAGE_SIZE] = [0; MAX_SIP_MESSAGE_SIZE];
        SipMsgSerializer {
            internal_buffer: ib,
        }
    }
    fn append_data_to_ib(&mut self, offset: usize, src: &[u8]) -> usize /* count written data */ {
        let new_offset = offset + src.len();
        if new_offset > MAX_SIP_MESSAGE_SIZE {
            panic!("Internal buffer overflow. Sip message is too long");
        }
        &self.internal_buffer[offset..new_offset].copy_from_slice(src);
        return new_offset;
    }

    pub fn serialize_msg(&mut self, msg: &SipMessage) -> &[u8] {
        match msg {
            SipMessage::Request(r) => return self.serialize_req(r),
            SipMessage::Response(r) => return self.serialize_resp(r),
        };
    }

    pub fn serialize_req(&mut self, req: &SipRequest) -> &[u8] {
        let mut offset = self.append_data_to_ib(0, &req.rl.raw);
        offset = self.serialize_headers(&req.headers, offset);
        &self.internal_buffer[..offset]
    }

    pub fn serialize_resp(&mut self, resp: &SipResponse) -> &[u8] {
        let mut offset = self.append_data_to_ib(0, &resp.sl.raw);
        offset = self.serialize_headers(&resp.headers, offset);
        &self.internal_buffer[..offset]
    }

    fn serialize_header(&mut self, hdr: &SipHeader, buf_offset: usize) -> usize {
        let mut new_offset = self.append_data_to_ib(buf_offset, hdr.name.as_ref().as_bytes());
        new_offset = self.append_data_to_ib(new_offset, b": ");
        self.append_data_to_ib(new_offset, hdr.raw_value_param)
    }

    fn serialize_headers(&mut self, sip_headers: &SipHeaders, buf_offset: usize) -> usize {
        let mut new_offset = buf_offset;
        // STEP 1
        // Serialize RFC priority headers
        for hdr in PRIORITY_HEADERS {
            let hdrs = sip_headers.get_rfc(*hdr);
            if hdrs == None {
                continue;
            }
            for hdr in hdrs.unwrap() {
                new_offset = self.serialize_header(hdr, new_offset);
                new_offset = self.append_data_to_ib(new_offset, b"\r\n");
            }
        }
        // STEP 2
        // Serialize other RFC headers
        let other_rfs_headers_iter = sip_headers
            .get_rfc_headers_keys()
            .filter(|x| !PRIORITY_HEADERS.contains(x));
        for hdrs_iter in other_rfs_headers_iter {
            let hdrs = sip_headers.get_rfc(*hdrs_iter);
            for hdr in hdrs.unwrap() {
                new_offset = self.serialize_header(hdr, new_offset);
                new_offset = self.append_data_to_ib(new_offset, b"\r\n");
            }
        }
        // STEP 3
        // Serialize extention headers
        let ext_headers_iter = sip_headers.get_ext_headers_keys();
        match ext_headers_iter {
            Some(ext_hdrs) => {
                for header_name in ext_hdrs {
                    // One header name can contain multiple header value
                    let hdrs = sip_headers.get_ext(header_name).unwrap();
                    for hdr in hdrs {
                        new_offset = self.serialize_header(hdr, new_offset);
                        new_offset = self.append_data_to_ib(new_offset, b"\r\n");
                    }
                }
            }
            None => { /* There is no ext. headers. Do nothing */ }
        }

        // Mark and headers by double "\r\n\r\n"
        self.append_data_to_ib(new_offset, b"\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str;
    #[test]
    fn test_serializator_parse_resp() {
        let resp_msg_buf = "SIP/2.0 180 Ringing\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\n\
        To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
        From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        Contact: <sip:bob@192.0.2.4>\r\n\
        CSeq: 314159 INVITE\r\n\
        Content-Length: 0\r\n\r\n"
            .as_bytes();
        let (_, resp) = SipResponse::parse(resp_msg_buf).unwrap();
        let mut s = SipMsgSerializer::new();
        let serialized_buf = s.serialize_resp(&resp);

        let (_, msg2) = SipMessage::parse(serialized_buf).unwrap();
        let new_resp = msg2.response().unwrap();
        assert_eq!(new_resp.sl.raw, "SIP/2.0 180 Ringing\r\n".as_bytes());
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::Via)
                .unwrap()
                .raw_value_param,
            "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1".as_bytes()
        );
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::To)
                .unwrap()
                .raw_value_param,
            "Bob <sip:bob@biloxi.com>;tag=a6c85cf".as_bytes()
        );
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::From)
                .unwrap()
                .raw_value_param,
            "Alice <sip:alice@atlanta.com>;tag=1928301774".as_bytes()
        );
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::CallID)
                .unwrap()
                .raw_value_param,
            "a84b4c76e66710".as_bytes()
        );
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::Contact)
                .unwrap()
                .raw_value_param,
            "<sip:bob@192.0.2.4>".as_bytes()
        );
        assert_eq!(
            new_resp
                .headers
                .get_rfc_s(SipRFCHeader::CSeq)
                .unwrap()
                .raw_value_param,
            "314159 INVITE".as_bytes()
        );
    }
    #[test]
    fn test_serializator_req() {
        let invite_msg_buf = "INVITE sip:001234567890@10.135.0.1:5060;user=phone SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt;param1;param2=value2\r\n\
        Via: SIP/2.0/UDP 10.135.0.13:5060;branch=3dfdfd2asdasxccc\r\n\
        Max-Forwards: 70\r\n\
        From: \"Calling User\" <sip:151@10.135.0.1:5060;uriparam>;tag=m3l2hbp\r\n\
        To: <sip:001234567890@10.135.0.1:5060;user=phone>\r\n\
        Call-ID: ud04chatv9q@10.135.0.1\r\n\
        CSeq: 10691 INVITE\r\n\
        Contact: <sip:151@10.135.0.12;line=12071>;+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\"\r\n\
        Authorization: Digest username=\"bob\", realm=\"atlanta.example.com\"\
        ,nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", opaque=\"\" ,uri=\"sips:ss2.biloxi.example.com\"\r\n\
        User-Agent: Wildix W-AIR 03.55.00.24 9c7514340722\r\n\
        Allow: INVITE, CANCEL, BYE, ACK, REGISTER, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK, UPDATE\r\n\
        Content-Disposition: session\r\n\
        Supported: replaces,100rel\r\n\
        Content-Type: application/sdp\r\n\
        ExtensionHeader: value1;param\r\n\
        ExtensionHeader: value2;param1=value1\r\n\
        Content-Length: 0\r\n\r\n".as_bytes();

        let (_, msg) = SipMessage::parse(invite_msg_buf).unwrap();
        let mut s = SipMsgSerializer::new();
        let serialized_buf = s.serialize_msg(&msg);
        let (_, msg2) = SipMessage::parse(serialized_buf).unwrap();
        let new_req = msg2.request().unwrap();
        assert_eq!(
            new_req.rl.raw,
            "INVITE sip:001234567890@10.135.0.1:5060;user=phone SIP/2.0\r\n".as_bytes()
        );
        let vias = new_req.headers.get_rfc(SipRFCHeader::Via).unwrap();
        assert_eq!(
            vias[0].raw_value_param,
            "SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt;param1;param2=value2"
                .as_bytes()
        );
        assert_eq!(
            vias[1].raw_value_param,
            "SIP/2.0/UDP 10.135.0.13:5060;branch=3dfdfd2asdasxccc".as_bytes()
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::MaxForwards)
                .unwrap()
                .raw_value_param,
            "70".as_bytes()
        );
        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::From)
                .unwrap()
                .raw_value_param,
            "\"Calling User\" <sip:151@10.135.0.1:5060;uriparam>;tag=m3l2hbp".as_bytes()
        );
        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::To)
                .unwrap()
                .raw_value_param,
            "<sip:001234567890@10.135.0.1:5060;user=phone>".as_bytes()
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::CallID)
                .unwrap()
                .raw_value_param,
            "ud04chatv9q@10.135.0.1".as_bytes()
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::CSeq)
                .unwrap()
                .raw_value_param,
            "10691 INVITE".as_bytes()
        );

        assert_eq!(
            new_req.headers.get_rfc_s(SipRFCHeader::Contact).unwrap().raw_value_param,
            "<sip:151@10.135.0.12;line=12071>;+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\"".as_bytes()
        );

        assert_eq!(
            new_req.headers.get_rfc_s(SipRFCHeader::Authorization).unwrap().raw_value_param,
            "Digest username=\"bob\", realm=\"atlanta.example.com\"\
            ,nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\", opaque=\"\" ,uri=\"sips:ss2.biloxi.example.com\"".as_bytes()
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::UserAgent)
                .unwrap()
                .raw_value_param,
            "Wildix W-AIR 03.55.00.24 9c7514340722".as_bytes()
        );

        assert_eq!(
            new_req.headers.get_rfc(SipRFCHeader::Allow).unwrap().len(),
            13
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::ContentDisposition)
                .unwrap()
                .raw_value_param,
            "session".as_bytes()
        );

        assert_eq!(
            new_req.headers.get_rfc(SipRFCHeader::Supported).unwrap()[0].raw_value_param,
            b"replaces"
        );
        assert_eq!(
            new_req.headers.get_rfc(SipRFCHeader::Supported).unwrap()[1].raw_value_param,
            b"100rel"
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::ContentType)
                .unwrap()
                .raw_value_param,
            b"application/sdp"
        );

        assert_eq!(
            new_req
                .headers
                .get_rfc_s(SipRFCHeader::ContentLength)
                .unwrap()
                .raw_value_param,
            b"0"
        );

        let extension_headers = new_req.headers.get_ext("ExtensionHeader").unwrap();
        assert_eq!(extension_headers[0].raw_value_param, b"value1;param");
        assert_eq!(
            extension_headers[1].raw_value_param,
            b"value2;param1=value1"
        );
    }
}
