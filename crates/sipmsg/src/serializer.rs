use crate::{SipHeader, SipHeaders, SipMessage, SipRFCHeader, SipRequest, SipResponse};

use core::str;

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

impl SipMsgSerializer {
    pub fn new() -> SipMsgSerializer {
        let ib: [u8; 5000] = [0; 5000];
        SipMsgSerializer {
            internal_buffer: ib,
        }
    }
    fn append_data_to_ib(&mut self, offset: usize, src: &[u8]) -> usize /* count written data */ {
        // TODO ADD CHECKING BUFF OVERFLOW
        let new_offset = offset + src.len();
        &self.internal_buffer[offset..new_offset].copy_from_slice(src);
        return new_offset;
    }

    pub fn serialize_msg(&mut self, msg: &SipMessage) -> &[u8] {
        let request = msg.request().unwrap();
        let mut offset = self.append_data_to_ib(0, &request.rl.raw);
        offset = self.serialize_headers(&request.headers, offset);
        &self.internal_buffer[..offset]
    }

    //  fn serialize_heder()
    pub fn serialize_req(&mut self, req: &SipRequest) -> &[u8] {
        panic!()
    }

    pub fn serialize_resp(&mut self, req: &SipResponse) -> &[u8] {
        panic!()
    }

    fn serialize_header(&mut self, hdr: &SipHeader, buf_offset: usize) -> usize {
        let mut new_offset = self.append_data_to_ib(buf_offset, hdr.name.as_ref().as_bytes());
        new_offset = self.append_data_to_ib(new_offset, b": ");
        new_offset = self.append_data_to_ib(new_offset, hdr.value.vstr.as_bytes());
        let params = hdr.params();
        if params == None {
            return new_offset;
        }
        let params = params.unwrap();
        let mut keys = params.keys();
        loop {
            let param_name = keys.next();
            if param_name == None {
                return new_offset;
            }
            new_offset = self.append_data_to_ib(new_offset, b";");
            new_offset = self.append_data_to_ib(new_offset, param_name.unwrap().as_bytes());
            let val = params.get(param_name.unwrap()).unwrap();
            if val != &None {
                // Parameter with value
                new_offset = self.append_data_to_ib(new_offset, b"=");
                new_offset = self.append_data_to_ib(new_offset, val.unwrap().as_bytes());
            }
        }
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
        self.append_data_to_ib(new_offset, b"\r\n")
    }
    // pub fn serialize_msg_a(msg: &SipMessage) -> &[u8] {
    //     let internal_buffer = [1,2,3];
    //     internal_buffer
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_serializator() {
        let invite_msg_buf = "INVITE sip:001234567890@10.135.0.1:5060;user=phone SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt;param1;param2=value2\r\n\
        Max-Forwards: 70\r\n\
        From: \"Calling User\" <sip:151@10.135.0.1:5060>;tag=m3l2hbp\r\n\
        To: <sip:001234567890@10.135.0.1:5060;user=phone>\r\n\
        Call-ID: ud04chatv9q@10.135.0.1\r\n\
        CSeq: 10691 INVITE\r\n\
        Contact: <sip:151@10.135.0.12;line=12071>;+sip.instance=\"<urn:uuid:0d9a008d-0355-0024-0004-000276f3d664>\"\r\n\
        User-Agent: Wildix W-AIR 03.55.00.24 9c7514340722\r\n\
        Allow: INVITE, CANCEL, BYE, ACK, REGISTER, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK, UPDATE\r\n\
        Content-Disposition: session\r\n\
        Supported: replaces,100rel\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 0\r\n\r\n".as_bytes();

        let (inp, msg) = SipMessage::parse(invite_msg_buf).unwrap();
        let mut s = SipMsgSerializer::new();
        let buf = s.serialize_msg(&msg);
        SipMessage::parse(buf).unwrap();
        //let buf = str::from_utf8(buf).unwrap();
        assert_eq!(
            str::from_utf8(buf).unwrap(),
            "INVITE sip:001234567890@10.135.0.1:5060;user=phone SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt;param1;param2=value2\r\n\
        Max-Forwards: 70\r\n"
        );
        // let mut dst = buf.to_vec();
        // dst[0] = 11;
    }
}
