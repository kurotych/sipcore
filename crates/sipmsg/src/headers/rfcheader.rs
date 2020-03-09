use unicase::Ascii;

/// Headers that defined in rfc3261
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SipRFCHeader {
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    AlertInfo,
    Allow,
    AuthenticationInfo,
    Authorization,
    CallID,
    CallInfo,
    Contact,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentType,
    CSeq,
    Date,
    ErrorInfo,
    Expires,
    From,
    InReplyTo,
    MaxForwards,
    MimeVersion,
    MinExpires,
    Organization,
    Priority,
    ProxyAuthenticate,
    ProxyAuthorization,
    ProxyRequire,
    RecordRoute,
    ReplyTo,
    Require,
    RetryAfter,
    Route,
    Server,
    Subject,
    Supported,
    Timestamp,
    To,
    Unsupported,
    UserAgent,
    Via,
    Warning,
    WWWAuthenticate,
}

impl SipRFCHeader {
    /// Supports compact forms and case-insensitive
    pub fn from_str(s: &str) -> Option<SipRFCHeader> {
        let s = Ascii::new(s);
        macro_rules! match_str {
            // error with message
            ($input_str:expr, $enum_result:expr) => {
                if s == $input_str {
                    return Some($enum_result);
                }
            };
        }

        match_str!("Accept", SipRFCHeader::Accept);
        match_str!("Accept-Encoding", SipRFCHeader::AcceptEncoding);
        match_str!("Accept-Language", SipRFCHeader::AcceptLanguage);
        match_str!("Alert-Info", SipRFCHeader::AlertInfo);
        match_str!("Allow", SipRFCHeader::Allow);
        match_str!("Authentication-Info", SipRFCHeader::AuthenticationInfo);
        match_str!("Authorization", SipRFCHeader::Authorization);
        match_str!("Call-ID", SipRFCHeader::CallID);
        match_str!("i", SipRFCHeader::CallID);
        match_str!("Call-Info", SipRFCHeader::CallInfo);
        match_str!("Contact", SipRFCHeader::Contact);
        match_str!("m", SipRFCHeader::Contact);
        match_str!("Content-Disposition", SipRFCHeader::ContentDisposition);
        match_str!("Content-Encoding", SipRFCHeader::ContentEncoding);
        match_str!("e", SipRFCHeader::ContentEncoding);
        match_str!("Content-Language", SipRFCHeader::ContentLanguage);
        match_str!("Content-Length", SipRFCHeader::ContentLength);
        match_str!("l", SipRFCHeader::ContentLength);
        match_str!("Content-Type", SipRFCHeader::ContentType);
        match_str!("c", SipRFCHeader::ContentType);
        match_str!("CSeq", SipRFCHeader::CSeq);
        match_str!("Date", SipRFCHeader::Date);
        match_str!("Error-Info", SipRFCHeader::ErrorInfo);
        match_str!("Expires", SipRFCHeader::Expires);
        match_str!("From", SipRFCHeader::From);
        match_str!("f", SipRFCHeader::From);
        match_str!("In-Reply-To", SipRFCHeader::InReplyTo);
        match_str!("Max-Forwards", SipRFCHeader::MaxForwards);
        match_str!("MIME-Version", SipRFCHeader::MimeVersion);
        match_str!("Min-Expires", SipRFCHeader::MinExpires);
        match_str!("Organization", SipRFCHeader::Organization);
        match_str!("Priority", SipRFCHeader::Priority);
        match_str!("Proxy-Authenticate", SipRFCHeader::ProxyAuthenticate);
        match_str!("Proxy-Authorization", SipRFCHeader::ProxyAuthorization);
        match_str!("Proxy-Require", SipRFCHeader::ProxyRequire);
        match_str!("Record-Route", SipRFCHeader::RecordRoute);
        match_str!("Reply-To", SipRFCHeader::ReplyTo);
        match_str!("Require", SipRFCHeader::Require);
        match_str!("Retry-After", SipRFCHeader::RetryAfter);
        match_str!("Route", SipRFCHeader::Route);
        match_str!("Server", SipRFCHeader::Server);
        match_str!("Subject", SipRFCHeader::Subject);
        match_str!("s", SipRFCHeader::Subject);
        match_str!("Supported", SipRFCHeader::Supported);
        match_str!("k", SipRFCHeader::Supported);
        match_str!("Timestamp", SipRFCHeader::Timestamp);
        match_str!("To", SipRFCHeader::To);
        match_str!("t", SipRFCHeader::To);
        match_str!("Unsupported", SipRFCHeader::Unsupported);
        match_str!("User-Agent", SipRFCHeader::UserAgent);
        match_str!("Via", SipRFCHeader::Via);
        match_str!("v", SipRFCHeader::Via);
        match_str!("Warning", SipRFCHeader::Warning);
        match_str!("WWW-Authenticate", SipRFCHeader::WWWAuthenticate);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() {
        assert_eq!(SipRFCHeader::from_str("V").unwrap(), SipRFCHeader::Via);
        assert_eq!(
            SipRFCHeader::from_str("accept").unwrap(),
            SipRFCHeader::Accept
        );
        assert_eq!(
            SipRFCHeader::from_str("accept-encoding").unwrap(),
            SipRFCHeader::AcceptEncoding
        );

        assert_eq!(
            SipRFCHeader::from_str("l").unwrap(),
            SipRFCHeader::ContentLength
        );

        assert_eq!(SipRFCHeader::from_str("1"), None);
    }
}
