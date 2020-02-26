#![no_std]

//! # Introduction
//!
//! Library for parsing/editing/constructing SIP requests and responses.
//!
//! This is the very first version where only simple parsing is support.
//!
//! ## Example
//! ```rust
//!
//! use sipmsg::*;
//!
//! let invite_msg_buf = "\
//! INVITE sip:bob@biloxi.com;user=phone?to=alice%40atlanta.com&priority=urgent SIP/2.0\r\n\
//! Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
//! Via: SIP/2.0/UDP 192.168.1.111\r\n\
//! To: Bob <sip:bob@biloxi.com>\r\n\
//! From: Alice <sip:alice@atlanta.com>;tag=88sja8x\r\n\
//! Max-Forwards: 70\r\n\
//! Call-ID: 987asjd97y7atg\r\n\
//! CSeq: 986759 INVITE\r\n\r\nbody_stuff"
//! .as_bytes();
//!
//! // First parameter not realized yet.
//! // It should consist be residue if Content-Length is less then actual body length.
//! let (_, request) = SipRequest::parse(invite_msg_buf).unwrap();
//! assert_eq!(request.rl.method, SipRequestMethod::INVITE);
//! assert_eq!(request.rl.sip_version, SipVersion(2, 0));
//!
//! // RURI
//! assert_eq!(request.rl.uri.scheme, SipRequestUriScheme::SIP);
//! assert_eq!(request.rl.uri.user_info().unwrap().value, "bob");
//! assert_eq!(request.rl.uri.hostport.host, "biloxi.com");
//! assert_eq!(request.rl.uri.params().unwrap().get(&"user"), Some(&"phone"));
//! assert_eq!(request.rl.uri.headers().unwrap().get(&"to"), Some(&"alice%40atlanta.com"));
//! assert_eq!(request.rl.uri.headers().unwrap().get(&"priority"), Some(&"urgent"));
//!
//! // Via Header
//! let via_headers = request.headers.get("via").unwrap(); // case insensitive
//! assert_eq!(via_headers[1].value, "SIP/2.0/UDP pc33.atlanta.com");
//! assert_eq!(via_headers[1].params().unwrap().get(&"branch"),  Some(&"z9hG4bKkjshdyff"));
//! assert_eq!(via_headers[0].value, "SIP/2.0/UDP 192.168.1.111");
//! 
//! assert_eq!(
//!     via_headers[1].params().unwrap().get(&"branch"),
//!     Some(&"z9hG4bKkjshdyff")
//! );
//!
//! assert_eq!(
//!     via_headers[1].params().unwrap().get(&"notExistParam"),
//!     None
//! );
//!
//! // Body
//! assert_eq!(request.body.unwrap(), "body_stuff".as_bytes());
//! ```
//!
extern crate alloc;
extern crate nom;

mod message;
pub use message::get_message_type as get_sip_message_type;
pub use message::MessageType as SipMessageType;
pub use message::SipVersion;

pub mod bnfcore;

#[macro_use]
mod errorparse;

mod hostport;
mod parameters;
mod parserhelpers;
mod userinfo;

mod header;
pub use header::Header as SipHeader;

mod request;
pub use request::Method as SipRequestMethod;
pub use request::Request as SipRequest;
pub use request::RequestLine as SipRequestLine;

mod response;
pub use response::Response as SipResponse;
pub use response::StatusCode as SipResponseStatusCode;
pub use response::StatusLine as SipResponseStatusLine;

mod traits;
pub use traits::NomParser as SipMessageParser;

mod sipuri;
pub use sipuri::RequestUriScheme as SipRequestUriScheme;
pub use sipuri::SipUri;

mod headers;
pub use headers::Headers as SipHeaders;
