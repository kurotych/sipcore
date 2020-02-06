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
//! let invite_msg_buf = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
//! Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\r\n\
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
//!
//! // Via Header
//! assert_eq!(request.headers[0].name, "Via");
//! assert_eq!(request.headers[0].value, "SIP/2.0/UDP pc33.atlanta.com");
//!
//! assert_eq!(
//!     request.headers[0].params().unwrap().get(&"branch"),
//!     Some(&"z9hG4bKkjshdyff")
//! );
//!
//! assert_eq!(
//!     request.headers[0].params().unwrap().get(&"notExistParam"),
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
pub use header::parse_headers as parse_sip_headers;
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
