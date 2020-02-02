use crate::header::parse_headers;
use crate::header::Header;
use crate::message::SipVersion;

use core::str;
use nom::{
    bytes::complete::{tag, take, take_until},
    character::complete,
    sequence::tuple,
};

use alloc::vec::Vec;

pub struct Response<'a> {
    /// Status line. Ex: `SIP/2.0 401 Unauthorized`
    pub sl: StatusLine<'a>,

    /// The response headers.
    pub headers: Vec<Header<'a>>,
    /// Body
    pub body: Option<&'a [u8]>,
}

/// Ex: `SIP/2.0 401 Unauthorized`
pub struct StatusLine<'a> {
    pub sip_version: SipVersion,
    pub status_code: StatusCode,
    pub reason_phrase: &'a str,
}

impl<'a> StatusLine<'a> {
    pub fn parse(sl: &[u8]) -> nom::IResult<&[u8], StatusLine> {
        let (input, (_, major_version, _, minor_version, _, status_code, _, reason_phrase, _)) =
            tuple((
                tag("SIP/"),
                complete::digit1,
                complete::char('.'),
                complete::digit1,
                complete::space1,
                take(3usize),
                complete::space1,
                take_until("\r\n"),
                take(2usize), // skip /r/n
            ))(sl)?;

        let sip_version = SipVersion(
            u8::from_str_radix(str::from_utf8(major_version).unwrap(), 10).unwrap(),
            u8::from_str_radix(str::from_utf8(minor_version).unwrap(), 10).unwrap(),
        );

        let status_code = StatusCode::from_bytes_str(status_code);

        Ok((
            input,
            StatusLine {
                sip_version: sip_version,
                status_code: status_code,
                reason_phrase: unsafe { str::from_utf8_unchecked(reason_phrase) },
            },
        ))
    }
}

/// [rfc3261 section-7.2](https://tools.ietf.org/html/rfc3261#section-7.2)
impl<'a> Response<'a> {
    fn new(sl: StatusLine<'a>, headers: Vec<Header<'a>>, body: Option<&'a [u8]>) -> Response<'a> {
        Response {
            sl: sl,
            headers: headers,
            body: body,
        }
    }

    pub fn parse(buf_input: &'a [u8]) -> nom::IResult<&[u8], Response> {
        let (input, rl) = StatusLine::parse(buf_input)?;

        let (input, headers) = parse_headers(input)?;
        // TODO check header Content-Length and fix buf_input return
        let (body, _) = tag("\r\n")(input)?;

        Ok((buf_input, Response::new(rl, headers, Some(body))))
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum StatusCode {
    // Provisional 1xx
    Trying = 100,
    Ringing = 180,
    CallIsBeingForwarded = 181,
    Queued = 182,
    SessionProgress = 183,

    // Successful 2xx
    OK = 200,

    // Redirection 3xx
    MultipleChoices = 300,
    MovedPermanently = 301,
    MovedTemporarily = 302,
    UseProxy = 305,
    AlternativeService = 380,

    // Request Failure 4xx
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptableResourceContent = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Gone = 410,
    RequestEntityTooLarge = 413,
    RequestUriTooLong = 414,
    UnsupportedMediaType = 415,
    UnsupportedUriScheme = 416,
    BadExtension = 420,
    ExtensionRequired = 421,
    IntervalTooBrief = 423,
    TemporarilyUnavailable = 480,
    CallOrTransactionDoesNotExist = 481,
    LoopDetected = 482,
    TooManyHops = 483,
    AddressIncomplete = 484,
    Ambiguous = 485,
    BusyHere = 486,
    RequestTerminated = 487,
    NotAcceptableHere = 488,
    RequestPending = 491,
    Undecipherable = 493,

    // Server Failure 5xx
    ServerInternalError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    ServerTimeout = 504,
    VersionNotSupported = 505,
    MessageTooLarge = 513,

    // Global Failures 6xx
    BusyEverywhere = 600,
    Decline = 603,
    DoesNotExistAnywhere = 604,
    NotAcceptable = 606,

    // Unknown
    Unknown = 999,
}

const BS_100: &'static [u8] = "100".as_bytes();
const BS_180: &'static [u8] = "180".as_bytes();
const BS_181: &'static [u8] = "181".as_bytes();
const BS_182: &'static [u8] = "182".as_bytes();
const BS_183: &'static [u8] = "183".as_bytes();
const BS_200: &'static [u8] = "200".as_bytes();
const BS_300: &'static [u8] = "300".as_bytes();
const BS_301: &'static [u8] = "301".as_bytes();
const BS_302: &'static [u8] = "302".as_bytes();
const BS_305: &'static [u8] = "305".as_bytes();
const BS_380: &'static [u8] = "380".as_bytes();
const BS_400: &'static [u8] = "400".as_bytes();
const BS_401: &'static [u8] = "401".as_bytes();
const BS_402: &'static [u8] = "402".as_bytes();
const BS_403: &'static [u8] = "403".as_bytes();
const BS_404: &'static [u8] = "404".as_bytes();
const BS_405: &'static [u8] = "405".as_bytes();
const BS_406: &'static [u8] = "406".as_bytes();
const BS_407: &'static [u8] = "407".as_bytes();
const BS_408: &'static [u8] = "408".as_bytes();
const BS_410: &'static [u8] = "410".as_bytes();
const BS_413: &'static [u8] = "413".as_bytes();
const BS_414: &'static [u8] = "414".as_bytes();
const BS_415: &'static [u8] = "415".as_bytes();
const BS_416: &'static [u8] = "416".as_bytes();
const BS_420: &'static [u8] = "420".as_bytes();
const BS_421: &'static [u8] = "421".as_bytes();
const BS_423: &'static [u8] = "423".as_bytes();
const BS_480: &'static [u8] = "480".as_bytes();
const BS_481: &'static [u8] = "481".as_bytes();
const BS_482: &'static [u8] = "482".as_bytes();
const BS_483: &'static [u8] = "483".as_bytes();
const BS_484: &'static [u8] = "484".as_bytes();
const BS_485: &'static [u8] = "485".as_bytes();
const BS_486: &'static [u8] = "486".as_bytes();
const BS_487: &'static [u8] = "487".as_bytes();
const BS_488: &'static [u8] = "488".as_bytes();
const BS_491: &'static [u8] = "491".as_bytes();
const BS_493: &'static [u8] = "493".as_bytes();
const BS_500: &'static [u8] = "500".as_bytes();
const BS_501: &'static [u8] = "501".as_bytes();
const BS_502: &'static [u8] = "502".as_bytes();
const BS_503: &'static [u8] = "503".as_bytes();
const BS_504: &'static [u8] = "504".as_bytes();
const BS_505: &'static [u8] = "505".as_bytes();
const BS_513: &'static [u8] = "513".as_bytes();
const BS_600: &'static [u8] = "600".as_bytes();
const BS_603: &'static [u8] = "603".as_bytes();
const BS_604: &'static [u8] = "604".as_bytes();
const BS_606: &'static [u8] = "606".as_bytes();

impl StatusCode {
    pub fn from_str(s: &str) -> StatusCode {
        StatusCode::from_bytes_str(s.as_bytes())
    }

    pub fn from_bytes_str(s: &[u8]) -> StatusCode {
        match s {
            BS_100 => StatusCode::Trying,
            BS_180 => StatusCode::Ringing,
            BS_181 => StatusCode::CallIsBeingForwarded,
            BS_182 => StatusCode::Queued,
            BS_183 => StatusCode::SessionProgress,
            BS_200 => StatusCode::OK,
            BS_300 => StatusCode::MultipleChoices,
            BS_301 => StatusCode::MovedPermanently,
            BS_302 => StatusCode::MovedTemporarily,
            BS_305 => StatusCode::UseProxy,
            BS_380 => StatusCode::AlternativeService,
            BS_400 => StatusCode::BadRequest,
            BS_401 => StatusCode::Unauthorized,
            BS_402 => StatusCode::PaymentRequired,
            BS_403 => StatusCode::Forbidden,
            BS_404 => StatusCode::NotFound,
            BS_405 => StatusCode::MethodNotAllowed,
            BS_406 => StatusCode::NotAcceptableResourceContent,
            BS_407 => StatusCode::ProxyAuthenticationRequired,
            BS_408 => StatusCode::RequestTimeout,
            BS_410 => StatusCode::Gone,
            BS_413 => StatusCode::RequestEntityTooLarge,
            BS_414 => StatusCode::RequestUriTooLong,
            BS_415 => StatusCode::UnsupportedMediaType,
            BS_416 => StatusCode::UnsupportedUriScheme,
            BS_420 => StatusCode::BadExtension,
            BS_421 => StatusCode::ExtensionRequired,
            BS_423 => StatusCode::IntervalTooBrief,
            BS_480 => StatusCode::TemporarilyUnavailable,
            BS_481 => StatusCode::CallOrTransactionDoesNotExist,
            BS_482 => StatusCode::LoopDetected,
            BS_483 => StatusCode::TooManyHops,
            BS_484 => StatusCode::AddressIncomplete,
            BS_485 => StatusCode::Ambiguous,
            BS_486 => StatusCode::BusyHere,
            BS_487 => StatusCode::RequestTerminated,
            BS_488 => StatusCode::NotAcceptableHere,
            BS_491 => StatusCode::RequestPending,
            BS_493 => StatusCode::Undecipherable,
            BS_500 => StatusCode::ServerInternalError,
            BS_501 => StatusCode::NotImplemented,
            BS_502 => StatusCode::BadGateway,
            BS_503 => StatusCode::ServiceUnavailable,
            BS_504 => StatusCode::ServerTimeout,
            BS_505 => StatusCode::VersionNotSupported,
            BS_513 => StatusCode::MessageTooLarge,
            BS_600 => StatusCode::BusyEverywhere,
            BS_603 => StatusCode::Decline,
            BS_604 => StatusCode::DoesNotExistAnywhere,
            BS_606 => StatusCode::NotAcceptable,
            _ => StatusCode::Unknown,
        }
    }

    pub fn reason_phrase(&self) -> &str {
        match self {
            &StatusCode::Trying => "Trying",
            &StatusCode::Ringing => "Ringing",
            &StatusCode::CallIsBeingForwarded => "Call Is Being Forwarded",
            &StatusCode::Queued => "Queued",
            &StatusCode::SessionProgress => "Session Progress",
            &StatusCode::OK => "OK",
            &StatusCode::MultipleChoices => "Multiple Choices",
            &StatusCode::MovedPermanently => "Moved Permanently",
            &StatusCode::MovedTemporarily => "Moved Temporarily",
            &StatusCode::UseProxy => "Use Proxy",
            &StatusCode::AlternativeService => "Alternative Service",
            &StatusCode::BadRequest => "Bad Request",
            &StatusCode::Unauthorized => "Unauthorized",
            &StatusCode::PaymentRequired => "Payment Required",
            &StatusCode::Forbidden => "Forbidden",
            &StatusCode::NotFound => "Not Found",
            &StatusCode::MethodNotAllowed => "Method Not Allowed",
            &StatusCode::NotAcceptableResourceContent => "Not Acceptable",
            &StatusCode::ProxyAuthenticationRequired => "Proxy Authentication Required",
            &StatusCode::RequestTimeout => "Request Timeout",
            &StatusCode::Gone => "Gone",
            &StatusCode::RequestEntityTooLarge => "Request Entity Too Large",
            &StatusCode::RequestUriTooLong => "Request-URI Too Long",
            &StatusCode::UnsupportedMediaType => "Unsupported Media Type",
            &StatusCode::UnsupportedUriScheme => "Unsupported URI Scheme",
            &StatusCode::BadExtension => "Bad Extension",
            &StatusCode::ExtensionRequired => "Extension Required",
            &StatusCode::IntervalTooBrief => "Interval Too Brief",
            &StatusCode::TemporarilyUnavailable => "Temporarily Unavailable",
            &StatusCode::CallOrTransactionDoesNotExist => "Call/Transaction Does Not Exist",
            &StatusCode::LoopDetected => "Loop Detected",
            &StatusCode::TooManyHops => "Too Many Hops",
            &StatusCode::AddressIncomplete => "Address Incomplete",
            &StatusCode::Ambiguous => "Ambiguous",
            &StatusCode::BusyHere => "Busy Here",
            &StatusCode::RequestTerminated => "Request Terminated",
            &StatusCode::NotAcceptableHere => "Not Acceptable Here",
            &StatusCode::RequestPending => "Request Pending",
            &StatusCode::Undecipherable => "Undecipherable",
            &StatusCode::ServerInternalError => "Server Internal Error",
            &StatusCode::NotImplemented => "Not Implemented",
            &StatusCode::BadGateway => "Bad Gateway",
            &StatusCode::ServiceUnavailable => "Service Unavailable",
            &StatusCode::ServerTimeout => "Server Time-out",
            &StatusCode::VersionNotSupported => "Version Not Supported",
            &StatusCode::MessageTooLarge => "Message Too Large",
            &StatusCode::BusyEverywhere => "Busy Everywhere",
            &StatusCode::Decline => "Decline",
            &StatusCode::DoesNotExistAnywhere => "Does Not Exist Anywhere",
            &StatusCode::NotAcceptable => "Not Acceptable",
            &StatusCode::Unknown => "Unknown",
        }
    }
}
