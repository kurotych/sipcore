use nom::error::{ErrorKind, ParseError};
use core::convert::From;

#[derive(Debug)]
pub struct SipParseError<'a> {
    pub code: u32,
    pub message: Option<&'a str>,
}

impl<'a> From<(&'a str, ErrorKind)> for SipParseError<'a> {
    fn from(error: (&'a str, ErrorKind)) -> Self {
        SipParseError {
            code: error.1 as u32,
            message: Some(error.0)
        }
    }
}

impl<'a> ParseError<&'a str> for SipParseError<'a> {
    fn from_error_kind(error: &'a str, kind: ErrorKind) -> Self {
        SipParseError {
            code: kind as u32,
            message: Some(error)
        }
    }

    fn append(error: &'a str, kind: ErrorKind, _other: SipParseError) -> Self {
        SipParseError {
            code: kind as u32,
            message: Some(error)
        }
    }
}

impl<'a> SipParseError<'a> {
    pub fn new(code: u32, message: Option<&'a str>) -> SipParseError {
        SipParseError {
            code : code,
            message : message
        }
    }
}