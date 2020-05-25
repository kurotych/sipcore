use core::convert::From;
use core::str;
use nom;
use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub struct SipParseError<'a> {
    pub code: u32,
    pub message: Option<&'a str>,
}

impl<'a> From<(&'a str, ErrorKind)> for SipParseError<'a> {
    fn from(error: (&'a str, ErrorKind)) -> Self {
        SipParseError {
            code: error.1 as u32,
            message: Some(error.0),
        }
    }
}

impl<'a> ParseError<&'a str> for SipParseError<'a> {
    fn from_error_kind(error: &'a str, kind: ErrorKind) -> Self {
        SipParseError {
            code: kind as u32,
            message: Some(error),
        }
    }

    fn append(error: &'a str, kind: ErrorKind, _other: SipParseError) -> Self {
        SipParseError {
            code: kind as u32,
            message: Some(error),
        }
    }
}

#[macro_export]
macro_rules! sip_parse_error {
    // error with message
    ($error_code:expr) => {
        Err(nom::Err::Error(SipParseError::new($error_code, None)))
    };

    // error without message
    ($error_code:expr, $message:expr) => {
        Err(nom::Err::Error(SipParseError::new(
            $error_code,
            Some($message),
        )))
    };
}

impl<'a> SipParseError<'a> {
    pub fn new(code: u32, message: Option<&'a str>) -> SipParseError {
        SipParseError {
            code: code,
            message: message,
        }
    }
}

impl<'a> ParseError<&'a [u8]> for SipParseError<'a> {
    fn from_error_kind(error: &'a [u8], kind: ErrorKind) -> Self {
        let error_str: &str;
        match str::from_utf8(error) {
            Ok(err_str) => {
                error_str = err_str;
            }
            Err(_) => {
                error_str = "Internal error of parser. Can't cast error string to to utf8";
            }
        }
        SipParseError {
            code: kind as u32,
            message: Some(error_str),
        }
    }

    fn append(error: &'a [u8], kind: ErrorKind, _other: SipParseError) -> Self {
        let error_str: &str;
        match str::from_utf8(error) {
            Ok(err_str) => {
                error_str = err_str;
            }
            Err(_) => {
                error_str = "Internal error of parser. Can't cast error string to to utf8";
            }
        }
        SipParseError {
            code: kind as u32,
            message: Some(error_str),
        }
    }
}
