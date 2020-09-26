use crate::common::errorparse::SipParseError;
use crate::headers::{
    header::{HeaderValue, HeaderValueType},
    traits::SipHeaderParser,
};

use nom::{
    bytes::complete::{tag, take},
    character::complete::{char, digit1},
    sequence::tuple,
};

// Date          =  "Date" HCOLON SIP-date
// SIP-date      =  rfc1123-date
// rfc1123-date  =  wkday "," SP date1 SP time SP "GMT"
// date1         =  2DIGIT SP month SP 4DIGIT
//                  ; day month year (e.g., 02 Jun 1982)
// time          =  2DIGIT ":" 2DIGIT ":" 2DIGIT
//                  ; 00:00:00 - 23:59:59
// wkday         =  "Mon" / "Tue" / "Wed"
//                  / "Thu" / "Fri" / "Sat" / "Sun"
// month         =  "Jan" / "Feb" / "Mar" / "Apr"
//                  / "May" / "Jun" / "Jul" / "Aug"
//                  / "Sep" / "Oct" / "Nov" / "Dec"

/// Be careful. It is not a full validation of date.
pub struct Date;

impl Date {
    fn is_wkday(value_name: &[u8]) -> bool {
        match value_name {
            b"Mon" => return true,
            b"Tue" => true,
            b"Wed" => true,
            b"Thu" => true,
            b"Fri" => true,
            b"Sat" => true,
            b"Sun" => true,
            _ => return false,
        }
    }

    fn is_month(value_name: &[u8]) -> bool {
        match value_name {
            b"Jan" => return true,
            b"Feb" => true,
            b"Mar" => true,
            b"Apr" => true,
            b"May" => true,
            b"Jun" => true,
            b"Jul" => true,
            b"Aug" => true,
            b"Sep" => true,
            b"Oct" => true,
            b"Nov" => true,
            b"Dec" => true,
            _ => return false,
        }
    }
}

// Date: Sat, 13 Nov 2010 23:29:00 GMT

impl SipHeaderParser for Date {
    fn take_value(source_input: &[u8]) -> nom::IResult<&[u8], HeaderValue, SipParseError> {
        let (input, wday) = take(3usize)(source_input)?;
        if !Date::is_wkday(wday) {
            return sip_parse_error!(1, "Invalid wday value in Date header");
        }
        let (input, _) = tag(", ")(input)?;
        let (input, day) = digit1(input)?;
        if day.len() > 2 {
            return sip_parse_error!(1, "Invalid day value in Date header");
        }
        let (input, _) = char(' ')(input)?;

        let (input, month) = take(3usize)(input)?;
        if !Date::is_month(month) {
            return sip_parse_error!(2, "Invalid month value in Date header");
        }
        let (input, _) = char(' ')(input)?;
        let (input, year) = digit1(input)?;
        if year.len() != 4 {
            // time bomb :D
            return sip_parse_error!(3, "Invalid year value in Date header");
        }
        let (input, _) = char(' ')(input)?;
        let (input, (_hours, _, _mins, _, _seconds)) =
            tuple((digit1, char(':'), digit1, char(':'), digit1))(input)?;

        let (input, _) = char(' ')(input)?;
        let (input, _) = tag("GMT")(input)?;
        let (_, hdr_val) = HeaderValue::new(
            &source_input[..source_input.len() - input.len()],
            HeaderValueType::DateString,
            None,
            None,
        )?;
        Ok((input, hdr_val))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_date_value() {
        let (input, val) =
            Date::take_value("Sat, 13 Nov 2010 23:29:00 GMT \r\n".as_bytes()).unwrap();
        assert_eq!(val.vstr, "Sat, 13 Nov 2010 23:29:00 GMT");
        assert_eq!(input, b" \r\n");
    }
}
