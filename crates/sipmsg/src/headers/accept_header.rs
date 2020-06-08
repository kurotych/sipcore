use crate::common::{
    bnfcore::{is_digit, is_token_char},
    errorparse::SipParseError,
    take_sws_token,
};
use crate::headers::traits::SipHeaderParser;
use nom::bytes::complete::take_while1;
use nom::sequence::tuple;

// Accept  =  "Accept" HCOLON [ accept-range *(COMMA accept-range) ]
// accept-range   =  media-range *(SEMI accept-param)
// media-range    =  ( "*/*"
//                 / ( m-type SLASH "*" )
//                 / ( m-type SLASH m-subtype )
// accept-param   =  ("q" EQUAL qvalue) / generic-param

pub struct AcceptHeader;

impl AcceptHeader {
    // qvalue         =  ( "0" [ "." 0*3DIGIT ] )
    //                   / ( "1" [ "." 0*3("0") ] )
    fn validate_q_param(qvalue: &str) -> bool {
        let mut bytes = qvalue.bytes();
        let next = bytes.next();
        if next == Some(b'1') {
            if bytes.next() != Some(b'.') {
                return false;
            }
            for val in bytes {
                if val != b'0' {
                    return false;
                }
            }
            return true;
        } else if next == Some(b'0') {
            if bytes.next() != Some(b'.') {
                return false;
            }

            for val in bytes {
                if !is_digit(val) {
                    return false;
                }
            }

            return true;
        }
        return false;
    }
}

impl SipHeaderParser for AcceptHeader {
    fn take_value(input: &[u8]) -> nom::IResult<&[u8], &[u8], SipParseError> {
        let (inp, (left_part, slash_part, right_part)) = tuple((
            take_while1(is_token_char),
            take_sws_token::slash,
            take_while1(is_token_char),
        ))(input)?;
        let offset = left_part.len() + slash_part.len() + right_part.len();
        Ok((inp, &input[..offset]))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /*
        For testing purpose:
        Accept: application/sdp, application/pkcs7-mime,
                multipart/mixed, multipart/signed,
                message/sip, message/sipfrag
        Accept: application/h.245;q=0.1, application/sdp;q=0.9
    */

    #[test]
    fn test_take_accept_value() {
        match AcceptHeader::take_value("application/sdp\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, "\r\n".as_bytes());
                assert_eq!(val, "application/sdp".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }

        match AcceptHeader::take_value("application/h.245;q=0.1\r\n".as_bytes()) {
            Ok((input, val)) => {
                assert_eq!(input, ";q=0.1\r\n".as_bytes());
                assert_eq!(val, "application/h.245".as_bytes());
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[test]
    fn test_validate_q_param() {
        assert_eq!(AcceptHeader::validate_q_param(""), false);
        assert_eq!(AcceptHeader::validate_q_param("1.1"), false);
        assert_eq!(AcceptHeader::validate_q_param("9"), false);
        assert_eq!(AcceptHeader::validate_q_param("00"), false);
        assert_eq!(AcceptHeader::validate_q_param("0.001"), true);
        assert_eq!(AcceptHeader::validate_q_param("0.01"), true);
        assert_eq!(AcceptHeader::validate_q_param("0.1"), true);
        assert_eq!(AcceptHeader::validate_q_param("0."), true);
        assert_eq!(AcceptHeader::validate_q_param("1."), true);
        assert_eq!(AcceptHeader::validate_q_param("1.000"), true);
    }
}
