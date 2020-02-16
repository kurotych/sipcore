use crate::bnfcore::*;
use crate::errorparse::SipParseError;
use crate::parserhelpers::*;
use core::str;

/// userinfo =  ( user / telephone-subscriber ) [ ":" password ] "@"
/// user     =  1*( unreserved / escaped / user-unreserved )
pub struct UserInfo<'a> {
    pub value: &'a str, // ( user / telephone-subscriber )
    pub password: Option<&'a str>,
    // TODO add boolean or enum about detect is it user or telefon-subscriber
}

#[inline]
fn is_userinfo_char(c: u8) -> bool {
    is_unreserved(c) || is_user_unreserved_char(c)
}

impl<'a> UserInfo<'a> {
    fn take_user(input: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8], SipParseError> {
        take_while_with_escaped(input, is_userinfo_char)
    }

    fn take_password(input: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8], SipParseError> {
        take_while_with_escaped(input, is_password_char)
    }

    pub fn from_bytes(input: &'a [u8]) -> Result<UserInfo, nom::Err<SipParseError>> {
        if input.len() <= 1 {
            return sip_parse_error!(1);
        }

        if !is_userinfo_char(input[0]) {
            return sip_parse_error!(2);
        }

        let (input, user) = UserInfo::take_user(input)?;
        if input.len() == 0 || (input.len() == 1 && input[0] == b'@') {
            return Ok(UserInfo {
                value: unsafe { str::from_utf8_unchecked(user) },
                password: None,
            });
        } else {
            if input[0] != b':' || input.len() == 2 {
                // input.len() == 2 it is ":@" ( emptypass )
                return sip_parse_error!(3, "Empty password");
            }

            let (_, pswd) = UserInfo::take_password(&input[1..])?;
            return Ok(UserInfo {
                value: unsafe { str::from_utf8_unchecked(user) },
                password: unsafe { Some(str::from_utf8_unchecked(pswd)) },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_take_user() {
        match UserInfo::take_user("alice@".as_bytes()) {
            Ok((input, user)) => {
                assert_eq!(input, "@".as_bytes());
                assert_eq!(user, "alice".as_bytes());
            }
            Err(_) => panic!(),
        }

        match UserInfo::take_user("bob:secretword@".as_bytes()) {
            Ok((input, user)) => {
                assert_eq!(input, ":secretword@".as_bytes());
                assert_eq!(user, "bob".as_bytes());
            }
            Err(_) => panic!(),
        }
    }

    fn parse_should_fail(input: &str) {
        match UserInfo::from_bytes(input.as_bytes()) {
            Ok(_) => {
                panic!();
            }
            Err(_) => {}
        }
    }

    fn test_case_from_bytes(input: &str, expexted_value: &str, expected_password: Option<&str>) {
        match UserInfo::from_bytes(input.as_bytes()) {
            Ok(userinfo) => {
                assert_eq!(userinfo.value, expexted_value);
                assert_eq!(userinfo.password, expected_password);
            }
            Err(_) => panic!(),
        }
    }
    #[test]
    fn user_info_from_bytes() {
        test_case_from_bytes("alice@", "alice", None);
        test_case_from_bytes("alice:secretword@", "alice", Some("secretword"));
        test_case_from_bytes("+1-212-555-1212:1234@", "+1-212-555-1212", Some("1234"));
        test_case_from_bytes("a:b@", "a", Some("b"));
        test_case_from_bytes("a@", "a", None);

        parse_should_fail("alice:@");
        parse_should_fail(":@");
        parse_should_fail(":a@");
        parse_should_fail("@");
        parse_should_fail("");
    }
}
