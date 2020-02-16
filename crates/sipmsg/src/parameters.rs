// TODO remove this shit
// And make parsing parameters according to RFC
use crate::errorparse::SipParseError;
use crate::traits::NomParser;
use alloc::collections::btree_map::BTreeMap;
use core::str;

// TODO strict parsing according description below
// generic-param  =  token [ EQUAL gen-value ]
pub struct Parameters;

impl<'a> NomParser<'a> for Parameters {
    type ParseResult = BTreeMap<&'a str, &'a str>;
    // Retuns pointer to char after terminated char.
    fn parse(input: &[u8]) -> nom::IResult<&[u8], BTreeMap<&str, &str>, SipParseError> {
        if input.is_empty() {
            return sip_parse_error!(1, "Empty input");
        }
        let mut result = BTreeMap::new();
        #[derive(PartialEq)]
        enum ParamState {
            Name,
            Value,
        };
        let mut start_idx = 0;
        let mut idx = 0;
        let mut name: &str = "";
        let mut value: &str = "";
        macro_rules! insert_param {
            ( ) => {
                result.insert(name, value);
                name = "";
                value = "";
            };
        };
        macro_rules! buf_to_string {
            () => {
                unsafe { str::from_utf8_unchecked(&input[start_idx..idx]) }
            };
        };
        let mut state = ParamState::Name;
        while idx < input.len() {
            match input[idx] {
                b';' => {
                    if state == ParamState::Value {
                        value = buf_to_string!();
                    } else {
                        name = buf_to_string!();
                    }
                    insert_param!();
                    if idx == input.len() - 1 {
                        return sip_parse_error!(2);
                    }
                    start_idx = idx + 1;
                    state = ParamState::Name;
                }
                b' ' => {
                    if start_idx != idx {
                        if state != ParamState::Value {
                            name = buf_to_string!();
                            state = ParamState::Value;
                        } else {
                            value = buf_to_string!();
                        }
                    }
                    start_idx = idx + 1;
                }
                b'=' => {
                    if state != ParamState::Value {
                        name = buf_to_string!();
                    }
                    if idx == input.len() - 1 {
                        // That is "param=""
                        return sip_parse_error!(3, "There is no value after '='");
                    }
                    start_idx = idx + 1;
                    state = ParamState::Value;
                }
                b'>' | b'?' => {
                    if state == ParamState::Name {
                        name = buf_to_string!();
                    } else {
                        if value.is_empty() {
                            value = buf_to_string!();
                        }
                    }
                    insert_param!();
                    if input[idx] == b'>' {
                        idx += 1;
                    }
                    break;
                }

                b'\r' => {
                    if idx < input.len() - 1 {
                        if input[idx + 1] == b'\n' {
                            if state == ParamState::Name {
                                name = buf_to_string!();
                            } else {
                                if value.is_empty() {
                                    value = buf_to_string!();
                                }
                            }
                            insert_param!();
                            idx += 2;
                            break;
                        } else {
                            return sip_parse_error!(4);
                        }
                    } else {
                        return sip_parse_error!(5);
                    }
                }
                _ => {}
            }
            idx += 1;
        }
        if start_idx != idx || !name.is_empty() {
            if state == ParamState::Name {
                name = buf_to_string!();
            } else {
                value = buf_to_string!();
            }
            result.insert(name, value);
        }
        Ok((&input[idx..], result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::NomParser;

    #[test]
    fn test_valid_parse_parameters() {
        match Parameters::parse("a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&""));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("a=b\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"b"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("a;d=e;s;m=a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"e"));
                assert_eq!(value.get(&"s"), Some(&""));
                assert_eq!(value.get(&"m"), Some(&"a"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("  aw\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match Parameters::parse(" a=1\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"1"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match Parameters::parse(" a =2\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"2"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("  a= 3\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"3"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("subject=project%20x\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"subject"), Some(&"project%20x"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }
        match Parameters::parse(" aa = 4 \r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aa"), Some(&"4"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match Parameters::parse("aw;d=es;sam;mark=a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"es"));
                assert_eq!(value.get(&"sam"), Some(&""));
                assert_eq!(value.get(&"mark"), Some(&"a"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"es"));
                assert_eq!(value.get(&"sam"), Some(&""));
                assert_eq!(value.get(&"mark"), Some(&"a"));
                assert_eq!(value.get(&"wam"), Some(&"kram"));
                assert_eq!(value.get(&"q"), Some(&"0.3"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse(" pr= fl; param2  ".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"pr"), Some(&"fl"));
                assert_eq!(value.get(&"param2"), Some(&""));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match Parameters::parse(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"es"));
                assert_eq!(value.get(&"sam"), Some(&""));
                assert_eq!(value.get(&"mark"), Some(&"a"));
                assert_eq!(value.get(&"wam"), Some(&"kram"));
                assert_eq!(value.get(&"q"), Some(&"0.3"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        // parse parameters in Record-Route
        match Parameters::parse(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3>;a=b".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"es"));
                assert_eq!(value.get(&"sam"), Some(&""));
                assert_eq!(value.get(&"mark"), Some(&"a"));
                assert_eq!(value.get(&"wam"), Some(&"kram"));
                assert_eq!(value.get(&"q"), Some(&"0.3"));
                assert_eq!(i, ";a=b".as_bytes());
            }
            Err(_) => panic!(),
        }

        // parse parameters in Request-URI. After '?' it are headers
        match Parameters::parse("method=REGISTER?to=alice%40atlanta.comb".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"method"), Some(&"REGISTER"));
                assert_eq!(i, "?to=alice%40atlanta.comb".as_bytes());
            }
            Err(_) => panic!(),
        }
    }

    #[test]
    fn test_invalid_parse_parameters() {
        match Parameters::parse("aw=".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
        match Parameters::parse("=".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
        match Parameters::parse("".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
    }
}
