use alloc::collections::btree_map::BTreeMap;
use core::str;

// O(n) RCP - Random code programming ;)
// Retuns pointer to char after terminated char.
pub fn parse_parameters(input: &[u8]) -> nom::IResult<&[u8], BTreeMap<&str, &str>> {
    if input.is_empty() {
        return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
            input,
            nom::error::ErrorKind::TakeWhile1,
        )));
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

    let mut state = ParamState::Name;
    while idx < input.len() {
        match input[idx] {
            b';' => {
                if state == ParamState::Value {
                    // parameter without value
                    unsafe {
                        value = str::from_utf8_unchecked(&input[start_idx..idx]);
                    }
                } else {
                    unsafe {
                        name = str::from_utf8_unchecked(&input[start_idx..idx]);
                    }
                }
                result.insert(name, value);
                name = "";
                value = "";
                if idx == input.len() - 1 {
                    return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                        &input[idx..],
                        nom::error::ErrorKind::TakeWhile1,
                    )));
                }
                start_idx = idx + 1;
                state = ParamState::Name;
            }
            b' ' => {
                if start_idx != idx {
                    if state != ParamState::Value {
                        unsafe {
                            name = str::from_utf8_unchecked(&input[start_idx..idx]);
                        }
                        state = ParamState::Value;
                    } else {
                        unsafe {
                            value = str::from_utf8_unchecked(&input[start_idx..idx]);
                        }
                    }
                }
                start_idx = idx + 1;
            }
            b'=' => {
                unsafe {
                    if state != ParamState::Value {
                        name = str::from_utf8_unchecked(&input[start_idx..idx]);
                    }
                }
                if idx == input.len() - 1 {
                    // That is "param=""
                    return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                        &input[idx..],
                        nom::error::ErrorKind::TakeWhile1,
                    )));
                }
                start_idx = idx + 1;
                state = ParamState::Value;
            }
            b'>' => {
                if state == ParamState::Name {
                    unsafe {
                        name = str::from_utf8_unchecked(&input[start_idx..idx]);
                    }
                    result.insert(name, "");
                } else {
                    if value.is_empty() {
                        unsafe {
                            value = str::from_utf8_unchecked(&input[start_idx..idx]);
                        }
                    }
                    result.insert(name, value);
                }
                name = "";
                value = "";
                idx += 1;
                break;
            }
            b'\r' => {
                if idx < input.len() - 1 {
                    if input[idx + 1] == b'\n' {
                        if state == ParamState::Name {
                            unsafe {
                                name = str::from_utf8_unchecked(&input[start_idx..idx]);
                            }
                            result.insert(name, "");
                        } else {
                            if value.is_empty() {
                                unsafe {
                                    value = str::from_utf8_unchecked(&input[start_idx..idx]);
                                }
                            }
                            result.insert(name, value);
                        }
                        name = "";
                        value = "";
                        idx += 2;
                        break;
                    } else {
                        return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                            &input[idx..],
                            nom::error::ErrorKind::TakeWhile1,
                        )));
                    }
                } else {
                    return Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                        &input[idx..],
                        nom::error::ErrorKind::TakeWhile1,
                    )));
                }
            }
            _ => {}
        }
        idx += 1;
    }

    if start_idx != idx || !name.is_empty() {
        if state == ParamState::Name {
            unsafe {
                name = str::from_utf8_unchecked(&input[start_idx..idx]);
            }
        } else {
            unsafe {
                value = str::from_utf8_unchecked(&input[start_idx..idx]);
            }
        }
        result.insert(name, value);
    }

    Ok((&input[idx..], result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_valid_parse_parameters() {
        match parse_parameters("a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&""));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match parse_parameters("a=b\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"b"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match parse_parameters("a;d=e;s;m=a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"e"));
                assert_eq!(value.get(&"s"), Some(&""));
                assert_eq!(value.get(&"m"), Some(&"a"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match parse_parameters("  aw\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match parse_parameters(" a=1\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"1"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match parse_parameters(" a =2\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"2"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match parse_parameters("  a= 3\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"a"), Some(&"3"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match parse_parameters(" aa = 4 \r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aa"), Some(&"4"));
                assert_eq!(i.len(), 0);
            }
            Err(_) => panic!(),
        }

        match parse_parameters("aw;d=es;sam;mark=a\r\n".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"aw"), Some(&""));
                assert_eq!(value.get(&"d"), Some(&"es"));
                assert_eq!(value.get(&"sam"), Some(&""));
                assert_eq!(value.get(&"mark"), Some(&"a"));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match parse_parameters(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3\r\n".as_bytes()) {
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

        match parse_parameters(" pr= fl; param2  ".as_bytes()) {
            Ok((i, value)) => {
                assert_eq!(value.get(&"pr"), Some(&"fl"));
                assert_eq!(value.get(&"param2"), Some(&""));
                assert_eq!(i.len(), 0)
            }
            Err(_) => panic!(),
        }

        match parse_parameters(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3".as_bytes()) {
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

        // like in record route:)
        match parse_parameters(" aw ;d =es;sam;mark= a; wam = kram; q = 0.3>;a=b".as_bytes()) {
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
    }

    #[test]
    fn test_invalid_parse_parameters() {
        match parse_parameters("aw=".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
        match parse_parameters("=".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
        match parse_parameters("".as_bytes()) {
            Ok((_, _)) => panic!(),
            Err(_) => {}
        }
    }
}
