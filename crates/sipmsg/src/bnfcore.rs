/// Basic common rules from
/// https://tools.ietf.org/html/rfc2234#section-6.1 and https://tools.ietf.org/html/rfc3261#section-25
/// that can be described by a limited number of characters

/// ALPHA =  %x41-5A / %x61-7A   ; A-Z / a-z
#[inline]
pub fn is_alpha(c: u8) -> bool {
    (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
}

/// BIT = "0" / "1"
#[inline]
pub fn is_bit(c: u8) -> bool {
    c == b'0' || c == b'1'
}

/// CHAR = %x01-7F
/// any 7-bit US-ASCII character, excluding NUL
#[inline]
pub fn is_char(c: u8) -> bool {
    c >= 0x01 && c <= 0x7F
}

/// CR = %x0D
/// Carriage return
#[inline]
pub fn is_cr(c: u8) -> bool {
    c == 0x0D
}

/// CRLF = CR LF
/// Internet standard newline
#[inline]
pub fn is_crlf(i: &[u8]) -> bool {
    is_cr(i[0]) && is_lf(i[1])
}

/// CTL = %x00-1F / %x7F
#[inline]
pub fn is_ctl(c: u8) -> bool {
    c <= 0x1F || c == 0x7F
}

/// DIGIT = %x30-39
#[inline]
pub fn is_digit(c: u8) -> bool {
    (c >= 0x30 && c <= 0x39)
}

/// DQUOTE =  %x22
#[inline]
pub fn is_dquote(c: u8) -> bool {
    c == 0x22
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
#[inline]
pub fn is_hexdig(c: u8) -> bool {
    is_digit(c) || c == b'A' || c == b'B' || c == b'C' || c == b'D' || c == b'E' || c == b'F'
}

/// HTAB = %x09
#[inline]
pub fn is_htab(c: u8) -> bool {
    c == 0x09
}

///  LF = %x0A
#[inline]
pub fn is_lf(c: u8) -> bool {
    c == 0x0A
}

/// OCTET = %x00-FF
/// 8 bits of data
#[inline]
pub fn is_octet(_: u8) -> bool {
    return true;
}

/// SP = %x20
#[inline]
pub fn is_sp(c: u8) -> bool {
    c == 0x20
}

/// VCHAR = %x21-7E
/// visible (printing) characters
#[inline]
pub fn is_vchar(c: u8) -> bool {
    c >= 0x21 && c <= 0x7E
}

/// WSP = SP / HTAB
/// white space
#[inline]
pub fn is_wsp(c: u8) -> bool {
    is_sp(c) || is_htab(c)
}

#[inline]
pub fn is_alphanum(c: u8) -> bool {
    is_digit(c) || is_alpha(c)
}

#[inline]
pub fn is_reserved(c: u8) -> bool {
    c == b';'
        || c == b'/'
        || c == b'?'
        || c == b':'
        || c == b'@'
        || c == b'&'
        || c == b'='
        || c == b'+'
        || c == b'$'
        || c == b','
}

#[inline]
pub fn is_unreserved(c: u8) -> bool {
    is_alphanum(c) || is_mark(c)
}

#[inline]
pub fn is_mark(c: u8) -> bool {
    c == b'-'
        || c == b'_'
        || c == b'.'
        || c == b'!'
        || c == b'~'
        || c == b'*'
        || c == b'\''
        || c == b'('
        || c == b')'
}

#[inline]
pub fn is_escaped(i: &[u8]) -> bool {
    i[0] == b'%' && is_hexdig(i[1]) && is_hexdig(i[2])
}

#[inline]
pub fn is_lhex(c: u8) -> bool {
    is_digit(c) || c >= 0x61 && c <= 0x66
}

/// separators  =  "(" / ")" / "<" / ">" / "@" /
/// "," / ";" / ":" / "\" / DQUOTE /
/// "/" / "[" / "]" / "?" / "=" /
/// "{" / "}" / SP / HTAB
#[inline]
pub fn is_separators(c: u8) -> bool {
    c == b'('
        || c == b')'
        || c == b'<'
        || c == b'>'
        || c == b'@'
        || c == b','
        || c == b';'
        || c == b':'
        || c == b'\\'
        || is_dquote(c)
        || c == b'/'
        || c == b'['
        || c == b']'
        || c == b'?'
        || c == b'='
        || c == b'{'
        || c == b'}'
        || is_sp(c)
        || is_htab(c)
}

#[inline]
pub fn is_word_char(c: u8) -> bool {
    is_alphanum(c)
        || c == b'-'
        || c == b'.'
        || c == b'!'
        || c == b'%'
        || c == b'*'
        || c == b'_'
        || c == b'+'
        || c == b'`'
        || c == b'\''
        || c == b'~'
        || c == b'('
        || c == b')'
        || c == b'<'
        || c == b'>'
        || c == b':'
        || c == b'\\'
        || is_dquote(c)
        || c == b'/'
        || c == b'['
        || c == b']'
        || c == b'?'
        || c == b'{'
        || c == b'}'
}

#[inline]
pub fn is_quoted_pair(i: &[u8]) -> bool {
    i[0] == b'\\' && (i[1] <= 0x09 || i[1] >= 0x0B && i[1] <= 0x0C || i[1] >= 0x0E && i[1] <= 0x7F)
}

#[inline]
pub fn is_token_char(c: u8) -> bool {
    is_alphanum(c) || c == b'-' || c == b'.' ||
    c == b'!' || c == b'%' || c == b'*' ||
    c == b'_' || c == b'+' || c == b'`' ||
    c == b'\'' || c == b'~'
}