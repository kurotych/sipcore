/// Core rules from https://tools.ietf.org/html/rfc2234#section-6.1 except LWSP

/// ALPHA =  %x41-5A / %x61-7A   ; A-Z / a-z
#[inline]
pub fn alpha(c: u8) -> bool {
  (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
}

/// BIT = "0" / "1"
#[inline]
pub fn bit(c: u8) -> bool {
    c == b'0' || c == b'1'
}

/// CHAR = %x01-7F
/// any 7-bit US-ASCII character, excluding NUL
#[inline]
pub fn char(c: u8) -> bool {
    c >= 0x01 && c <= 0x7F
}

/// CR = %x0D
/// Carriage return
#[inline]
pub fn cr(c: u8) -> bool {
    c == 0x0D
}

/// CRLF = CR LF
/// Internet standard newline
#[inline]
pub fn crlf(i: &[u8]) -> bool {
    cr(i[0]) && lf(i[1])
}

/// CTL = %x00-1F / %x7F
#[inline]
pub fn ctl(c: u8) -> bool {
    c <= 0x1F || c == 0x7F
}

/// DIGIT = %x30-39
#[inline]
pub fn digit(c: u8) -> bool {
  (c >= 0x30 && c <= 0x39)
}

/// DQUOTE =  %x22
#[inline]
pub fn dquote(c: u8) -> bool {
    c == 0x22
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
#[inline]
pub fn hexdig(c: u8) -> bool {
    digit(c) || c == b'A' || c == b'B' ||
    c == b'C' || c == b'D' || c == b'E' ||
    c == b'F'
}

/// HTAB = %x09
#[inline]
pub fn htab(c: u8) -> bool {
    c == 0x09
}

///  LF = %x0A
#[inline]
pub fn lf(c: u8) -> bool {
    c == 0x0A
}

/// OCTET = %x00-FF
/// 8 bits of data
#[inline]
pub fn octet(_: u8) -> bool {
    return true
}

/// SP = %x20
#[inline]
pub fn sp(c: u8) -> bool {
    c == 0x20
}

/// VCHAR = %x21-7E
/// visible (printing) characters
#[inline]
pub fn vchar(c: u8) -> bool {
    c >= 0x21 && c <= 0x7E
}

/// WSP = SP / HTAB
/// white space
#[inline]
pub fn wsp(c: u8) -> bool {
    sp(c) || htab(c)
}
