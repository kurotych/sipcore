use unicase::Ascii;
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SipMethod {
    ACK,
    BYE,
    CANCEL,
    INFO,
    INVITE,
    MESSAGE,
    NOTIFY,
    OPTIONS,
    PRACK,
    PUBLISH,
    REFER,
    REGISTER,
    SUBSCRIBE,
    UPDATE,
}

impl SipMethod {
    pub fn as_str(&self) -> &str {
        match self {
            &SipMethod::ACK => "ACK",
            &SipMethod::BYE => "BYE",
            &SipMethod::CANCEL => "CANCEL",
            &SipMethod::INFO => "INFO",
            &SipMethod::INVITE => "INVITE",
            &SipMethod::MESSAGE => "MESSAGE",
            &SipMethod::NOTIFY => "NOTIFY",
            &SipMethod::OPTIONS => "OPTIONS",
            &SipMethod::PRACK => "PRACK",
            &SipMethod::PUBLISH => "PUBLISH",
            &SipMethod::REFER => "REFER",
            &SipMethod::REGISTER => "REGISTER",
            &SipMethod::SUBSCRIBE => "SUBSCRIBE",
            &SipMethod::UPDATE => "UPDATE",
        }
    }

    pub fn from_str(s: &str) -> Option<SipMethod> {
        let s = Ascii::new(s);
        macro_rules! match_str {
            ($input_str:expr, $enum_result:expr) => {
                if s == $input_str {
                    return Some($enum_result);
                }
            };
        }
        match_str!("ACK", SipMethod::ACK);
        match_str!("BYE", SipMethod::BYE);
        match_str!("CANCEL", SipMethod::CANCEL);
        match_str!("INFO", SipMethod::INFO);
        match_str!("INVITE", SipMethod::INVITE);
        match_str!("MESSAGE", SipMethod::MESSAGE);
        match_str!("NOTIFY", SipMethod::NOTIFY);
        match_str!("OPTIONS", SipMethod::OPTIONS);
        match_str!("PRACK", SipMethod::PRACK);
        match_str!("PUBLISH", SipMethod::PUBLISH);
        match_str!("REFER", SipMethod::REFER);
        match_str!("REGISTER", SipMethod::REGISTER);
        match_str!("SUBSCRIBE", SipMethod::SUBSCRIBE);
        match_str!("UPDATE", SipMethod::UPDATE);
        None
    }
}
