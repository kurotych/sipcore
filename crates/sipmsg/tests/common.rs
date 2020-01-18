pub fn check_header_value(result_header: &sipmsg::Header, exp_h_name: &str, exp_h_value: &str) {
    assert_eq!(result_header.name, exp_h_name);
    assert_eq!(result_header.value, exp_h_value);
}
