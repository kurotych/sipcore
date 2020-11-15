# sipmsg [![crates.io](https://img.shields.io/crates/v/sipmsg.svg?maxAge=2592000)](https://crates.io/crates/sipmsg)

Parsing and validation SIP Messages according to [RFC3261](https://tools.ietf.org/html/rfc3261#section-25)

![Build and test](https://github.com/armatusmiles/sipcore/workflows/sipmsg/badge.svg)   ![Build and test](https://github.com/armatusmiles/sipcore/workflows/sipmsg_no_std/badge.svg)

[Documentation](https://docs.rs/sipmsg)

## Benchmark
It is tested on **Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz**  
Result: **63 mbytes per second**, count sip messages: **184942**   
It is full parsing and validation. See [benchmark.rs](tests/benchmark.rs)
