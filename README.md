# zmodem2 - ZMODEM transfer protocol crate

This a library crate that implements ZMODEM transfer protocol, and is 
continued development from [zmodem](https://github.com/lexxvir/zmodem)
crate by Aleksei Arbuzov. The crate does not use heap and can be
compiled for `no_std`.

# Development environment

* Running `cargo t` requires `lrzsz`.
* To try out `no_std` build, build with `cargo b --no-default-featuers`.
