# zmodem2 - ZMODEM transfer protocol crate

This a library crate that implements ZMODEM transfer protocol, and is continued
development from [zmodem](https://github.com/lexxvir/zmodem) crate by Aleksei
Arbuzov. The crate does not use heap and can be compiled for `no_std`.

# Contributing

1. Create issue for any pull request. Use `Closes: #<id>` in the top most commit
   to close the pull request.
2. Commit messages: https://www.conventionalcommits.org/en/v1.0.0/
3. Run `cargo clippy` and `cargo t`.
4. Preferably write a short description to the commit what it does, and why it
   does what it does (i.e. motivation).

# Roadmap

For 0.1 `async` support is purposely left out to future version because for the
first release functional correctness is the priority over anything else.
However, the API is made sequential per ZMODEM subpacket, which should be
good enough to display updated status information on the transfer progress.

# Development environment

* Running `cargo t` requires `lrzsz`.
* To try out `no_std` build, build with `cargo b --no-default-featuers`.
