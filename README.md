# zmodem2 - ZMODEM transfer protocol crate

This a library crate that implements ZMODEM transfer protocol, and is continued
development from [zmodem](https://github.com/lexxvir/zmodem) crate by Aleksei
Arbuzov. The crate does not use heap and can be compiled for `no_std`.

# Contributing

1. For larger changes, please create an issue. For small and cosmetic PR's just
   a PR is good enough.
2. Use `Closes: #<issue>` when the issue exists.
3. For large singular commits, preferably write also a description to the commit
   message.
4. Add `Signed-off-by: Firstname Lastname <email@address.com>` to the commmits
   (i.e. `git commit -s`).
5. Try to separate changes into
   [logical pieces](https://www.kernel.org/doc/html/latest/process/submitting-patches.html#separate-your-changes)
   in a pull requests with multiple commits.
