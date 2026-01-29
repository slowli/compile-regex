# Compile-Time Regular Expression Parsing

This library provides compile-time validation and parsing for regular expressions.
It has only a lightweight [`compile-fmt`] dependency (to produce better panic messages)
and is no-std / no-alloc compatible. Unlike some alternatives, it does not wrap a proc macro.

The library strives to be compatible with [`regex`] / [`regex-syntax`] crates; it applies
the same approach to parsing as the latter. It only implements parsing / validation; i.e.,
it **does not** produce automata for matching against a regex. On the other hand, **almost all** of
`regex` syntax is supported:

- Whitespace control (`x` / `-x` flags) are correctly accounted for during parsing
- Duplicate capture names are correctly checked for, so e.g. `(?<t>.)(?<t>.)` is invalid.
- Counted repetition ranges are checked, so e.g. `.{2,1}` is invalid.
- Char ranges in char sets are checked, so e.g. `[9-0]` is invalid.

## Why?

The main use case is checking whether a particular string constitutes a valid regex so that
it can be supplied to a `Regex` constructor, e.g. via a [`LazyLock`].

Ultimately, it's a benchmark of how far one can take compile-time computations in Rust just by using
a bunch of `const fn`s. As it turns out, it can get you pretty far.

## Usage

Add this to your `Crate.toml`:

```toml
[dependencies]
compile-regex = "0.1.0"
```

Example of usage:

```rust
use compile_regex::{ast::{Node, Syntax}, parse, validate};

// Validate a simple regex for phone numbers.
const _: () = validate(r"(?<code>\+1\s*)?\(\d{3}\)\d{3}-\d{4}");
// Parse the same regex with whitespace and additional named captures
const PHONE_REGEX: &str = r"(?x)
    (?<intl> \+1\s*)? # International prefix
    (?<city> \( \d{3} \)) # City code
    \s*
    (?<num> \d{3}-\d{4})";
const SYNTAX: Syntax = parse(PHONE_REGEX);

println!("{SYNTAX:#?}");
```

See the crate docs for more examples.

## Limitations

- Unicode classes (`\p` and `\P` escapes) are not supported since it's almost impossible to check these
  in compile time.
- The depth of group nesting is limited to 8. (Nesting is used internally for whitespace control, i.e., the `x` flag.)
- The number of named captures is limited to 16.

## Alternatives / similar tools

- Use [`regex`] or [`regex-syntax`] if you don't need compile-time validation / parsing.
- There are a couple of crates that use `regex` + proc macro to move regex validation to compile time,
  for example, [`regex_static`].
- [`ere`] parses and compiles regular expressions in compile time. It supports POSIX extended regexes (i.e.,
  a strict subset of what `regex` supports), and still uses proc macros.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `term-transcript` by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[`compile-fmt`]: https://crates.io/crates/compile-fmt/
[`regex`]: https://crates.io/crates/regex/
[`regex-syntax`]: https://crates.io/crates/regex-syntax/
[`LazyLock`]: https://doc.rust-lang.org/std/sync/struct.LazyLock.html
[`regex_static`]: https://crates.io/crates/regex_static
[`ere`]: https://crates.io/crates/ere/
