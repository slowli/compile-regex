//! Compile-time regular expression validation and parsing.
//!
//! This library provides compile-time validation and parsing for regular expressions.
//! It has only a lightweight [`compile-fmt`] dependency (to produce better panic messages)
//! and is no-std / no-alloc compatible. Unlike some alternatives, it does not wrap a proc macro.
//!
//! The library strives to be compatible with [`regex`] / [`regex-syntax`] crates; it applies
//! the same approach to parsing as the latter. It only implements parsing / validation; i.e.,
//! it **does not** produce automata for matching against a regex. On the other hand, **almost all** of
//! `regex` syntax is supported:
//!
//! - Whitespace control (`x` / `-x` flags) are correctly accounted for during parsing
//! - Duplicate capture names are correctly checked for, so e.g. `(?<t>.)(?<t>.)` is invalid.
//! - Counted repetition ranges are checked, so e.g. `.{2,1}` is invalid.
//! - Char ranges in char sets are checked, so e.g. `[9-0]` is invalid.
//!
//! # Why?
//!
//! The main use case is checking whether a particular string constitutes a valid regex so that
//! it can be supplied to a `Regex` constructor, e.g. via a [`LazyLock`](std::sync::LazyLock).
//!
//! Ultimately, it's a benchmark of how far one can take compile-time computations in Rust just by using
//! a bunch of `const fn`s. As it turns out, it can get you pretty far.
//!
//! # Limitations
//!
//! - Unicode classes (`\p` and `\P` escapes) are not supported since it's almost impossible to check these
//!   in compile time.
//! - The depth of group nesting is limited to 8. (Nesting is used internally for whitespace control, i.e., the `x` flag.)
//! - The number of named captures is limited to 16.
//!
//! # Alternatives / similar tools
//!
//! - Use [`regex`] or [`regex-syntax`] if you don't need compile-time validation / parsing.
//! - There are a couple of crates that use `regex` + proc macro to move regex validation to compile time,
//!   for example, [`regex_static`](https://docs.rs/regex_static/).
//! - [`ere`](https://docs.rs/ere/) parses and compiles regular expressions in compile time.
//!   It supports POSIX extended regexes (i.e., a strict subset of what `regex` supports), and still uses proc macros.
//!
//! # Crate features
//!
//! ## `alloc`
//!
//! *(On by default)*
//!
//! Enables support of alloc types, such as [`Vec`] in [`RegexOptions::try_parse_to_vec()`].
//!
//! ## `std`
//!
//! *(On by default)*
//!
//! Enables support of the standard library types, e.g. the [`Error`](std::error::Error) trait implementation
//! for [`Error`].
//!
//! # Examples
//!
//! ```
//! use compile_regex::{ast::{Node, Syntax}, parse, validate};
//!
//! // Validate a regex for phone numbers.
//! const _: () = validate(r"(?<code>\+1\s*)?\(\d{3}\)\d{3}-\d{4}");
//! // Parse the same regex with whitespace and additional named captures
//! const PHONE_REGEX: &str = r"(?x)
//!     (?<intl> \+1\s*)? # International prefix
//!     (?<city> \( \d{3} \)) # City code
//!     \s*
//!     (?<num> \d{3}-\d{4})";
//! const SYNTAX: Syntax = parse(PHONE_REGEX);
//!
//! println!("{SYNTAX:#?}");
//!
//! // Get all named groups in the regex.
//! let group_names = SYNTAX.iter().filter_map(|spanned| {
//!     if let Node::GroupStart { name: Some(name), .. } = &spanned.node {
//!         return Some(&PHONE_REGEX[name.name]);
//!     }
//!     None
//! });
//! let group_names: Vec<_> = group_names.collect();
//! assert_eq!(group_names, ["intl", "city", "num"]);
//! ```
//!
//! ## Errors
//!
//! If [`validate()`] or [`parse()`] functions fail, they raise a compile-time error:
//!
//! ```compile_fail
//! # use compile_regex::validate;
//! // Fails because '+' is not escaped and is thus treated
//! // as a one-or-more quantifier
//! const _: () = validate(r"(?<code>+1\s*)?");
//! ```
//!
//! Getting information about an error:
//!
//! ```
//! use compile_regex::{try_validate, Error, ErrorKind};
//! # use assert_matches::assert_matches;
//!
//! const ERR: Error = match try_validate(r"(?<code>+1\s*)?") {
//!     Ok(()) => panic!("validation succeeded"),
//!     Err(err) => err,
//! };
//!
//! assert_matches!(ERR.kind(), ErrorKind::MissingRepetition);
//! assert_eq!(ERR.pos(), 8..9);
//! ```
//!
//! ## See also
//!
//! See [`RegexOptions`] docs for more advanced use cases.
//!
//! [`compile-fmt`]: https://docs.rs/compile-fmt/
//! [`regex`]: https://docs.rs/regex/
//! [`regex-syntax`]: https://docs.rs/regex-syntax/

// Conditional compilation
#![cfg_attr(not(feature = "std"), no_std)]
// Documentation settings
#![doc(html_root_url = "https://docs.rs/compile-regex/0.1.0")]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use crate::{
    errors::{Error, ErrorKind},
    parse::RegexOptions,
    utils::Stack,
};

#[macro_use]
mod utils;
pub mod ast;
mod errors;
mod parse;
#[cfg(test)]
mod tests;

/// `alloc` re-exports.
#[cfg(feature = "alloc")]
mod alloc {
    #[cfg(not(feature = "std"))]
    extern crate alloc as std;

    pub(crate) use std::vec::Vec;
}

/// Tries to validate the provided regular expression with the default [options](RegexOptions).
///
/// # Errors
///
/// Returns an error if the provided `regex` is not a valid regular expression.
pub const fn try_validate(regex: &str) -> Result<(), Error> {
    RegexOptions::DEFAULT.try_validate(regex)
}

/// Validates the provided regular expression, panicking on errors. This is a shortcut for
/// [`try_validate()`]`.unwrap()`.
///
/// # Panics
///
/// Panics if the provided `regex` is not a valid regular expression.
#[track_caller]
pub const fn validate(regex: &str) {
    if let Err(err) = try_validate(regex) {
        err.compile_panic(regex);
    }
}

/// Tries to parse the provided regular expression with the default [options](RegexOptions).
///
/// # Errors
///
/// - Returns an error if the provided `regex` is not a valid regular expression.
/// - Errors if one of internal limits is hit (e.g., the number of [syntax spans](ast::Spanned)
///   or the number of named captures).
pub const fn try_parse<const CAP: usize>(regex: &str) -> Result<ast::Syntax<CAP>, Error> {
    RegexOptions::DEFAULT.try_parse(regex)
}

/// Parses the provided regular expression, panicking on errors. This is a shortcut for
/// [`try_parse()`]`.unwrap()`.
///
/// # Panics
///
/// Panics in the same situations in which [`try_parse()`] returns an error.
#[track_caller]
pub const fn parse<const CAP: usize>(regex: &str) -> ast::Syntax<CAP> {
    match try_parse(regex) {
        Ok(spans) => spans,
        Err(err) => err.compile_panic(regex),
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../README.md");
