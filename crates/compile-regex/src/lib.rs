//! Compile-time regular expression validation and parsing.
//!
//! This library provides compile-time validation and parsing for regular expressions.

pub use crate::{
    errors::{Error, ErrorKind},
    parse::RegexOptions,
};

#[macro_use]
mod utils;
pub mod ast;
mod errors;
mod parse;
#[cfg(test)]
mod tests;

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
