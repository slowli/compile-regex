pub use crate::{
    ast::{Ast, GroupName, Range, SyntaxSpan, SyntaxSpans},
    errors::{Error, ErrorKind},
    parse::RegexOptions,
};

#[macro_use]
mod utils;
mod ast;
mod errors;
mod parse;
#[cfg(test)]
mod tests;

const fn is_meta_char(ch: u8) -> bool {
    matches!(
        ch,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
            | b'#'
            | b'&'
            | b'-'
            | b'~'
    )
}

const fn is_escapable_char(ch: u8) -> bool {
    !matches!(ch, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'<' | b'>')
}

/// Tries to validate the provided regular expression.
pub const fn try_validate(regex: &str) -> Result<(), Error> {
    RegexOptions::DEFAULT.try_validate(regex)
}

#[track_caller]
pub const fn validate(regex: &str) {
    if let Err(err) = try_validate(regex) {
        err.compile_panic(regex);
    }
}

pub const fn try_parse<const CAP: usize>(regex: &str) -> Result<SyntaxSpans<CAP>, Error> {
    RegexOptions::DEFAULT.try_parse(regex)
}

#[track_caller]
pub const fn parse<const CAP: usize>(regex: &str) -> SyntaxSpans<CAP> {
    match try_parse(regex) {
        Ok(spans) => spans,
        Err(err) => err.compile_panic(regex),
    }
}
