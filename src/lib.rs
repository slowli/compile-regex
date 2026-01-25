use core::ops;

use crate::parse::ParseState;
pub use crate::{
    ast::{Ast, GroupName, Range, SyntaxSpan, SyntaxSpans},
    errors::{Error, ErrorKind},
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
    let mut state = <ParseState>::new(regex);
    loop {
        match state.step() {
            Err(err) => return Err(err),
            Ok(ops::ControlFlow::Break(())) => break,
            Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
        }
    }

    Ok(())
}

#[track_caller]
pub const fn validate(regex: &str) {
    if let Err(err) = try_validate(regex) {
        err.compile_panic(regex);
    }
}

pub const fn try_parse<const CAP: usize>(regex: &str) -> Result<SyntaxSpans<CAP>, Error> {
    let mut state = ParseState::custom(regex, true);
    loop {
        match state.step() {
            Err(err) => return Err(err),
            Ok(ops::ControlFlow::Break(())) => return Ok(state.into_spans()),
            Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
        }
    }
}

#[track_caller]
pub const fn parse<const CAP: usize>(regex: &str) -> SyntaxSpans<CAP> {
    match try_parse(regex) {
        Ok(spans) => spans,
        Err(err) => err.compile_panic(regex),
    }
}
