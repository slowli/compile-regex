//! AST definitions. Because of `const`-ness, we support only very primitive AST spanning.

use core::{fmt, ops};

#[derive(Debug)]
#[non_exhaustive]
pub enum Ast {
    /// `.`
    Dot,
    /// `^`, `$`
    LineAssertion,
    /// Perl character class: `\d`, `\s`, `\w` etc.
    PerlClass,
    /// Escaped literal with special meaning, such as `\n` or `\t`.
    EscapedLiteral,
    /// Escaped char without special meaning, such as `\*`.
    EscapedChar {
        /// Must the char be escaped?
        meta: bool,
    },
    /// Standard assertion like `\A` (beginning of the haystack) or `\<` (start-of-word boundary).
    StdAssertion,
    /// Uncounted repetition, like `*`, `+` or `?`, with an optional non-greedy marker.
    UncountedRepetition,
    /// Counted repetition, like `{3}` or `{3,5}`, with an optional non-greedy marker.
    CountedRepetition,
    /// Hexadecimal escape, like `\x0C` or `\u{123}`.
    HexEscape,

    /// Alteration char (`|`).
    Alteration,
    /// Group start `(` together with optional flags and naming.
    GroupStart {
        /// Group name.
        name: Option<GroupName>,
    },
    /// Group end `)`.
    GroupEnd,
}

#[derive(Debug)]
pub struct GroupName {
    /// Span of the start marker, i.e., `?<` or `?P<`.
    pub start: ops::Range<usize>,
    /// Span of the name.
    pub name: ops::Range<usize>,
    /// Position of the end marker, i.e. `>`.
    pub end: ops::Range<usize>,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SyntaxSpan {
    pub node: Ast,
    pub range: ops::Range<usize>,
}

impl SyntaxSpan {
    const DUMMY: Self = Self {
        node: Ast::Dot,
        range: 0..0,
    };
}

#[derive(Debug)]
pub(crate) struct PushError;

pub struct SyntaxSpans<const N: usize = 128> {
    inner: [SyntaxSpan; N],
    len: usize,
}

impl<const N: usize> fmt::Debug for SyntaxSpans<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.spans(), formatter)
    }
}

impl<const N: usize> SyntaxSpans<N> {
    pub(crate) const fn new() -> Self {
        Self {
            inner: [SyntaxSpan::DUMMY; N],
            len: 0,
        }
    }

    pub const fn spans(&self) -> &[SyntaxSpan] {
        let (start, _) = self.inner.split_at(self.len);
        start
    }

    pub(crate) const fn push(&mut self, span: SyntaxSpan) -> Result<(), PushError> {
        if self.len == N {
            Err(PushError)
        } else {
            self.inner[self.len] = span;
            self.len += 1;
            Ok(())
        }
    }
}
