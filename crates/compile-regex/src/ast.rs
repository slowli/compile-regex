//! AST definitions. Because of `const`-ness, we support only very primitive AST spanning.

use core::{fmt, ops};

use crate::utils::Stack;

/// Range of chars. Similar to `Range<usize>`, but implements `Copy`.
#[derive(Clone, Copy, PartialEq)]
pub struct Range {
    pub start: usize,
    pub end: usize,
}

impl fmt::Debug for Range {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}..{}", self.start, self.end)
    }
}

impl From<Range> for ops::Range<usize> {
    fn from(range: Range) -> Self {
        range.start..range.end
    }
}

impl Range {
    pub const fn new(start: usize, end: usize) -> Self {
        assert!(start <= end);
        Self { start, end }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.end == self.start
    }

    pub(crate) const fn len(&self) -> usize {
        self.end - self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CountedRepetition {
    Exactly(Range),
    AtLeast(Range),
    Between(Range, Range),
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
    CountedRepetition(CountedRepetition),
    /// Hexadecimal escape, like `\x0C` or `\u{123}`.
    HexEscape,

    /// Alteration char (`|`).
    Alteration,
    /// Group start `(` together with optional flags and naming.
    GroupStart {
        /// Group name.
        name: Option<GroupName>,
        /// Flags for the current group, e.g. `?x-m` in `(?x-m)` or in `(?x-m:.*)`.
        /// By design, this is mutually exclusive with `name`.
        flags: Option<Range>,
    },
    /// Group end `)`.
    GroupEnd,
    /// Set start `[`.
    SetStart { negation: Option<Range> },
    /// Set end `]`.
    SetEnd,
    /// Set operation: `&&`, `--` or `~~`.
    SetOp,
    /// Set range char: `-`.
    SetRange,
    /// ASCII char class, e.g., `[:alnum:]`.
    AsciiClass,
    /// Comment, e.g., `# Test`. May span over multiple lines, where comments may be preceded by whitespace
    /// (but no AST nodes).
    Comment,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GroupName {
    /// Span of the start marker, i.e., `?<` or `?P<`.
    pub start: Range,
    /// Span of the name.
    pub name: Range,
    /// Position of the end marker, i.e. `>`.
    pub end: Range,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SyntaxSpan {
    pub node: Ast,
    pub range: Range,
}

impl SyntaxSpan {
    pub(crate) const DUMMY: Self = Self {
        node: Ast::Dot,
        range: Range { start: 0, end: 0 },
    };
}

/// Linearized syntax tree.
pub type Syntax<const LEN: usize = 128> = Stack<SyntaxSpan, LEN>;
