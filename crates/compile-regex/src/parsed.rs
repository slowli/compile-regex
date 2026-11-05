//! Syntax highlighting for regular expressions.

use core::{fmt, ops};

use crate::{
    ast::{Node, Spanned, Syntax},
    utils::RawStr,
};

#[derive(Debug)]
enum DebugNode<'a> {
    Dot,
    LineAssertion,
    PerlClass,
    EscapedLiteral,
    EscapedChar,
    ObsoleteEscapedChar,
    StdAssertion,
    UncountedRepetition,
    CountedRepetition,
    HexEscape,

    Alternation,
    Group,
    #[expect(dead_code)] // only read by the `Debug` impl
    NamedGroup(&'a str),
    #[expect(dead_code)] // only read by the `Debug` impl
    Flags(&'a str),
    GroupEnd,

    SetStart,
    SetEnd,
    SetOp,
    SetRange,
    AsciiClass,
}

impl<'a> DebugNode<'a> {
    fn new(raw: &'a str, node: &Node) -> Option<Self> {
        Some(match node {
            Node::Dot => Self::Dot,
            Node::LineAssertion => Self::LineAssertion,
            Node::PerlClass => Self::PerlClass,
            Node::EscapedLiteral => Self::EscapedLiteral,
            Node::EscapedChar { meta: true } => Self::EscapedChar,
            Node::EscapedChar { meta: false } => Self::ObsoleteEscapedChar,
            Node::StdAssertion => Self::StdAssertion,
            Node::UncountedRepetition => Self::UncountedRepetition,
            Node::CountedRepetition(_) => Self::CountedRepetition,
            Node::HexEscape => Self::HexEscape,
            Node::Alternation => Self::Alternation,

            Node::GroupStart {
                flags: Some(flags), ..
            } => Self::Flags(&raw[*flags]),
            Node::GroupStart {
                name: Some(name), ..
            } => Self::NamedGroup(&raw[name.name]),
            Node::GroupStart { .. } => Self::Group,

            Node::GroupEnd => Self::GroupEnd,
            Node::SetStart { .. } => Self::SetStart,
            Node::SetEnd => Self::SetEnd,
            Node::SetOp => Self::SetOp,
            Node::SetRange => Self::SetRange,
            Node::AsciiClass => Self::AsciiClass,
            Node::Comment => return None,
        })
    }
}

/// Parsed regular expression consisting of an original string and the linearized syntax tree
/// (parametric, usually a slice of [`Spanned`] AST nodes).
///
/// # Debugging
///
/// You may use the alternate debugging representation `{:#?}` to check how the expression is parsed:
///
/// ```
/// use compile_regex::{parse, Parsed};
///
/// const REGEX: Parsed = parse!(r"^\s*\d{3,5}?");
/// assert_eq!(format!("{REGEX:#?}"), r#"{
///     r"^": LineAssertion,
///     r"\s": PerlClass,
///     r"*": UncountedRepetition,
///     r"\d": PerlClass,
///     r"{3,5}?": CountedRepetition,
/// }"#);
/// ```
#[derive(Clone, Copy)]
pub struct Parsed<'a, T = &'a [Spanned]> {
    regex: &'a str,
    syntax: T,
}

impl<T: ops::Deref<Target = [Spanned]>> fmt::Debug for Parsed<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if formatter.alternate() {
            let mut map = formatter.debug_map();
            for spanned in self.syntax() {
                let Some(node) = DebugNode::new(self.regex, &spanned.node) else {
                    continue;
                };
                map.entry(&RawStr(&self.regex[spanned.span]), &node);
            }
            map.finish()
        } else {
            // Just output the expression
            formatter
                .debug_tuple("Parsed")
                .field(&RawStr(self.regex))
                .finish()
        }
    }
}

impl<'a, T: ops::Deref<Target = [Spanned]>> Parsed<'a, T> {
    #[doc(hidden)] // used by `parse!` macro; logically private
    pub const fn new_unchecked(regex: &'a str, syntax: T) -> Self {
        Self { regex, syntax }
    }

    /// Returns the wrapped regular expression string.
    pub const fn raw(&self) -> &'a str {
        self.regex
    }

    /// Returns a reference to the underlying syntax nodes.
    pub fn syntax(&self) -> &[Spanned] {
        &self.syntax
    }

    /// Extract underlying syntax nodes.
    // TODO: this cannot be a `const fn` because of possible `Drop` impl, which doesn't make sense
    pub fn into_syntax(self) -> T {
        self.syntax
    }
}

impl<const CAP: usize> Parsed<'_, Syntax<CAP>> {
    #[doc(hidden)] // used by `parse!` macro; logically private
    pub const fn as_slice(&self) -> Parsed<'_> {
        Parsed {
            regex: self.regex,
            syntax: self.syntax.as_slice(),
        }
    }
}

impl<T, U> PartialEq<Parsed<'_, U>> for Parsed<'_, T>
where
    T: ops::Deref<Target = [Spanned]>,
    U: ops::Deref<Target = [Spanned]>,
{
    fn eq(&self, other: &Parsed<'_, U>) -> bool {
        self.regex == other.regex && self.syntax() == other.syntax()
    }
}
