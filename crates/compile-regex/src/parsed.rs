//! Syntax highlighting for regular expressions.

use core::ops;

use crate::ast::{Spanned, Syntax};

/// Parsed regular expression consisting of an original string and the linearized syntax tree
/// (parametric, usually a slice of [`Spanned`] AST nodes).
#[derive(Debug, Clone, Copy)] // TODO: custom debug?
pub struct Parsed<'a, T = &'a [Spanned]> {
    regex: &'a str,
    syntax: T,
}

impl<'a, T: ops::Deref<Target = [Spanned]>> Parsed<'a, T> {
    #[doc(hidden)] // used by `parse!` macro; logically private
    pub const fn new_unchecked(regex: &'a str, syntax: T) -> Self {
        Self { regex, syntax }
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
