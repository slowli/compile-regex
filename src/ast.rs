//! AST definitions. Because of `const`-ness, we support only very primitive AST spanning.

pub struct SyntaxSpans<const N: usize> {
    inner: [SyntaxSpan; N],
}
