use super::*;

impl From<ops::Range<usize>> for Range {
    fn from(range: ops::Range<usize>) -> Self {
        Self::new(range.start, range.end)
    }
}

fn span(range: ops::Range<usize>, node: Ast) -> SyntaxSpan {
    SyntaxSpan {
        range: range.into(),
        node,
    }
}

#[test]
fn parsing_ast() {
    const AST: SyntaxSpans = parse(r"^wh\x40t(?<group>\t|\.\>){3, 5}?\d+$");

    assert_eq!(
        AST.spans(),
        &[
            span(0..1, Ast::LineAssertion),
            span(3..7, Ast::HexEscape),
            span(
                8..17,
                Ast::GroupStart {
                    name: Some(GroupName {
                        start: (9..11).into(),
                        name: (11..16).into(),
                        end: (16..17).into(),
                    }),
                    flags: None,
                }
            ),
            span(17..19, Ast::EscapedLiteral),
            span(19..20, Ast::Alteration),
            span(20..22, Ast::EscapedChar { meta: true }),
            span(22..24, Ast::StdAssertion),
            span(24..25, Ast::GroupEnd),
            span(
                25..32,
                Ast::CountedRepetition {
                    min_or_exact_count: (26..27).into(),
                    max_count: Some((29..30).into()),
                }
            ),
            span(32..34, Ast::PerlClass),
            span(34..35, Ast::UncountedRepetition),
            span(35..36, Ast::LineAssertion),
        ]
    );
}

#[test]
fn parsing_set_ast() {
    let ast: SyntaxSpans = parse(r"[[^ab]~~\t]");
    assert_eq!(
        ast.spans(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(
                1..3,
                Ast::SetStart {
                    negation: Some((2..3).into())
                }
            ),
            span(5..6, Ast::SetEnd),
            span(6..8, Ast::SetOp),
            span(8..10, Ast::EscapedLiteral),
            span(10..11, Ast::SetEnd),
        ]
    );

    let ast: SyntaxSpans = parse(r"[[:digit:]&&[:^cntrl:]-]");
    assert_eq!(
        ast.spans(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(1..10, Ast::AsciiClass),
            span(10..12, Ast::SetOp),
            span(12..22, Ast::AsciiClass),
            span(23..24, Ast::SetEnd),
        ]
    );

    let ast: SyntaxSpans = parse(r"[0-9--4-]");
    assert_eq!(
        ast.spans(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(2..3, Ast::SetRange),
            span(4..6, Ast::SetOp),
            span(8..9, Ast::SetEnd),
        ]
    );
}

#[test]
fn creating_ast_with_flags() {
    const AST: SyntaxSpans = parse(r"(?us)^(?-x:\d{5})");

    assert_eq!(
        AST.spans(),
        [
            span(
                0..4,
                Ast::GroupStart {
                    name: None,
                    flags: Some((1..4).into())
                }
            ),
            span(4..5, Ast::GroupEnd),
            span(5..6, Ast::LineAssertion),
            span(
                6..11,
                Ast::GroupStart {
                    name: None,
                    flags: Some((7..10).into())
                }
            ),
            span(11..13, Ast::PerlClass),
            span(
                13..16,
                Ast::CountedRepetition {
                    min_or_exact_count: (14..15).into(),
                    max_count: None,
                }
            ),
            span(16..17, Ast::GroupEnd),
        ]
    );
}
