use core::ops;
use std::collections::HashMap;

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
    const AST: Syntax = parse(r"^wh\x40t(?<group>\t|\.\>){3, 5}?\d+$");

    assert_eq!(
        AST.as_slice(),
        &[
            span(0..1, Ast::LineAssertion),
            span(3..7, Ast::HexEscape),
            span(
                8..9,
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
fn parsing_ast_with_whitespace() {
    const REGEX: &str = r"
      ^w h \x40 # ascii escape
      t (?<group>
        \t | \ \.\> # named group
      ) { 3, 5 }? # non-greedy repetition
      \d+ $";
    const AST: Syntax = RegexOptions::DEFAULT.ignore_whitespace(true).parse(REGEX);

    let expected_spans = [
        (r"\x40", Ast::HexEscape),
        ("# ascii escape", Ast::Comment),
        (r"\t", Ast::EscapedLiteral),
        (r"\.", Ast::EscapedChar { meta: true }),
        (r"\ ", Ast::EscapedChar { meta: false }),
        (r"\>", Ast::StdAssertion),
        ("# named group", Ast::Comment),
        ("# non-greedy repetition", Ast::Comment),
        (r"\d", Ast::PerlClass),
        ("+", Ast::UncountedRepetition),
    ];
    let actual_spans: HashMap<_, _> = AST
        .as_slice()
        .iter()
        .map(|span| (&REGEX[ops::Range::from(span.range)], span.node))
        .collect();

    for (span_str, ast) in expected_spans {
        assert_eq!(actual_spans[&span_str], ast, "{span_str:?}");
    }
}

#[test]
fn parsing_set_ast() {
    let ast: Syntax = parse(r"[[^ab]~~\t]");
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(
                1..2,
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

    let ast: Syntax = parse(r"[[:digit:]&&[:^cntrl:]-]");
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(1..10, Ast::AsciiClass),
            span(10..12, Ast::SetOp),
            span(12..22, Ast::AsciiClass),
            span(23..24, Ast::SetEnd),
        ]
    );

    let ast: Syntax = parse(r"[0-9--4-]");
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Ast::SetStart { negation: None }),
            span(2..3, Ast::SetRange),
            span(4..6, Ast::SetOp),
            span(8..9, Ast::SetEnd),
        ]
    );
}

#[test]
fn parsing_set_ast_with_whitespace() {
    const AST: Syntax = RegexOptions::DEFAULT.ignore_whitespace(true).parse(
        r"[ ^ # negated!
          0 - 9 # another comment
          -- 4-
        ]",
    );

    assert_eq!(
        AST.as_slice(),
        [
            span(
                0..1,
                Ast::SetStart {
                    negation: Some((2..3).into()),
                }
            ),
            span(4..14, Ast::Comment),
            span(27..28, Ast::SetRange),
            span(31..48, Ast::Comment),
            span(59..61, Ast::SetOp),
            span(73..74, Ast::SetEnd),
        ]
    );
}

#[test]
fn creating_ast_with_flags() {
    const AST: Syntax = parse(r"(?us)^(?-x:\d{5})");

    assert_eq!(
        AST.as_slice(),
        [
            span(
                0..1,
                Ast::GroupStart {
                    name: None,
                    flags: Some((1..4).into())
                }
            ),
            span(4..5, Ast::GroupEnd),
            span(5..6, Ast::LineAssertion),
            span(
                6..7,
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

#[test]
fn ast_with_dynamic_whitespace_control() {
    const AST: Syntax = parse(
        r"(?x)
        \d+ # digits
        (?<color>(?-x)#\d{6}) # literal hash",
    );

    assert_eq!(
        AST.as_slice(),
        [
            span(
                0..1,
                Ast::GroupStart {
                    flags: Some((1..3).into()),
                    name: None,
                }
            ),
            span(3..4, Ast::GroupEnd),
            span(13..15, Ast::PerlClass),
            span(15..16, Ast::UncountedRepetition),
            span(17..25, Ast::Comment),
            span(
                34..35,
                Ast::GroupStart {
                    flags: None,
                    name: Some(GroupName {
                        start: (35..37).into(),
                        name: (37..42).into(),
                        end: (42..43).into(),
                    }),
                }
            ),
            span(
                43..44,
                Ast::GroupStart {
                    flags: Some((44..47).into()),
                    name: None,
                }
            ),
            span(47..48, Ast::GroupEnd),
            span(49..51, Ast::PerlClass),
            span(
                51..54,
                Ast::CountedRepetition {
                    min_or_exact_count: (52..53).into(),
                    max_count: None,
                }
            ),
            span(54..55, Ast::GroupEnd),
            span(56..70, Ast::Comment),
        ]
    );
}
