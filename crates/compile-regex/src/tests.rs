use std::{collections::HashMap, ops};

use assert_matches::assert_matches;

use super::*;
use crate::ast::{CountedRepetition, GroupName, Node, Spanned, Syntax};

impl From<ops::Range<usize>> for ast::Span {
    fn from(range: ops::Range<usize>) -> Self {
        Self::new(range.start, range.end)
    }
}

fn span(range: ops::Range<usize>, node: Node) -> Spanned {
    Spanned {
        span: range.into(),
        node,
    }
}

#[test]
fn parsing_ast() {
    const REGEX: &str = r"^wh\x40t(?<group>\t|\.\>){3, 5}?\d+$";
    const AST: &[Spanned] = parse!(REGEX);

    assert_eq!(
        AST,
        &[
            span(0..1, Node::LineAssertion),
            span(3..7, Node::HexEscape),
            span(
                8..9,
                Node::GroupStart {
                    name: Some(GroupName {
                        start: (9..11).into(),
                        name: (11..16).into(),
                        end: (16..17).into(),
                    }),
                    flags: None,
                }
            ),
            span(17..19, Node::EscapedLiteral),
            span(19..20, Node::Alteration),
            span(20..22, Node::EscapedChar { meta: true }),
            span(22..24, Node::StdAssertion),
            span(24..25, Node::GroupEnd),
            span(
                25..32,
                Node::CountedRepetition(CountedRepetition::Between(
                    (26..27).into(),
                    (29..30).into(),
                ))
            ),
            span(32..34, Node::PerlClass),
            span(34..35, Node::UncountedRepetition),
            span(35..36, Node::LineAssertion),
        ]
    );

    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(REGEX).unwrap();
    assert_eq!(dynamic_ast, AST);
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
        (r"\x40", Node::HexEscape),
        ("# ascii escape", Node::Comment),
        (r"\t", Node::EscapedLiteral),
        (r"\.", Node::EscapedChar { meta: true }),
        (r"\ ", Node::EscapedChar { meta: false }),
        (r"\>", Node::StdAssertion),
        ("# named group", Node::Comment),
        ("# non-greedy repetition", Node::Comment),
        (r"\d", Node::PerlClass),
        ("+", Node::UncountedRepetition),
    ];
    let actual_spans: HashMap<_, _> = AST
        .as_slice()
        .iter()
        .map(|span| (&REGEX[ops::Range::from(span.span)], span.node))
        .collect();

    for (span_str, ast) in expected_spans {
        assert_eq!(actual_spans[&span_str], ast, "{span_str:?}");
    }

    let dynamic_ast = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_parse_to_vec(REGEX)
        .unwrap();
    assert_eq!(dynamic_ast, AST.as_slice());
}

#[test]
fn parsing_set_ast() {
    let regex = r"[[^ab]~~\t]";
    let ast: Syntax = RegexOptions::DEFAULT.parse(regex);
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Node::SetStart { negation: None }),
            span(
                1..2,
                Node::SetStart {
                    negation: Some((2..3).into())
                }
            ),
            span(5..6, Node::SetEnd),
            span(6..8, Node::SetOp),
            span(8..10, Node::EscapedLiteral),
            span(10..11, Node::SetEnd),
        ]
    );
    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(regex).unwrap();
    assert_eq!(dynamic_ast, ast.as_slice());

    let regex = r"[[:digit:]&&[:^cntrl:]-]";
    let ast: Syntax = RegexOptions::DEFAULT.parse(regex);
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Node::SetStart { negation: None }),
            span(1..10, Node::AsciiClass),
            span(10..12, Node::SetOp),
            span(12..22, Node::AsciiClass),
            span(23..24, Node::SetEnd),
        ]
    );
    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(regex).unwrap();
    assert_eq!(dynamic_ast, ast.as_slice());

    let regex = r"[0-9--4-]";
    let ast: Syntax = RegexOptions::DEFAULT.parse(regex);
    assert_eq!(
        ast.as_slice(),
        [
            span(0..1, Node::SetStart { negation: None }),
            span(2..3, Node::SetRange),
            span(4..6, Node::SetOp),
            span(8..9, Node::SetEnd),
        ]
    );
    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(regex).unwrap();
    assert_eq!(dynamic_ast, ast.as_slice());
}

#[test]
fn parsing_set_ast_with_whitespace() {
    const REGEX: &str = r"[ ^ # negated!
      0 - 9 # another comment
      -- 4-
    ]";
    const AST: Syntax = RegexOptions::DEFAULT.ignore_whitespace(true).parse(REGEX);

    assert_eq!(
        AST.as_slice(),
        [
            span(
                0..1,
                Node::SetStart {
                    negation: Some((2..3).into()),
                }
            ),
            span(4..14, Node::Comment),
            span(23..24, Node::SetRange),
            span(27..44, Node::Comment),
            span(51..53, Node::SetOp),
            span(61..62, Node::SetEnd),
        ]
    );

    let dynamic_ast = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_parse_to_vec(REGEX)
        .unwrap();
    assert_eq!(dynamic_ast, AST.as_slice());
}

#[test]
fn creating_ast_with_flags() {
    const REGEX: &str = r"(?us)^(?-x:\d{5})";
    const AST: &[Spanned] = parse!(REGEX);

    assert_eq!(
        AST,
        [
            span(
                0..1,
                Node::GroupStart {
                    name: None,
                    flags: Some((1..4).into())
                }
            ),
            span(4..5, Node::GroupEnd),
            span(5..6, Node::LineAssertion),
            span(
                6..7,
                Node::GroupStart {
                    name: None,
                    flags: Some((7..10).into())
                }
            ),
            span(11..13, Node::PerlClass),
            span(
                13..16,
                Node::CountedRepetition(CountedRepetition::Exactly((14..15).into())),
            ),
            span(16..17, Node::GroupEnd),
        ]
    );

    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(REGEX).unwrap();
    assert_eq!(dynamic_ast, AST);
}

#[test]
fn ast_with_dynamic_whitespace_control() {
    const REGEX: &str = r"(?x)
        \d+ # digits
        (?<color>(?-x)#\d{6}) # literal hash";
    const AST: &[Spanned] = parse!(REGEX);

    assert_eq!(
        AST,
        [
            span(
                0..1,
                Node::GroupStart {
                    flags: Some((1..3).into()),
                    name: None,
                }
            ),
            span(3..4, Node::GroupEnd),
            span(13..15, Node::PerlClass),
            span(15..16, Node::UncountedRepetition),
            span(17..25, Node::Comment),
            span(
                34..35,
                Node::GroupStart {
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
                Node::GroupStart {
                    flags: Some((44..47).into()),
                    name: None,
                }
            ),
            span(47..48, Node::GroupEnd),
            span(49..51, Node::PerlClass),
            span(
                51..54,
                Node::CountedRepetition(CountedRepetition::Exactly((52..53).into())),
            ),
            span(54..55, Node::GroupEnd),
            span(56..70, Node::Comment),
        ]
    );

    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(REGEX).unwrap();
    assert_eq!(dynamic_ast, AST);
}

#[test]
fn duplicate_capture_name() {
    let regex = r"(?<test>.)(?<test>.)";
    let err = try_validate(regex).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DuplicateCaptureName { prev_pos } if *prev_pos == (3..7));
    assert_eq!(err.pos(), 13..17);

    let regex = r"(?<test>.(?<test>.))";
    let err = try_validate(regex).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DuplicateCaptureName { prev_pos } if *prev_pos == (3..7));
    assert_eq!(err.pos(), 12..16);

    let regex = r"(?<t>.(?<test>.)(?P<t>\d))";
    let err = try_validate(regex).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DuplicateCaptureName { prev_pos } if *prev_pos == (3..4));
    assert_eq!(err.pos(), 20..21);
}

#[test]
fn parsing_regex_with_many_comments() {
    const REGEX: &str = r"(?x) \d{
        # comment
        # comment
        # comment
        # comment
        # comment
        1,
        # comment
        # comment
        # comment
        # comment
        # comment
        # comment
        # comment
        2 }
    ";

    let dynamic_ast = RegexOptions::DEFAULT.try_parse_to_vec(REGEX).unwrap();
    let mut comment_count = 0;
    for span in &dynamic_ast {
        if matches!(span.node, Node::Comment) {
            comment_count += 1;
            let comment_str = &REGEX[ops::Range::from(span.span)];
            assert!(comment_str.starts_with('#'), "{comment_str}");
            assert!(comment_str.ends_with("comment"), "{comment_str}");
        }
    }
    assert_eq!(comment_count, 2, "{dynamic_ast:#?}");
}

#[test]
fn parsing_boundaries() {
    const AST: &[Spanned] = parse!(r"\b|.|");

    assert_eq!(
        AST,
        [
            span(0..2, Node::StdAssertion),
            span(2..3, Node::Alteration),
            span(3..4, Node::Dot),
            span(4..5, Node::Alteration),
        ]
    );
}
