use assert_matches::assert_matches;

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
    const AST: SyntaxSpans = parse(r"^wh\x40t(?<group>\t|\.\>){3,5}?\d+$");

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
                25..31,
                Ast::CountedRepetition {
                    min_or_exact_count: (26..27).into(),
                    max_count: Some((28..29).into()),
                }
            ),
            span(31..33, Ast::PerlClass),
            span(33..34, Ast::UncountedRepetition),
            span(34..35, Ast::LineAssertion),
        ]
    );
}

#[test]
fn parsing_uncounted_repetition() {
    let repetitions = ["a*", "a+", "a?", "a*?", "a??", "a+?"];
    for rep in repetitions {
        let mut state = ParseState::new(rep);
        assert!(state.step().unwrap().is_continue());
        state.parse_uncounted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let invalid_repetitions = ["*", "?", "+"];
    for rep in invalid_repetitions {
        let mut state = ParseState::new(rep);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::MissingRepetition);
        assert_eq!(err.pos(), 0..1);
    }
}

#[test]
fn parsing_counted_repetition() {
    let repetitions = ["a{5}", "a{5}?", "a{2,5}", "a{2,5}?", "a{2,}", "a{2,}?"];
    for rep in repetitions {
        let mut state = ParseState::new(rep);
        assert!(state.step().unwrap().is_continue());
        state.parse_counted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let mut state = ParseState::new("{5}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("a{what}");
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let mut state = ParseState::new("a{}");
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let mut state = ParseState::new("a{9876543210}");
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidDecimal);
    assert_eq!(err.pos(), 2..12);

    let mut state = ParseState::new("a{5,2}");
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRepetitionRange);
    assert_eq!(err.pos(), 1..5);
}

#[test]
fn parsing_escaped_chars() {
    let escaped_chars = [
        "\\d", "\\D", "\\s", "\\{", "\\)", "\\$", "\\.", "\\n", "\\f", "\\t", "\\b",
    ];
    for pat in escaped_chars {
        println!("Testing {pat}");
        let mut state = ParseState::new(pat);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, pat.len());
    }

    let mut state = ParseState::new("\\");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("\\д");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("\\0");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedBackref);
    assert_eq!(err.pos(), 0..2);

    let mut state = ParseState::new("\\Y");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedEscape);
    assert_eq!(err.pos(), 0..2);
}

#[test]
fn parsing_hex_digits() {
    let escapes = ["\\x0c", "\\x0A", "\\u077d", "\\uABCD", "\\U0001234A"];
    for esc in escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x", "\\x0", "\\u977", "\\U1234"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let non_hex_escapes = ["\\x0g", "\\u977l", "\\U1234w"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let invalid_char_escapes = ["\\uD800", "\\U00110000"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
        assert_eq!(err.pos(), 0..esc.len());
    }
}

#[test]
fn parsing_hex_brace() {
    let escapes = ["\\x{c}", "\\x{0A}", "\\x{077d}", "\\u{ABC}", "\\U{1234A}"];
    for esc in escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x{", "\\u{0", "\\U{123"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let mut state = ParseState::new("\\u{}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyHex);
    assert_eq!(err.pos(), 0..4);

    let non_hex_escapes = ["\\x{0g}", "\\u{97l}", "\\U{1234 }"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len() - 1); // the invalid hex digit is always the last one
    }

    let invalid_char_escapes = ["\\x{D800}", "\\U{110001}"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let mut state = ParseState::new("\\u{ddddddddd}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
    assert_eq!(err.pos(), 0..11);
}

#[test]
fn parsing_group() {
    let groups = ["()", "(?<group>)", "(?P<u.w0t[1]>)"];
    for group in groups {
        println!("Testing {group}");
        let mut state = ParseState::new(group);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, group.len() - 1);
        assert_eq!(state.group_depth, 1);
    }

    let mut state = ParseState::new("(");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedGroup);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("(?=.*)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::LookaroundNotSupported);
    assert_eq!(err.pos(), 0..3);

    let mut state = ParseState::new("(?<$>)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidCaptureName);
    assert_eq!(err.pos(), 3..4);

    let mut state = ParseState::new("(?<д>)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonAsciiCaptureName);
    assert_eq!(err.pos(), 3..3); // FIXME: span the char

    let mut state = ParseState::new("(?<name");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedCaptureName);
    assert_eq!(err.pos(), 3..7);
}

#[test]
fn unfinished_group_errors() {
    let unfinished_groups = ["(a", "((a+)", "((ab)c+"];
    for regex in unfinished_groups {
        let err = try_validate(regex).unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedGroup);
        assert_eq!(err.pos(), regex.len()..regex.len());
    }
}

#[test]
fn parsing_set() {
    let simple_sets = ["[]]", "[^]]", "[abc]", "[a-z]", "[A-Za-z-]", r"[\t\.]"];
    for set in simple_sets {
        println!("Testing {set}");
        let mut state = ParseState::new(set);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, set.len());
    }

    let mut state = ParseState::new("[]");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedSet);

    let mut state = ParseState::new(r"[\>-a]");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRangeStart);
    assert_eq!(err.pos(), 1..3);

    let mut state = ParseState::new(r"[a-\>]");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRangeEnd);
    assert_eq!(err.pos(), 3..5);

    let mut state = ParseState::new(r"[_a-Z]");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRange);
    assert_eq!(err.pos(), 2..5);
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
fn parsing_flags() {
    for flags_str in ["?i:", "?i)", "?isU:", "?-isU:"] {
        println!("Testing flags: {flags_str}");
        let mut state = ParseState::new(flags_str);
        let flags = state.parse_flags().unwrap();
        assert!(!flags.is_empty);
        assert_eq!(flags.ignore_whitespace, None);
        assert_eq!(state.pos, flags_str.len() - 1);
    }

    let mut state = ParseState::new("?i");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedFlags);
    assert_eq!(err.pos(), 0..2);

    let mut state = ParseState::new("?i-:");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedFlagsNegation);
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?i--s:");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::RepeatedFlagNegation);
    assert_eq!(err.pos(), 3..4);

    let mut state = ParseState::new("?iX:");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedFlag);
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?ii:");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::RepeatedFlag {
            contradicting: false
        }
    );
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?i-i:");
    let err = state.parse_flags().unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::RepeatedFlag {
            contradicting: true
        }
    );
    assert_eq!(err.pos(), 3..4);

    let err = try_validate("(?)").unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 0..3);
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
