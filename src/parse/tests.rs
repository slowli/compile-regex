//! Low-level parsing tests.

use assert_matches::assert_matches;
use regex_syntax::{
    ast,
    ast::parse::{Parser, ParserBuilder},
};

use super::*;
use crate::try_validate;

#[test]
fn parsing_uncounted_repetition() {
    let repetitions = ["a*", "a+", "a?", "a*?", "a??", "a+?"];
    for rep in repetitions {
        let mut state = ParseState::new(rep, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        state.parse_uncounted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let invalid_repetitions = ["*", "?", "+"];
    for rep in invalid_repetitions {
        let mut state = ParseState::new(rep, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::MissingRepetition);
        assert_eq!(err.pos(), 0..1);
    }
}

#[test]
fn gobbling_whitespace() {
    let mut state = ParseState::<2>::custom(
        "  # Comment\n\t # Another comment",
        RegexOptions::DEFAULT,
        true,
    );
    state.ignore_whitespace = true;

    state.gobble_whitespace_and_comments().unwrap();
    assert!(state.is_eof(), "{state:#?}");
    let spans = state.into_spans();
    assert_eq!(spans.as_slice().len(), 2);
    assert!(spans
        .as_slice()
        .iter()
        .all(|span| matches!(span.node, Ast::Comment)));
}

#[test]
fn missing_repetition_with_flags() {
    let err = try_validate("(?U)*").unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 4..5);

    let err = try_validate(".(?-x)+?").unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 6..7);

    let err = try_validate("(?U){3,}").unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 4..5);
}

#[test]
fn parsing_counted_repetition() {
    let repetitions = ["a{5}", "a{5}?", "a{2,5}", "a{2,5}?", "a{2,}", "a{2,}?"];
    for rep in repetitions {
        let mut state = ParseState::new(rep, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        state.parse_counted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let repetitions_with_whitespace = ["a{ 5 }", "a{ 5\t}?", "a{2, 5}", "a{ 2 , 5 }?", "a{ 2,}"];
    for rep in repetitions_with_whitespace {
        let mut state = ParseState::new(rep, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        state.parse_counted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let mut state = ParseState::new("{5}", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("a{what}", RegexOptions::DEFAULT);
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let mut state = ParseState::new("a{}", RegexOptions::DEFAULT);
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let mut state = ParseState::new("a{9876543210}", RegexOptions::DEFAULT);
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidDecimal);
    assert_eq!(err.pos(), 2..12);

    let mut state = ParseState::new("a{5,2}", RegexOptions::DEFAULT);
    assert!(state.step().unwrap().is_continue());
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRepetitionRange);
    assert_eq!(err.pos(), 1..5);
}

#[test]
fn parsing_counted_repetition_with_whitespace() {
    let repetitions_with_whitespace = [
        "a{ # start\n5 }",
        "a{ 5 # end\n } ?",
        "a{# start\n2#middle\n ,#end\n5 # five\n}",
    ];
    for rep in repetitions_with_whitespace {
        println!("Testing {rep}");
        ParserBuilder::new()
            .ignore_whitespace(true)
            .build()
            .parse(rep)
            .unwrap();

        let mut state = ParseState::new(rep, RegexOptions::DEFAULT.ignore_whitespace(true));
        assert!(state.step().unwrap().is_continue());
        state.parse_counted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }
}

#[test]
fn parsing_escaped_chars() {
    let escaped_chars = [
        "\\d", "\\D", "\\s", "\\{", "\\)", "\\$", "\\.", "\\n", "\\f", "\\t", "\\b",
    ];
    for pat in escaped_chars {
        println!("Testing {pat}");
        let mut state = ParseState::new(pat, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, pat.len());
    }

    let mut state = ParseState::new("\\", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("\\д", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("\\0", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedBackref);
    assert_eq!(err.pos(), 0..2);

    let mut state = ParseState::new("\\Y", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedEscape);
    assert_eq!(err.pos(), 0..2);
}

#[test]
fn parsing_word_boundaries() {
    let boundaries = [r"\b{start}", r"\b{end}", r"\b{start-half}", r"\b{end-half}"];
    for boundary in boundaries {
        println!("Testing {boundary}");
        let mut state = ParseState::new(boundary, RegexOptions::DEFAULT);
        assert_matches!(state.parse_escape().unwrap(), PrimitiveKind::Other);
        assert_eq!(state.pos, boundary.len());
    }
}

#[test]
fn parsing_word_boundaries_with_whitespace() {
    let boundaries = [
        r"\b{ start }",
        "\\b{ end # maybe?\n }",
        "\\b{\tstart-half\t}",
        "\\b{# end \n  end-half # !\n # ??\n }",
    ];
    for boundary in boundaries {
        println!("Testing {boundary}");
        ParserBuilder::new()
            .ignore_whitespace(true)
            .build()
            .parse(boundary)
            .unwrap();

        let mut state = ParseState::new(boundary, RegexOptions::DEFAULT.ignore_whitespace(true));
        assert_matches!(state.parse_escape().unwrap(), PrimitiveKind::Other);
        assert_eq!(state.pos, boundary.len());
    }
}

#[test]
fn parsing_hex_digits() {
    let escapes = ["\\x0c", "\\x0A", "\\u077d", "\\uABCD", "\\U0001234A"];
    for esc in escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x", "\\x0", "\\u977", "\\U1234"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let non_hex_escapes = ["\\x0g", "\\u977l", "\\U1234w"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let invalid_char_escapes = ["\\uD800", "\\U00110000"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
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
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x{", "\\u{0", "\\U{123"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let mut state = ParseState::new("\\u{}", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyHex);
    assert_eq!(err.pos(), 0..4);

    let non_hex_escapes = ["\\x{0g}", "\\u{97l}", "\\U{1234 }"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len() - 1); // the invalid hex digit is always the last one
    }

    let invalid_char_escapes = ["\\x{D800}", "\\U{110001}"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let mut state = ParseState::new(esc, RegexOptions::DEFAULT);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let mut state = ParseState::new("\\u{ddddddddd}", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
    assert_eq!(err.pos(), 0..11);
}

#[test]
fn parsing_group() {
    let groups = ["()", "(?<group>)", "(?P<u.w0t[1]>)"];
    for group in groups {
        println!("Testing {group}");
        let mut state = ParseState::new(group, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, group.len() - 1);
        assert_eq!(state.groups.len(), 1);
    }

    let mut state = ParseState::new("(", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedGroup);
    assert_eq!(err.pos(), 0..1);

    let mut state = ParseState::new("(?=.*)", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::LookaroundNotSupported);
    assert_eq!(err.pos(), 0..3);

    let mut state = ParseState::new("(?<>)", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyCaptureName);
    assert_eq!(err.pos(), 3..3);

    let mut state = ParseState::new("(?<$>)", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidCaptureName);
    assert_eq!(err.pos(), 3..4);

    let mut state = ParseState::new("(?<д>)", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonAsciiCaptureName);
    assert_eq!(err.pos(), 3..3); // FIXME: span the char

    let mut state = ParseState::new("(?<name", RegexOptions::DEFAULT);
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
fn regex_does_not_allow_whitespace_in_group_start() {
    let err = ParserBuilder::new()
        .ignore_whitespace(true)
        .build()
        .parse("(? <test>.*)")
        .unwrap_err();
    assert_matches!(err.kind(), ast::ErrorKind::FlagUnrecognized);

    let err = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_validate("(? <test>.*)")
        .unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedFlag);
    assert_eq!(err.pos(), 2..3);

    let err = ParserBuilder::new()
        .ignore_whitespace(true)
        .build()
        .parse("(?< test >.*)")
        .unwrap_err();
    assert_matches!(err.kind(), ast::ErrorKind::GroupNameInvalid);

    let err = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_validate("(?< test >.*)")
        .unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidCaptureName);
    assert_eq!(err.pos(), 3..4);
}

#[test]
fn controlling_whitespace_in_groups_via_flags() {
    let regex = "(?x) .*";
    let mut state = ParseState::new(regex, RegexOptions::DEFAULT);
    assert!(!state.ignore_whitespace);

    assert!(state.step().unwrap().is_continue());
    assert_eq!(state.pos, 4);
    assert!(state.ignore_whitespace);
    assert_eq!(state.groups.len(), 0);
}

#[test]
fn controlling_whitespace_in_groups_via_group_flags() {
    let regex = "(?x: .* ){2,}";
    let mut state = ParseState::new(regex, RegexOptions::DEFAULT);
    assert!(!state.ignore_whitespace);

    assert!(state.step().unwrap().is_continue());
    assert_eq!(state.pos, 4);
    assert!(state.ignore_whitespace);
    assert_eq!(state.groups.len(), 1);

    while state.groups.len() > 0 {
        assert!(state.step().unwrap().is_continue());
    }
    assert_eq!(state.pos, 9);
    assert!(!state.ignore_whitespace);
}

#[test]
fn parsing_set() {
    let simple_sets = ["[]]", "[^]]", "[abc]", "[a-z]", "[A-Za-z-]", r"[\t\.]"];
    for set in simple_sets {
        println!("Testing {set}");
        let mut state = ParseState::new(set, RegexOptions::DEFAULT);
        assert!(state.step().unwrap().is_continue());
        assert_eq!(state.pos, set.len());
    }

    let sets_with_invalid_escapes = [r"[\b]", r"[\>a]", r"[^\A]"];
    for set in sets_with_invalid_escapes {
        println!("Testing {set}");
        let err = try_validate(set).unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidEscapeInSet);
    }

    let mut state = ParseState::new("[]", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedSet);

    let mut state = ParseState::new(r"[\>-a]", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRangeStart);
    assert_eq!(err.pos(), 1..3);

    let mut state = ParseState::new(r"[a-\>]", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRangeEnd);
    assert_eq!(err.pos(), 3..5);

    let mut state = ParseState::new(r"[_a-Z]", RegexOptions::DEFAULT);
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidRange);
    assert_eq!(err.pos(), 2..5);
}

#[test]
fn parsing_set_with_whitespace() {
    let sets = [r"[ ^ ] ]", r"[ ^ - -   1-9 ]"];
    for set in sets {
        println!("Testing {set}");
        ParserBuilder::new()
            .ignore_whitespace(true)
            .build()
            .parse(set)
            .unwrap();

        let ast = RegexOptions::DEFAULT
            .ignore_whitespace(true)
            .try_parse::<16>(set)
            .unwrap();
        let ast = ast.as_slice();
        assert_matches!(ast[0].node, Ast::SetStart { .. });
        assert_eq!(ast[0].range.start, 0);

        let last_node = ast.last().unwrap();
        assert_matches!(last_node.node, Ast::SetEnd);
        assert_eq!(last_node.range.start, set.len() - 1);
    }
}

#[test]
fn parsing_flags() {
    for flags_str in ["?i:", "?i)", "?isU:", "?-isU:"] {
        println!("Testing flags: {flags_str}");
        let mut state = ParseState::new(flags_str, RegexOptions::DEFAULT);
        let flags = state.parse_flags().unwrap();
        assert!(!flags.is_empty);
        assert_eq!(flags.ignore_whitespace, None);
        assert_eq!(state.pos, flags_str.len() - 1);
    }

    let mut state = ParseState::new("?i", RegexOptions::DEFAULT);
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedFlags);
    assert_eq!(err.pos(), 0..2);

    let mut state = ParseState::new("?i-:", RegexOptions::DEFAULT);
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedFlagsNegation);
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?i--s:", RegexOptions::DEFAULT);
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::RepeatedFlagNegation);
    assert_eq!(err.pos(), 3..4);

    let mut state = ParseState::new("?iX:", RegexOptions::DEFAULT);
    let err = state.parse_flags().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedFlag);
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?ii:", RegexOptions::DEFAULT);
    let err = state.parse_flags().unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::RepeatedFlag {
            contradicting: false
        }
    );
    assert_eq!(err.pos(), 2..3);

    let mut state = ParseState::new("?i-i:", RegexOptions::DEFAULT);
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
fn countable_repetition_with_space() {
    // Check that `regex-syntax` indeed fails on this input.
    Parser::new().parse(r".{2, }").unwrap_err();

    let err = try_validate(r".{2, }").unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 4..5);
}

#[test]
fn disallowed_whitespace_errors() {
    let err = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_validate(".{2 3}")
        .unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DisallowedWhitespace);
    assert_eq!(err.pos(), 3..4);

    let err = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_validate(".{23, 12 3}")
        .unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DisallowedWhitespace);
    assert_eq!(err.pos(), 8..9);

    let err = RegexOptions::DEFAULT
        .ignore_whitespace(true)
        .try_validate(".{2# what?\n3}")
        .unwrap_err();
    assert_matches!(err.kind(), ErrorKind::DisallowedComment);
    assert_eq!(err.pos(), 3..4);
}
