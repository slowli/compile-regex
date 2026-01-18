use assert_matches::assert_matches;

use super::*;

#[test]
fn parsing_uncounted_repetition() {
    let repetitions = ["a*", "a+", "a?", "a*?", "a??", "a+?"];
    for rep in repetitions {
        let state = ParseState::new(rep);
        let state = state.step().unwrap().expect("no new state");
        let state = state.parse_uncounted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let invalid_repetitions = ["*", "?", "+"];
    for rep in invalid_repetitions {
        let state = ParseState::new(rep);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::MissingRepetition);
        assert_eq!(err.pos(), 0..1);
    }
}

#[test]
fn parsing_counted_repetition() {
    let repetitions = ["a{5}", "a{5}?", "a{2,5}", "a{2,5}?"];
    for rep in repetitions {
        let state = ParseState::new(rep);
        let state = state.step().unwrap().expect("no new state");
        let state = state.parse_counted_repetition().unwrap();
        assert_eq!(state.pos, rep.len());
    }

    let state = ParseState::new("{5}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MissingRepetition);
    assert_eq!(err.pos(), 0..1);

    let state = ParseState::new("a{what}");
    let state = state.step().unwrap().expect("no new state");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let state = ParseState::new("a{}");
    let state = state.step().unwrap().expect("no new state");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyDecimal);
    assert_eq!(err.pos(), 2..2);

    let state = ParseState::new("a{9876543210}");
    let state = state.step().unwrap().expect("no new state");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidDecimal);
    assert_eq!(err.pos(), 2..12);

    let state = ParseState::new("a{5,2}");
    let state = state.step().unwrap().expect("no new state");
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
        let state = ParseState::new(pat);
        let state = state.step().unwrap().expect("no new state");
        assert_eq!(state.pos, pat.len());
    }

    let state = ParseState::new("\\");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let state = ParseState::new("\\д");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
    assert_eq!(err.pos(), 0..1);

    let state = ParseState::new("\\0");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedBackref);
    assert_eq!(err.pos(), 0..2);

    let state = ParseState::new("\\Y");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnsupportedEscape);
    assert_eq!(err.pos(), 0..2);
}

#[test]
fn parsing_hex_digits() {
    let escapes = ["\\x0c", "\\x0A", "\\u077d", "\\uABCD", "\\U0001234A"];
    for esc in escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let state = state.step().unwrap().expect("no new state");
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x", "\\x0", "\\u977", "\\U1234"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let non_hex_escapes = ["\\x0g", "\\u977l", "\\U1234w"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let invalid_char_escapes = ["\\uD800", "\\U00110000"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
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
        let state = ParseState::new(esc);
        let state = state.step().unwrap().expect("no new state");
        assert_eq!(state.pos, esc.len());
    }

    let unfinished_escapes = ["\\x{", "\\u{0", "\\U{123"];
    for esc in unfinished_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedEscape);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let state = ParseState::new("\\u{}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::EmptyHex);
    assert_eq!(err.pos(), 0..4);

    let non_hex_escapes = ["\\x{0g}", "\\u{97l}", "\\U{1234 }"];
    for esc in non_hex_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::InvalidHex);
        assert_eq!(err.pos(), 0..esc.len() - 1); // the invalid hex digit is always the last one
    }

    let invalid_char_escapes = ["\\x{D800}", "\\U{110001}"];
    for esc in invalid_char_escapes {
        println!("Testing {esc}");
        let state = ParseState::new(esc);
        let err = state.step().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
        assert_eq!(err.pos(), 0..esc.len());
    }

    let state = ParseState::new("\\u{ddddddddd}");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonUnicodeHex);
    assert_eq!(err.pos(), 0..11);
}

#[test]
fn parsing_group() {
    let groups = ["()", "(?<group>)", "(?P<u.w0t[1]>)"];
    for group in groups {
        println!("Testing {group}");
        let state = ParseState::new(group);
        let state = state.step().unwrap().expect("no new state");
        assert_eq!(state.pos, group.len() - 1);
        assert_eq!(state.group_depth, 1);
    }

    let state = ParseState::new("(");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedGroup);
    assert_eq!(err.pos(), 0..1);

    let state = ParseState::new("(?=.*)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::LookaroundNotSupported);
    assert_eq!(err.pos(), 0..3);

    let state = ParseState::new("(?<$>)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::InvalidCaptureName);
    assert_eq!(err.pos(), 3..4);

    let state = ParseState::new("(?<д>)");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::NonAsciiCaptureName);
    assert_eq!(err.pos(), 3..3); // FIXME: span the char

    let state = ParseState::new("(?<name");
    let err = state.step().unwrap_err();
    assert_matches!(err.kind(), ErrorKind::UnfinishedCaptureName);
    assert_eq!(err.pos(), 3..7);
}
