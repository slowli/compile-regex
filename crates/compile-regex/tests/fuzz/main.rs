//! High level regex AST fuzzing.
//!
//! Supposed to be run in the release mode, with the `PROPTEST_CASES` env var specifying the number of base cases
//! to generate for each test:
//!
//! ```shell
//! PROPTEST_CASES=1000000 cargo test --release --test fuzz
//! ```

use std::{env, ops};

use arbitrary::{Arbitrary, Unstructured};
use compile_regex::{try_validate, Error, ErrorKind, RegexOptions};
use rand::{rngs::StdRng, seq::IteratorRandom, Rng, SeedableRng};
use regex_syntax::ast::{
    self,
    parse::{Parser, ParserBuilder},
    Ast,
};

const ASCII_CHARS: ops::RangeInclusive<char> = ' '..='\x7f';
const ASCII_WHITESPACE: [char; 4] = [' ', '\t', '\n', '#'];

mod ast_match;

struct UnsupportedChecker;

impl ast::Visitor for UnsupportedChecker {
    type Output = ();
    type Err = ();

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(())
    }

    fn visit_pre(&mut self, ast: &Ast) -> Result<(), Self::Err> {
        match ast {
            Ast::ClassUnicode(_) => Err(()),
            _ => Ok(()),
        }
    }

    fn visit_class_set_item_pre(&mut self, ast: &ast::ClassSetItem) -> Result<(), Self::Err> {
        match ast {
            ast::ClassSetItem::Unicode(_) => Err(()),
            _ => Ok(()),
        }
    }
}

fn is_unsupported(ast: &Ast) -> bool {
    ast::visit(ast, UnsupportedChecker).is_err()
}

fn is_unsupported_error(err: &ErrorKind) -> bool {
    matches!(err, ErrorKind::UnicodeClassesNotSupported)
}

#[test]
fn unsupported_visitor_works() {
    let ast = Parser::new().parse("^.*$").unwrap();
    assert!(!is_unsupported(&ast));
    let ast = Parser::new().parse(r"\p1").unwrap();
    assert!(is_unsupported(&ast));
    let ast = Parser::new().parse(r"\p1{2,5}").unwrap();
    assert!(is_unsupported(&ast));
    let ast = Parser::new().parse(r"\P1{3}").unwrap();
    assert!(is_unsupported(&ast));
    let ast = Parser::new().parse(r"[a\p1]{3}").unwrap();
    assert!(is_unsupported(&ast));
}

fn sample_count() -> usize {
    if let Ok(cases) = env::var("PROPTEST_CASES") {
        cases
            .parse()
            .expect("PROPTEST_CASES env var is not an integer")
    } else {
        1_000 // This is small, but works in the debug mode
    }
}

#[derive(Debug, Default)]
struct Stats {
    total: usize,
    skips: usize,
    invalid_asts: usize,
    unsupported: usize,
    stricter_ws_control: usize,
}

/// Returns `true` iff `ast_str` is a valid regex as per both parsers.
fn test_regex(ast_str: &str, ws: bool, stats: &mut Stats) -> bool {
    stats.total += 1;

    let validate_fn: fn(&str) -> Result<(), Error> = if ws {
        |regex| {
            RegexOptions::DEFAULT
                .ignore_whitespace(true)
                .try_validate(regex)
                .map(drop)
        }
    } else {
        try_validate
    };

    let mut parser = ParserBuilder::new().ignore_whitespace(ws).build();
    let ast = match parser.parse(ast_str) {
        Ok(ast) => ast,
        Err(err) => {
            assert!(
                validate_fn(ast_str).is_err(),
                "Expected {ast_str:?} to be unparseable, but its parsing succeeded\n\
                 regex-syntax error: {err}"
            );

            stats.invalid_asts += 1;
            return false;
        }
    };

    if is_unsupported(&ast) {
        let Err(err) = validate_fn(ast_str) else {
            panic!(
                "expected regex {ast_str:?} with unsupported features to fail, but it succeeded"
            );
        };
        assert!(
            is_unsupported_error(err.kind()),
            "regex {ast_str:?} w/ unsupported features failed with unexpected error: {err}"
        );

        stats.unsupported += 1;
        return false;
    }

    if let Err(err) = validate_fn(ast_str) {
        if matches!(
            err.kind(),
            ErrorKind::DisallowedWhitespace | ErrorKind::DisallowedComment
        ) {
            // TODO: check that whitespace is ignored at error location
            stats.stricter_ws_control += 1;
        } else {
            panic!("failed validating {ast_str:?}: {err}");
        }
        false
    } else {
        true
    }
}

fn test_valid_regex_is_accepted<const INPUT_LEN: usize>(
    rng_seed: u64,
    ws: bool,
    sample_count: usize,
    replacement_chars: &(impl Iterator<Item = char> + Clone),
) {
    /// Probability to remove a char when mutating a regex string.
    const REMOVE_P: f64 = 0.2;
    /// Probability to insert a char when mutating a regex string.
    const INSERT_P: f64 = 0.2;

    let mut rng = StdRng::seed_from_u64(rng_seed);
    let mut stats = Stats::default();
    for i in 0..sample_count {
        let input: [u8; INPUT_LEN] = rng.random();
        let Ok(ast) = Ast::arbitrary(&mut Unstructured::new(&input)) else {
            stats.skips += 1;
            continue;
        };

        let ast_str = ast.to_string();
        if !test_regex(&ast_str, ws, &mut stats) || ast_str.is_empty() {
            continue;
        }

        for _ in 0..10 {
            // Mutate a string in a single place, so it's close to a parseable regex
            let mut ast_str = ast_str.clone();
            let (mutated_pos, _) = ast_str.char_indices().choose(&mut rng).unwrap();

            let observed = rng.random_range(0.0..=1.0);
            let (is_removed, is_inserted) = if observed <= REMOVE_P {
                (true, false)
            } else if observed <= REMOVE_P + INSERT_P {
                (false, true)
            } else {
                (true, true)
            };

            if is_removed {
                ast_str.remove(mutated_pos);
            }
            if is_inserted {
                let ch = replacement_chars.clone().choose(&mut rng).unwrap();
                ast_str.insert(mutated_pos, ch);
            }

            test_regex(&ast_str, ws, &mut stats);
        }

        if (i + 1) % 10_000 == 0 {
            println!("Partial test stats: {stats:?}");
        }
    }

    println!("Test stats: {stats:?}");
}

#[test]
fn valid_regex_is_accepted_ascii_256b_input() {
    test_valid_regex_is_accepted::<256>(123, false, sample_count(), &ASCII_CHARS);
}

#[test]
fn valid_regex_is_accepted_256b_input_ws_replacement() {
    test_valid_regex_is_accepted::<256>(555, false, sample_count(), &ASCII_WHITESPACE.into_iter());
}

#[test]
fn valid_ws_regex_is_accepted_ascii_256b_input() {
    test_valid_regex_is_accepted::<256>(321, true, sample_count(), &ASCII_CHARS);
}

#[test]
fn valid_regex_is_accepted_ascii_1kb_input() {
    test_valid_regex_is_accepted::<1_024>(111, false, sample_count(), &ASCII_CHARS);
}
