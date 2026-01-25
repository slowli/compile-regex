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
use compile_regex::{try_validate, ErrorKind};
use rand::{rngs::StdRng, seq::IteratorRandom, Rng, SeedableRng};
use regex_syntax::ast::{self, parse::Parser, Ast, ClassSetItem};

const ASCII_CHARS: ops::RangeInclusive<char> = ' '..='\x7f';

struct UnsupportedChecker;

impl ast::Visitor for UnsupportedChecker {
    type Output = ();
    type Err = ();

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(())
    }

    fn visit_pre(&mut self, ast: &Ast) -> Result<(), Self::Err> {
        fn is_unsupported_flags(flags: &ast::Flags) -> bool {
            flags.flag_state(ast::Flag::IgnoreWhitespace) == Some(true)
        }

        match ast {
            Ast::ClassUnicode(_) => Err(()),
            Ast::Flags(flags) if is_unsupported_flags(&flags.flags) => Err(()),
            Ast::Group(group) if group.flags().is_some_and(is_unsupported_flags) => Err(()),
            _ => Ok(()),
        }
    }

    fn visit_class_set_item_pre(&mut self, ast: &ClassSetItem) -> Result<(), Self::Err> {
        match ast {
            ClassSetItem::Unicode(_) => Err(()),
            _ => Ok(()),
        }
    }
}

fn is_unsupported(ast: &Ast) -> bool {
    ast::visit(ast, UnsupportedChecker).is_err()
}

fn is_unsupported_error(err: &ErrorKind) -> bool {
    matches!(
        err,
        ErrorKind::UnicodeClassesNotSupported | ErrorKind::UnsupportedWhitespaceFlag
    )
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

    let ast = Parser::new().parse(r"(?x).*").unwrap();
    assert!(is_unsupported(&ast));
    let ast = Parser::new().parse(r"(?-sx)").unwrap();
    assert!(!is_unsupported(&ast));
    let ast = Parser::new().parse(r"(?sx:)").unwrap();
    assert!(is_unsupported(&ast));
    let ast = Parser::new().parse(r"(?-x).*").unwrap();
    assert!(!is_unsupported(&ast));
}

// TODO: allow constraining group names, so that duplicate names can be hit

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
    errors: usize,
    invalid_asts: usize,
    unsupported: usize,
}

/// Returns `true` iff `ast_str` is a valid regex as per both parsers.
fn test_regex(ast_str: &str, stats: &mut Stats) -> bool {
    stats.total += 1;

    let ast = match Parser::new().parse(ast_str) {
        Ok(ast) => ast,
        Err(err) => {
            if try_validate(ast_str).is_ok() {
                println!(
                    "Expected {ast_str:?} to be unparseable, but its parsing succeeded\n\
                        regex-syntax error: {err}"
                );
                stats.errors += 1;
                return false;
            };

            stats.invalid_asts += 1;
            return false;
        }
    };

    if is_unsupported(&ast) {
        let err = match try_validate(ast_str) {
            Ok(()) => {
                println!("expected regex {ast_str:?} with unsupported features to fail, but it succeeded");
                stats.errors += 1;
                return false;
            }
            Err(err) => err,
        };
        if !is_unsupported_error(err.kind()) {
            println!(
                "regex {ast_str:?} w/ unsupported features failed with unexpected error: {err}"
            );
            stats.errors += 1;
            return false;
        }

        stats.unsupported += 1;
        return false;
    }

    if let Err(err) = try_validate(ast_str) {
        println!("failed validating {ast_str:?}: {err}");
        stats.errors += 1;
        false
    } else {
        true
    }
}

fn test_valid_regex_is_accepted<const INPUT_LEN: usize>(
    sample_count: usize,
    replacement_chars: ops::RangeInclusive<char>,
) {
    const RNG_SEED: u64 = 123;
    /// Probability to remove a char when mutating a regex string.
    const REMOVE_P: f64 = 0.2;
    /// Probability to insert a char when mutating a regex string.
    const INSERT_P: f64 = 0.2;

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut stats = Stats::default();
    for i in 0..sample_count {
        let input: [u8; 1_024] = rng.random();
        let Ok(ast) = Ast::arbitrary(&mut Unstructured::new(&input)) else {
            stats.skips += 1;
            continue;
        };

        let ast_str = ast.to_string();
        if !test_regex(&ast_str, &mut stats) || ast_str.is_empty() {
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
                let ch = rng.random_range(replacement_chars.clone());
                ast_str.insert(mutated_pos, ch);
            }

            test_regex(&ast_str, &mut stats);
        }

        if (i + 1) % 10_000 == 0 {
            println!("Partial test stats: {stats:?}");
        }
    }

    println!("Test stats: {stats:?}");
    if stats.errors > 0 {
        panic!("There were {} errors (printed above)", stats.errors);
    }
}

#[test]
fn valid_regex_is_accepted_ascii_256b_input() {
    test_valid_regex_is_accepted::<256>(sample_count(), ASCII_CHARS);
}

#[test]
fn valid_regex_is_accepted_ascii_1kb_input() {
    test_valid_regex_is_accepted::<1_024>(sample_count(), ASCII_CHARS);
}
