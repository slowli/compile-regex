//! Checks correspondence between ASTs produced by `regex-syntax` and `compile-regex`.

use std::convert::Infallible;

use arbitrary::{Arbitrary, Unstructured};
use assert_matches::assert_matches;
use compile_regex::{ErrorKind, RegexOptions, SyntaxSpan};
use rand::{prelude::StdRng, Rng, SeedableRng};
use regex_syntax::{
    ast,
    ast::{parse::Parser, Ast},
};

use crate::{is_unsupported, sample_count};

fn map_span(span: ast::Span) -> compile_regex::Range {
    compile_regex::Range::new(span.start.offset, span.end.offset)
}

#[derive(Debug)]
struct SpansCollector<'a> {
    regex_str: &'a str,
    spans: Vec<SyntaxSpan>,
}

impl<'a> SpansCollector<'a> {
    fn new(regex_str: &'a str) -> Self {
        Self {
            regex_str,
            spans: vec![],
        }
    }

    fn push_lit(&mut self, lit: &ast::Literal) {
        let node = match lit.kind {
            ast::LiteralKind::HexFixed(_) | ast::LiteralKind::HexBrace(_) => {
                compile_regex::Ast::HexEscape
            }
            ast::LiteralKind::Meta => compile_regex::Ast::EscapedChar { meta: true },
            ast::LiteralKind::Special(_) => compile_regex::Ast::EscapedLiteral,
            ast::LiteralKind::Verbatim => return,
            _ => compile_regex::Ast::EscapedChar { meta: false },
        };
        self.spans.push(SyntaxSpan {
            node,
            range: map_span(lit.span),
        });
    }

    fn push_bracketed(&mut self, cls: &ast::ClassBracketed) {
        let start_offset = cls.span.start.offset;
        let end_offset = cls.span.end.offset;

        self.spans.push(SyntaxSpan {
            node: compile_regex::Ast::SetStart {
                negation: cls.negated.then_some(DUMMY_RANGE),
            },
            range: compile_regex::Range::new(start_offset, start_offset + 1),
        });
        self.spans.push(SyntaxSpan {
            node: compile_regex::Ast::SetEnd,
            range: compile_regex::Range::new(end_offset - 1, end_offset),
        });
    }
}

const DUMMY_RANGE: compile_regex::Range = compile_regex::Range::new(usize::MAX - 1, usize::MAX);
const DUMMY_CAPTURE_NAME: compile_regex::GroupName = compile_regex::GroupName {
    start: DUMMY_RANGE,
    name: DUMMY_RANGE,
    end: DUMMY_RANGE,
};

impl ast::Visitor for SpansCollector<'_> {
    type Output = Vec<SyntaxSpan>;
    type Err = Infallible;

    fn finish(mut self) -> Result<Self::Output, Self::Err> {
        self.spans.sort_unstable_by_key(|span| span.range.start);
        Ok(self.spans)
    }

    fn visit_pre(&mut self, ast: &Ast) -> Result<(), Self::Err> {
        match ast {
            Ast::Empty(_) => { /* Do nothing */ }
            Ast::Flags(flags) => {
                let start = flags.span.start.offset;
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::GroupStart {
                        name: None,
                        flags: Some(DUMMY_RANGE),
                    },
                    range: compile_regex::Range::new(start, start + 1),
                });

                let end = flags.span.end.offset;
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::GroupEnd,
                    range: compile_regex::Range::new(end - 1, end),
                });
            }
            Ast::Literal(lit) => {
                self.push_lit(lit);
            }
            Ast::Dot(dot) => self.spans.push(SyntaxSpan {
                node: compile_regex::Ast::Dot,
                range: map_span(**dot),
            }),
            Ast::Assertion(assertion) => {
                self.spans.push(SyntaxSpan {
                    node: match assertion.kind {
                        ast::AssertionKind::StartLine | ast::AssertionKind::EndLine => {
                            compile_regex::Ast::LineAssertion
                        }
                        _ => compile_regex::Ast::StdAssertion,
                    },
                    range: map_span(assertion.span),
                });
            }
            Ast::ClassUnicode(_) => unreachable!(),
            Ast::ClassPerl(perl) => {
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::PerlClass,
                    range: map_span(perl.span),
                });
            }
            Ast::ClassBracketed(cls) => {
                self.push_bracketed(cls);
            }
            Ast::Repetition(rep) => {
                let range = map_span(rep.op.span);
                let node = match &rep.op.kind {
                    ast::RepetitionKind::Range(rep_range) => {
                        let rep = match rep_range {
                            ast::RepetitionRange::Exactly(_) => {
                                compile_regex::CountedRepetition::Exactly(DUMMY_RANGE)
                            }
                            ast::RepetitionRange::AtLeast(_) => {
                                compile_regex::CountedRepetition::AtLeast(DUMMY_RANGE)
                            }
                            ast::RepetitionRange::Bounded(..) => {
                                compile_regex::CountedRepetition::Between(DUMMY_RANGE, DUMMY_RANGE)
                            }
                        };
                        compile_regex::Ast::CountedRepetition(rep)
                    }
                    _ => compile_regex::Ast::UncountedRepetition,
                };
                self.spans.push(SyntaxSpan { node, range });
            }
            Ast::Group(group) => {
                let start_offset = group.span.start.offset;
                let end_offset = group.span.end.offset;
                let (name, flags) = match &group.kind {
                    ast::GroupKind::CaptureName { .. } => (Some(DUMMY_CAPTURE_NAME), None),
                    ast::GroupKind::NonCapturing(flags) if !flags.items.is_empty() => {
                        (None, Some(DUMMY_RANGE))
                    }
                    _ => (None, None),
                };

                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::GroupStart { name, flags },
                    range: compile_regex::Range::new(start_offset, start_offset + 1),
                });
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::GroupEnd,
                    range: compile_regex::Range::new(end_offset - 1, end_offset),
                });
            }
            Ast::Alternation(alt) => {
                for neighbors in alt.asts.windows(2) {
                    let [prev, next] = neighbors else {
                        unreachable!();
                    };
                    let alt_char_range = prev.span().end.offset..next.span().start.offset;
                    assert!(!alt_char_range.is_empty());

                    let mut alt_char_pos = self.regex_str[alt_char_range].find('|').unwrap();
                    alt_char_pos += prev.span().end.offset;

                    self.spans.push(SyntaxSpan {
                        node: compile_regex::Ast::Alteration,
                        range: compile_regex::Range::new(alt_char_pos, alt_char_pos + 1),
                    });
                }
            }
            Ast::Concat(_) => {}
        }
        Ok(())
    }

    fn visit_class_set_item_pre(&mut self, ast: &ast::ClassSetItem) -> Result<(), Self::Err> {
        match ast {
            ast::ClassSetItem::Range(range) => {
                self.push_lit(&range.start);

                let lhs_end = range.start.span.end.offset;
                let rhs_start = range.end.span.start.offset;
                let mut range_pos = self.regex_str[lhs_end..rhs_start].find('-').unwrap();
                range_pos += lhs_end;
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::SetRange,
                    range: compile_regex::Range::new(range_pos, range_pos + 1),
                });

                self.push_lit(&range.end);
            }
            ast::ClassSetItem::Ascii(cls) => {
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::AsciiClass,
                    range: map_span(cls.span),
                });
            }
            ast::ClassSetItem::Literal(lit) => {
                self.push_lit(lit);
            }
            ast::ClassSetItem::Perl(perl) => {
                self.spans.push(SyntaxSpan {
                    node: compile_regex::Ast::PerlClass,
                    range: map_span(perl.span),
                });
            }
            ast::ClassSetItem::Bracketed(cls) => {
                self.push_bracketed(cls);
            }
            _ => { /* do nothing */ }
        }
        Ok(())
    }

    fn visit_class_set_binary_op_pre(
        &mut self,
        ast: &ast::ClassSetBinaryOp,
    ) -> Result<(), Self::Err> {
        let lhs_end = ast.lhs.span().end.offset;
        let rhs_start = ast.rhs.span().start.offset;
        let op_str = match ast.kind {
            ast::ClassSetBinaryOpKind::Intersection => "&&",
            ast::ClassSetBinaryOpKind::Difference => "--",
            ast::ClassSetBinaryOpKind::SymmetricDifference => "~~",
        };
        let mut op_pos = self.regex_str[lhs_end..rhs_start].find(op_str).unwrap();
        op_pos += lhs_end;

        self.spans.push(SyntaxSpan {
            node: compile_regex::Ast::SetOp,
            range: compile_regex::Range::new(op_pos, op_pos + 2),
        });
        Ok(())
    }
}

fn assert_asts_match(regex: &str, expected: &Ast, mut actual: Vec<SyntaxSpan>) {
    actual.retain_mut(|span| {
        // Erase spans that are not captured by `regex-syntax`
        match &mut span.node {
            compile_regex::Ast::GroupStart { name, flags } => {
                if let Some(flags) = flags {
                    *flags = DUMMY_RANGE;
                }
                if let Some(name) = name {
                    *name = DUMMY_CAPTURE_NAME;
                }
            }

            compile_regex::Ast::SetStart {
                negation: Some(negation),
            } => {
                *negation = DUMMY_RANGE;
            }

            compile_regex::Ast::CountedRepetition(rep) => match rep {
                compile_regex::CountedRepetition::Exactly(range)
                | compile_regex::CountedRepetition::AtLeast(range) => {
                    *range = DUMMY_RANGE;
                }
                compile_regex::CountedRepetition::Between(from, to) => {
                    *from = DUMMY_RANGE;
                    *to = DUMMY_RANGE;
                }
            },

            compile_regex::Ast::Comment => return false,
            _ => { /* do nothing */ }
        }
        true
    });

    let expected_spans = ast::visit(expected, SpansCollector::new(regex)).unwrap();
    assert_eq!(actual, expected_spans, "{regex:?}");
}

#[test]
fn matching_asts_manual() {
    let regexes = [
        r"^wh\x40t(?<group>\t|\.\>){3, 5}?\d+\b{end}$",
        r"(?x) ^w h (\x40|\u{040}) # ascii escape
          t (?<group>
            \t | \ \.\> # named group
          ) { 3, 5 }? # non-greedy repetition
          \d+ $",
        r"(?x)
          \d+ # digits
          (?<color>(?-x)#\d{6}) # literal hash",
        r"[\d\x34\u0035-\u{37}[:digit:]&&[:^cntrl:]-]",
        r"[\d&&[^0-9]--4]",
    ];

    for regex in regexes {
        let ast = Parser::new().parse(regex).unwrap();
        let actual = RegexOptions::DEFAULT.try_parse_to_vec(regex).unwrap();
        assert_asts_match(regex, &ast, actual);
    }
}

fn test_regex_ast(ast_str: &str) {
    let Ok(ast) = Parser::new().parse(ast_str) else {
        return;
    };

    if is_unsupported(&ast) {
        return;
    }

    match RegexOptions::DEFAULT.try_parse_to_vec(ast_str) {
        Ok(parsed_ast) => {
            assert_asts_match(ast_str, &ast, parsed_ast);
        }
        Err(err) => {
            assert_matches!(
                err.kind(),
                ErrorKind::DisallowedWhitespace | ErrorKind::DisallowedComment
            );
        }
    }
}

fn test_regex_ast_match<const INPUT_LEN: usize>(rng_seed: u64, sample_count: usize) {
    let mut rng = StdRng::seed_from_u64(rng_seed);
    for _ in 0..sample_count {
        let input: [u8; INPUT_LEN] = rng.random();
        let Ok(ast) = Ast::arbitrary(&mut Unstructured::new(&input)) else {
            continue;
        };

        let ast_str = ast.to_string();
        test_regex_ast(&ast_str);
    }
}

#[test]
fn regex_ast_match_256b_input() {
    test_regex_ast_match::<256>(777, sample_count());
}

#[test]
fn regex_ast_match_1kb_input() {
    test_regex_ast_match::<1_024>(1_777, sample_count());
}
