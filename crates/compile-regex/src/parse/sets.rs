//! Parsing character sets.

use super::{types::PrimitiveKind, ParseState, SyntaxOrLen};
use crate::{
    ast::{Node, Span},
    utils::split_first_char,
    Error, ErrorKind,
};

impl<const CAP: usize> ParseState<'_, CAP> {
    /// Parses the start of the set class, including the opening `[` and any specially handled chars
    /// (`^`, `-` and `]`).
    pub(super) const fn parse_set_class_start(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'[');
        self.pos += 1;

        let ast_idx = self.syntax.len();
        const_try!(self.push_ast(start_pos, Node::SetStart { negation: None }));

        const_try!(self.gobble_whitespace_and_comments());
        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedSet));
        }

        if self.regex_bytes[self.pos] == b'^' {
            self.pos += 1;
            let negation_range = Span::new(self.pos - 1, self.pos);
            const_try!(self.gobble_whitespace_and_comments());
            if self.is_eof() {
                return Err(self.error(start_pos, ErrorKind::UnfinishedSet));
            }

            if let SyntaxOrLen::Syntax(syntax) = &mut self.syntax {
                if let Node::SetStart { negation } = &mut syntax.index_mut(ast_idx).node {
                    *negation = Some(negation_range);
                }
            }
        }

        if self.regex_bytes[self.pos] == b']' {
            // Literal ']'
            self.pos += 1;
            const_try!(self.gobble_whitespace_and_comments());
        } else {
            // Any amount of literal '-'
            while !self.is_eof() && self.regex_bytes[self.pos] == b'-' {
                self.pos += 1;
                const_try!(self.gobble_whitespace_and_comments());
            }
        }
        Ok(())
    }

    pub(super) const fn set_step(&mut self) -> Result<(), Error> {
        debug_assert!(self.set_depth > 0);

        const_try!(self.gobble_whitespace_and_comments());
        if self.is_eof() {
            return Err(self.error(self.pos, ErrorKind::UnfinishedSet));
        }

        let op_start = self.pos;
        if self.gobble_any(&[b"&&", b"--", b"~~"]) {
            const_try!(self.push_ast(op_start, Node::SetOp));
            return Ok(());
        }

        let ch = self.regex_bytes[self.pos];
        match ch {
            b'[' => {
                // Try parse the ASCII char class first. If that fails, treat it as an embedded class.
                if self.try_parse_ascii_class() {
                    const_try!(self.push_ast(op_start, Node::AsciiClass));
                } else {
                    self.pos = op_start; // Restore the parser position
                    const_try!(self.parse_set_class_start());
                    self.set_depth += 1;
                }
            }
            b']' => {
                self.pos += 1;
                const_try!(self.push_ast(op_start, Node::SetEnd));
                self.set_depth -= 1;
            }
            _ => const_try!(self.parse_set_class_range()),
        }
        Ok(())
    }

    /// Parses an ASCII char class, e.g., `[:alnum:]`. If successful, advances the parser beyond the closing `]`.
    ///
    /// **Important.** The caller is responsible for rewinding the parser position if `false` is returned.
    const fn try_parse_ascii_class(&mut self) -> bool {
        const CLASSES: &[&[u8]] = &[
            b"alnum", b"alpha", b"ascii", b"blank", b"cntrl", b"digit", b"graph", b"lower",
            b"print", b"punct", b"space", b"upper", b"word", b"xdigit",
        ];

        debug_assert!(self.regex_bytes[self.pos] == b'[');
        self.pos += 1;

        if self.is_eof() || self.regex_bytes[self.pos] != b':' {
            return false;
        }

        self.pos += 1;
        if self.is_eof() {
            return false;
        }
        if self.regex_bytes[self.pos] == b'^' {
            self.pos += 1;
            if self.is_eof() {
                return false;
            }
        }

        if !self.gobble_any(CLASSES) {
            return false;
        }

        !self.is_eof() && self.gobble(b":]")
    }

    const fn parse_set_class_range(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        let start_item = const_try!(self.parse_set_class_item());
        const_try!(self.gobble_whitespace_and_comments());
        if self.is_eof() {
            return Err(self.error(self.pos, ErrorKind::UnfinishedSet));
        }

        let ch = self.regex_bytes[self.pos];
        if ch != b'-' || {
            let next_ch = self.peek_whitespace(self.pos + 1);
            matches!(next_ch, Some(']' | '-'))
        } {
            // Not a range.
            if !start_item.is_valid_set_member() {
                return Err(self.error(start_pos, ErrorKind::InvalidEscapeInSet));
            }
            return Ok(());
        }

        let PrimitiveKind::Literal(range_start) = start_item else {
            return Err(self.error(start_pos, ErrorKind::InvalidRangeStart));
        };

        debug_assert!(ch == b'-');
        self.pos += 1;
        const_try!(self.push_ast(self.pos - 1, Node::SetRange));
        const_try!(self.gobble_whitespace_and_comments());

        let end_start_pos = self.pos;
        let PrimitiveKind::Literal(range_end) = const_try!(self.parse_set_class_item()) else {
            return Err(self.error(end_start_pos, ErrorKind::InvalidRangeEnd));
        };

        if range_start > range_end {
            return Err(self.error(start_pos, ErrorKind::InvalidRange));
        }
        Ok(())
    }

    const fn parse_set_class_item(&mut self) -> Result<PrimitiveKind, Error> {
        let Some((ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
            return Err(self.error(self.pos, ErrorKind::UnfinishedSet));
        };
        if ch == '\\' {
            self.parse_escape()
        } else {
            self.pos = next_pos;
            Ok(PrimitiveKind::Literal(ch))
        }
    }
}
