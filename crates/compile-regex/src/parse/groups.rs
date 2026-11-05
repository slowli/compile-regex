//! Parsing groups.

use super::{types::Flags, GroupFrame, ParseState, SyntaxOrLen};
use crate::{
    ast::{GroupName, Node, Span},
    errors::{Error, ErrorKind},
};

impl<const CAP: usize> ParseState<'_, CAP> {
    pub(super) const fn parse_group_start_or_flags(&mut self) -> Result<(), Error> {
        const LOOKAROUND_PREFIXES: &[&[u8]] = &[b"?=", b"?!", b"?<=", b"?<!"];
        const NAMED_PREFIXES: &[&[u8]] = &[b"?P<", b"?<"];

        // Gobble the opening '('
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'(');
        self.pos += 1;

        let start_ast_idx = self.syntax.len();
        const_try!(self.push_ast(
            start_pos,
            Node::GroupStart {
                name: None,
                flags: None,
            }
        ));
        const_try!(self.gobble_whitespace_and_comments());

        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedGroup));
        }

        let is_lookaround = self.gobble_any(LOOKAROUND_PREFIXES);
        if is_lookaround {
            return Err(self.error(start_pos, ErrorKind::LookaroundNotSupported));
        }

        let name_start = self.pos;
        let is_named = self.gobble_any(NAMED_PREFIXES);
        if is_named {
            let start = Span::new(name_start, self.pos);
            let name_ast = const_try!(self.parse_capture_name(start));
            if let SyntaxOrLen::Syntax(syntax) = &mut self.syntax {
                if let Node::GroupStart { name, .. } = &mut syntax.index_mut(start_ast_idx).node {
                    *name = Some(name_ast);
                }
            }

            const_try!(self.group_names.insert(name_ast.name, self.regex_bytes));
        }

        let mut spanned_flags = None;
        let mut is_standalone_flags = false;
        if !is_named && self.regex_bytes[self.pos] == b'?' {
            let flags_start = self.pos;
            let flags = const_try!(self.parse_flags());
            if !flags.is_empty {
                spanned_flags = Some((flags, Span::new(flags_start, self.pos)));
            }

            let ch = self.regex_bytes[self.pos];
            debug_assert!(ch == b':' || ch == b')');

            if ch == b')' {
                // Flags for the current group.
                if flags.is_empty {
                    // Include the closing `)` in the error span
                    self.pos += 1;
                    // Treat `(?)` as missing repetition, same as in `regex-parser`
                    return Err(self.error(start_pos, ErrorKind::MissingRepetition));
                }
                // Do not advance the pos, so that `)` is parsed as the group end and decrements the group depth.
                is_standalone_flags = true;
            } else {
                self.pos += 1;
            }
        }

        if let SyntaxOrLen::Syntax(syntax) = &mut self.syntax {
            if let (Node::GroupStart { flags, .. }, Some((_, span))) =
                (&mut syntax.index_mut(start_ast_idx).node, &spanned_flags)
            {
                *flags = Some(*span);
            }
        }

        let new_ignore_whitespace = if let Some((
            Flags {
                ignore_whitespace: Some(ws),
                ..
            },
            _,
        )) = spanned_flags
        {
            ws
        } else {
            self.ignore_whitespace
        };

        let push_result = self.groups.push(GroupFrame {
            prev_ignore_whitespace: if is_standalone_flags {
                // Will set `ignore_whitespace` in the *surrounding* group once the flags pseudo-group
                // is popped below.
                new_ignore_whitespace
            } else {
                let prev = self.ignore_whitespace;
                self.ignore_whitespace = new_ignore_whitespace;
                prev
            },
        });
        if push_result.is_err() {
            return Err(self.error(start_pos, ErrorKind::GroupDepthOverflow));
        }

        // This works fine with the standalone flags like `(?m-u)` because we immediately close the pseudo-group.
        if is_standalone_flags {
            const_try!(self.end_group());
        }
        Ok(())
    }

    /// Parses a capture name. The parser position is after the opening `<`.
    const fn parse_capture_name(&mut self, start: Span) -> Result<GroupName, Error> {
        const fn is_capture_char(ch: u8, is_first: bool) -> bool {
            if is_first {
                ch == b'_' || ch.is_ascii_alphabetic()
            } else {
                ch == b'_' || ch == b'.' || ch == b'[' || ch == b']' || ch.is_ascii_alphanumeric()
            }
        }

        let start_pos = self.pos;
        while self.pos < self.regex_bytes.len() && self.regex_bytes[self.pos] != b'>' {
            let ch = self.regex_bytes[self.pos];
            if ch > 0x7f {
                return Err(self.error(start_pos, ErrorKind::NonAsciiCaptureName));
            }

            let is_first = start_pos == self.pos;
            self.pos += 1;
            if !is_capture_char(ch, is_first) {
                return Err(self.error(start_pos, ErrorKind::InvalidCaptureName));
            }
        }

        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedCaptureName));
        }
        if start_pos == self.pos {
            return Err(self.error(start_pos, ErrorKind::EmptyCaptureName));
        }

        debug_assert!(self.regex_bytes[self.pos] == b'>');
        self.pos += 1;

        Ok(GroupName {
            start,
            name: Span::new(start_pos, self.pos - 1),
            end: Span::new(self.pos - 1, self.pos),
        })
    }

    /// Parses flags. The parser position is at the opening `?`.
    const fn parse_flags(&mut self) -> Result<Flags, Error> {
        const KNOWN_FLAGS_COUNT: usize = 7;
        const KNOWN_FLAGS: [u8; KNOWN_FLAGS_COUNT] = *b"ximsUuR";

        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'?');
        self.pos += 1;

        let mut negation = false;
        let mut flag_values = [None::<bool>; KNOWN_FLAGS_COUNT];
        let mut is_empty = true;
        let mut is_empty_negation = true;
        while !self.is_eof() {
            let ch = self.regex_bytes[self.pos];
            if ch == b':' || ch == b')' {
                break;
            }
            self.pos += 1;

            if ch == b'-' {
                if negation {
                    return Err(self.error(self.pos - 1, ErrorKind::RepeatedFlagNegation));
                }
                negation = true;
                continue;
            }

            let mut i = 0;
            while i < KNOWN_FLAGS_COUNT {
                if ch == KNOWN_FLAGS[i] {
                    break;
                }
                i += 1;
            }
            if i == KNOWN_FLAGS_COUNT {
                return Err(self.error(self.pos - 1, ErrorKind::UnsupportedFlag));
            }

            if let Some(prev_value) = flag_values[i] {
                let err = ErrorKind::RepeatedFlag {
                    contradicting: prev_value == negation,
                };
                return Err(self.error(self.pos - 1, err));
            }
            flag_values[i] = Some(!negation);
            is_empty = false;
            is_empty_negation = !negation;
        }

        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedFlags));
        }
        if negation && is_empty_negation {
            return Err(self.error(self.pos - 1, ErrorKind::UnfinishedFlagsNegation));
        }

        Ok(Flags {
            is_empty,
            ignore_whitespace: flag_values[0],
        })
    }

    pub(super) const fn end_group(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b')');
        self.pos += 1;

        if let Some(popped) = self.groups.pop() {
            self.ignore_whitespace = popped.prev_ignore_whitespace;
        } else {
            return Err(self.error(start_pos, ErrorKind::NonMatchingGroupEnd));
        }
        self.push_ast(start_pos, Node::GroupEnd)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::{try_validate, RegexOptions};

    #[test]
    fn parsing_flags() {
        for flags_str in ["?i:", "?i)", "?isU:", "?-isU:"] {
            println!("Testing flags: {flags_str}");
            let mut state = ParseState::new(flags_str, &RegexOptions::DEFAULT);
            let flags = state.parse_flags().unwrap();
            assert!(!flags.is_empty);
            assert_eq!(flags.ignore_whitespace, None);
            assert_eq!(state.pos, flags_str.len() - 1);
        }

        let mut state = ParseState::new("?i", &RegexOptions::DEFAULT);
        let err = state.parse_flags().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedFlags);
        assert_eq!(err.pos(), 0..2);

        let mut state = ParseState::new("?i-:", &RegexOptions::DEFAULT);
        let err = state.parse_flags().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnfinishedFlagsNegation);
        assert_eq!(err.pos(), 2..3);

        let mut state = ParseState::new("?i--s:", &RegexOptions::DEFAULT);
        let err = state.parse_flags().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::RepeatedFlagNegation);
        assert_eq!(err.pos(), 3..4);

        let mut state = ParseState::new("?iX:", &RegexOptions::DEFAULT);
        let err = state.parse_flags().unwrap_err();
        assert_matches!(err.kind(), ErrorKind::UnsupportedFlag);
        assert_eq!(err.pos(), 2..3);

        let mut state = ParseState::new("?ii:", &RegexOptions::DEFAULT);
        let err = state.parse_flags().unwrap_err();
        assert_matches!(
            err.kind(),
            ErrorKind::RepeatedFlag {
                contradicting: false
            }
        );
        assert_eq!(err.pos(), 2..3);

        let mut state = ParseState::new("?i-i:", &RegexOptions::DEFAULT);
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
}
