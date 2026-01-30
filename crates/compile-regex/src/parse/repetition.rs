//! Parsing counted and uncounted repetitions.

use super::ParseState;
use crate::{
    ast::{CountedRepetition, Node, Span},
    errors::{Error, ErrorKind},
};

impl<const CAP: usize> ParseState<'_, CAP> {
    /// Parses uncounted repetition operation, e.g. `*` or `+?`.
    pub(super) const fn parse_uncounted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        // `pos` is currently at one of `?`, `*` or `+` (all ASCII chars)
        self.pos += 1;
        if self.is_empty_last_item {
            return Err(self.error(self.pos - 1, ErrorKind::MissingRepetition));
        }
        // Parse optional non-greedy marker `?`
        self.gobble(b"?");

        const_try!(self.push_ast(start_pos, Node::UncountedRepetition));
        Ok(())
    }

    /// Parses counted repetition, e.g., `{2}`, `{2,}` or `{2,5}`.
    pub(super) const fn parse_counted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'{');
        self.pos += 1; // gobble '{'

        if self.is_empty_last_item {
            return Err(self.error(start_pos, ErrorKind::MissingRepetition));
        }
        const_try!(self.gobble_whitespace_and_comments());

        // Minimum or exact count
        let (min_count, min_count_span) = const_try!(self.parse_decimal());
        let Some(min_count) = min_count else {
            return Err(
                ErrorKind::EmptyDecimal.with_position(min_count_span.start..min_count_span.end)
            );
        };
        const_try!(self.gobble_whitespace_and_comments());

        let Some(current_char) = self.ascii_char() else {
            return Err(self.error(start_pos, ErrorKind::UnfinishedRepetition));
        };
        let max_count_span = if current_char == b',' {
            self.pos += 1;
            const_try!(self.gobble_whitespace_and_comments());

            let max_count_start = self.pos;
            // Maximum count
            let (max_count, max_count_span) = const_try!(self.parse_decimal());
            if let Some(count) = max_count {
                if count < min_count {
                    return Err(self.error(start_pos, ErrorKind::InvalidRepetitionRange));
                }
            } else if max_count_start != self.pos {
                // `regex-syntax` quirk: if there's whitespace after `,`, but no digits, then the repetition is invalid.
                // I.e., `{2,}` is valid, but `{2, }` is not.
                return Err(self.error(max_count_start, ErrorKind::EmptyDecimal));
            }
            Some(max_count_span)
        } else {
            None
        };

        const_try!(self.gobble_whitespace_and_comments());
        if matches!(self.ascii_char(), Some(b'}')) {
            self.pos += 1;
            const_try!(self.gobble_whitespace_and_comments());

            // Parse optional non-greedy marker `?`
            self.gobble(b"?");
            const_try!(self.push_ast(
                start_pos,
                Node::CountedRepetition(match max_count_span {
                    Some(span) if span.is_empty() => CountedRepetition::AtLeast(min_count_span),
                    Some(span) => CountedRepetition::Between(min_count_span, span),
                    None => CountedRepetition::Exactly(min_count_span),
                })
            ));
            Ok(())
        } else {
            Err(self.error(start_pos, ErrorKind::UnfinishedRepetition))
        }
    }

    /// This will trim leading and trailing whitespace regardless of the whitespace handling mode.
    const fn parse_decimal(&mut self) -> Result<(Option<u32>, Span), Error> {
        while !self.is_eof() && self.regex_bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }

        let start_pos = self.pos;
        let mut pos = self.pos;
        let mut decimal = 0_u32;
        while pos < self.regex_bytes.len() && self.regex_bytes[pos].is_ascii_digit() {
            let Some(new_decimal) = decimal.checked_mul(10) else {
                return Err(ErrorKind::InvalidDecimal.with_position(start_pos..pos + 1));
            };
            decimal = match new_decimal.checked_add((self.regex_bytes[pos] - b'0') as u32) {
                Some(dec) => dec,
                None => return Err(ErrorKind::InvalidDecimal.with_position(start_pos..pos + 1)),
            };
            pos += 1;
        }

        let decimal = if pos == self.pos {
            None
        } else {
            self.pos = pos;
            Some(decimal)
        };

        while !self.is_eof() && self.regex_bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }

        if self.ignore_whitespace {
            // Look ahead and check whether the next char ignoring whitespace is a digit.
            // If so, the decimal would be valid as per regex-syntax, but it looks confusing, so we
            // raise an error.
            if let Some(ch) = self.peek_whitespace(pos) {
                if ch.is_ascii_digit() {
                    return Err(self.disallowed_error(pos));
                }
            }
        }

        Ok((decimal, Span::new(start_pos, pos)))
    }
}
