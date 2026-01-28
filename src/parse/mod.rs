//! Parsing logic. Heavily inspired by AST parsing in the `regex-syntax` crate:
//!
//! https://github.com/rust-lang/regex/blob/master/regex-syntax/src/ast/parse.rs

use core::{fmt, mem, ops};

use crate::{
    ast::CountedRepetition,
    is_escapable_char, is_meta_char,
    utils::{ceil_char_boundary, is_char_boundary, split_first_char, Stack},
    Ast, Error, ErrorKind, GroupName, Range, Syntax, SyntaxSpan,
};

#[cfg(test)]
mod tests;

/// Regular expression parsing options.
#[derive(Debug, Default)]
pub struct RegexOptions {
    ignore_whitespace: bool,
}

impl RegexOptions {
    pub const DEFAULT: Self = Self {
        ignore_whitespace: false,
    };

    #[must_use]
    pub const fn ignore_whitespace(mut self, yes: bool) -> Self {
        self.ignore_whitespace = yes;
        self
    }

    /// Tries to validate the provided regular expression.
    pub const fn try_validate(self, regex: &str) -> Result<(), Error> {
        let mut state = <ParseState>::new(regex, self);
        loop {
            match state.step() {
                Err(err) => return Err(err),
                Ok(ops::ControlFlow::Break(())) => break,
                Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
            }
        }

        Ok(())
    }

    #[track_caller]
    pub const fn validate(self, regex: &str) {
        if let Err(err) = self.try_validate(regex) {
            err.compile_panic(regex);
        }
    }

    pub const fn try_parse<const CAP: usize>(self, regex: &str) -> Result<Syntax<CAP>, Error> {
        let mut state = ParseState::custom(regex, self, true);
        loop {
            match state.step() {
                Err(err) => return Err(err),
                Ok(ops::ControlFlow::Break(())) => return Ok(state.into_spans()),
                Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
            }
        }
    }

    #[track_caller]
    pub const fn parse<const CAP: usize>(self, regex: &str) -> Syntax<CAP> {
        match self.try_parse(regex) {
            Ok(spans) => spans,
            Err(err) => err.compile_panic(regex),
        }
    }

    pub fn try_parse_to_vec(self, regex: &str) -> Result<Vec<SyntaxSpan>, Error> {
        /// Max number of AST spans added during a single parsing step.
        // FIXME: either don't capture comments, capture a single comment, or split parsing whitespace into steps somehow
        const STEP_CAP: usize = 8;

        let mut state = ParseState::<STEP_CAP>::custom(regex, self, true);
        let mut syntax = Vec::new();
        loop {
            let step_result = state.step()?;
            // Empty all captured spans to `syntax`. Since we never read from spans in the parser,
            // this doesn't influence subsequent steps.
            let spans = state.spans.as_mut().unwrap();
            let spans = mem::replace(spans, Syntax::new(SyntaxSpan::DUMMY));
            syntax.extend_from_slice(spans.as_slice());

            if step_result.is_break() {
                return Ok(syntax);
            }
        }
    }
}

#[derive(Debug)]
enum PrimitiveKind {
    Literal(char),
    PerlClass,
    Other,
}

impl PrimitiveKind {
    const fn is_valid_set_member(&self) -> bool {
        matches!(self, Self::Literal(_) | Self::PerlClass)
    }
}

#[derive(Debug, Clone, Copy)]
struct Flags {
    is_empty: bool,
    ignore_whitespace: Option<bool>,
}

/// Parser state backup.
#[derive(Debug)]
struct Backup {
    pos: usize,
    span_count: usize,
}

/// Maximum supported group depth.
const GROUP_DEPTH: usize = 16;
/// Maximum supported number of named groups.
const MAX_NAMED_GROUPS: usize = 64;

#[derive(Debug, Clone, Copy)]
struct GroupFrame {
    /// `ignore_whitespace` value when the group was pushed to the stack (= one that should be set
    /// when the group is popped from the stack).
    prev_ignore_whitespace: bool,
}

impl GroupFrame {
    const DUMMY: Self = Self {
        prev_ignore_whitespace: false,
    };
}

struct GroupNames<const CAP: usize> {
    items: [Range; CAP],
    len: usize,
}

impl<const CAP: usize> fmt::Debug for GroupNames<CAP> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (items, _) = self.items.split_at(self.len);
        formatter.debug_list().entries(items).finish()
    }
}

impl<const CAP: usize> GroupNames<CAP> {
    const fn new() -> Self {
        Self {
            items: [Range::new(0, 0); CAP],
            len: 0,
        }
    }

    const fn insert(&mut self, item: Range, regex_bytes: &[u8]) -> Result<(), Error> {
        const fn bytes_eq(bytes: &[u8], x: Range, y: Range) -> bool {
            let mut i = 0;
            while i < x.len() {
                if bytes[x.start + i] != bytes[y.start + i] {
                    return false;
                }
                i += 1;
            }
            true
        }

        if self.len == CAP {
            return Err(ErrorKind::NamedGroupOverflow.with_position(item.start..item.end));
        }

        let item_len = item.len();
        let mut i = 0;
        while i < self.len {
            let prev_pos = self.items[i];
            if prev_pos.len() == item_len && bytes_eq(regex_bytes, prev_pos, item) {
                let err = ErrorKind::DuplicateCaptureName {
                    prev_pos: prev_pos.start..prev_pos.end,
                };
                return Err(err.with_position(item.start..item.end));
            }
            i += 1;
        }

        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ParseState<'a, const CAP: usize = 0> {
    /// Always a valid UTF-8 string.
    regex_bytes: &'a [u8],
    /// Points to the next char to be parsed in `regex_bytes`.
    pos: usize,
    groups: Stack<GroupFrame, GROUP_DEPTH>,
    group_names: GroupNames<MAX_NAMED_GROUPS>,
    set_depth: usize,
    is_empty_last_item: bool,
    ignore_whitespace: bool,
    spans: Option<Syntax<CAP>>,
}

impl<'a> ParseState<'a> {
    pub(crate) const fn new(regex: &'a str, options: RegexOptions) -> Self {
        Self::custom(regex, options, false)
    }
}

impl<'a, const CAP: usize> ParseState<'a, CAP> {
    pub(crate) const fn custom(regex: &'a str, options: RegexOptions, with_ast: bool) -> Self {
        Self {
            regex_bytes: regex.as_bytes(),
            pos: 0,
            groups: Stack::new(GroupFrame::DUMMY),
            group_names: GroupNames::new(),
            set_depth: 0,
            is_empty_last_item: true,
            ignore_whitespace: options.ignore_whitespace,
            spans: if with_ast {
                Some(Syntax::new(SyntaxSpan::DUMMY))
            } else {
                None
            },
        }
    }

    const fn backup(&self) -> Backup {
        Backup {
            pos: self.pos,
            span_count: match &self.spans {
                Some(spans) => spans.len(),
                None => 0,
            },
        }
    }

    const fn restore(&mut self, backup: Backup) {
        debug_assert!(self.pos >= backup.pos);

        self.pos = backup.pos;
        if let Some(spans) = &mut self.spans {
            debug_assert!(spans.len() >= backup.span_count);
            spans.trim(backup.span_count);
        }
    }

    const fn ascii_char_at(&self, pos: usize) -> Option<u8> {
        if pos >= self.regex_bytes.len() {
            None
        } else {
            let ch = self.regex_bytes[pos];
            if ch <= 0x7f {
                Some(ch)
            } else {
                None
            }
        }
    }

    const fn ascii_char(&self) -> Option<u8> {
        self.ascii_char_at(self.pos)
    }

    const fn error(&self, start: usize, kind: ErrorKind) -> Error {
        debug_assert!(start <= self.pos);
        debug_assert!(start <= self.regex_bytes.len());
        if start < self.regex_bytes.len() {
            debug_assert!(is_char_boundary(self.regex_bytes[start]));
        }

        let end = if self.pos <= self.regex_bytes.len() {
            ceil_char_boundary(self.regex_bytes, self.pos)
        } else {
            self.regex_bytes.len()
        };
        kind.with_position(start..end)
    }

    const fn ast_len(&self) -> usize {
        if let Some(spans) = &self.spans {
            spans.len()
        } else {
            0
        }
    }

    const fn push_ast(&mut self, start_pos: usize, node: Ast) -> Result<(), Error> {
        self.push_custom_ast(Range::new(start_pos, self.pos), node)
    }

    const fn push_custom_ast(&mut self, range: Range, node: Ast) -> Result<(), Error> {
        if let Some(spans) = &mut self.spans {
            let span = SyntaxSpan { node, range };
            if spans.push(span).is_err() {
                return Err(self.error(range.start, ErrorKind::AstOverflow));
            }
        }
        Ok(())
    }

    /// Gobbles the provided bytes if they are next. Otherwise, doesn't change the state.
    const fn gobble(&mut self, bytes: &[u8]) -> bool {
        let mut i = 0;
        while i < bytes.len()
            && self.pos + i < self.regex_bytes.len()
            && bytes[i] == self.regex_bytes[self.pos + i]
        {
            i += 1;
        }
        if i == bytes.len() {
            // All bytes have matched
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    const fn gobble_any(&mut self, needles: &[&[u8]]) -> bool {
        let mut i = 0;
        while i < needles.len() {
            let matched = self.gobble(needles[i]);
            if matched {
                return true;
            }
            i += 1;
        }
        false
    }

    const fn matches(&self, range: ops::Range<usize>, needle: &[u8]) -> bool {
        if range.end - range.start != needle.len() {
            return false;
        }
        if range.end > self.regex_bytes.len() {
            return false;
        }

        let mut i = 0;
        while i < needle.len() && self.regex_bytes[range.start + i] == needle[i] {
            i += 1;
        }
        i == needle.len()
    }

    const fn matches_any(&self, range: ops::Range<usize>, needles: &[&[u8]]) -> bool {
        let mut i = 0;
        while i < needles.len() {
            if self.matches(range.start..range.end, needles[i]) {
                return true;
            }
            i += 1;
        }
        false
    }

    const fn gobble_whitespace_and_comments(&mut self) -> Result<(), Error> {
        if !self.ignore_whitespace {
            return Ok(());
        }

        // Start of the very first comment.
        let mut comment_range = None::<Range>;
        let mut is_in_comment = false;
        while !self.is_eof() {
            let Some((ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
                break; // reached EOF
            };

            if is_in_comment {
                if ch == '\n' {
                    is_in_comment = false;
                    if let Some(range) = &mut comment_range {
                        range.end = self.pos;
                    }
                }
                self.pos = next_pos;
            } else if ch.is_ascii_whitespace() {
                // TODO: support non-ASCII whitespace? `char::is_whitespace` is const only since Rust 1.87
                self.pos = next_pos;
            } else if ch == '#' {
                is_in_comment = true;
                if comment_range.is_none() {
                    comment_range = Some(Range::new(self.pos, self.pos + 1));
                }
                self.pos = next_pos;
            } else {
                break;
            }
        }

        if let Some(mut range) = comment_range {
            if is_in_comment {
                // Reached EOF without a closing '\n', so we need to update the comment span here.
                range.end = self.pos;
            }
            const_try!(self.push_custom_ast(range, Ast::Comment));
        }
        Ok(())
    }

    /// Fails if the parser is currently at ASCII whitespace and whitespace is ignored.
    const fn disallowed_error(&self, pos: usize) -> Error {
        debug_assert!(self.ignore_whitespace);

        let err = if self.regex_bytes[pos] == b'#' {
            ErrorKind::DisallowedComment
        } else {
            debug_assert!(self.regex_bytes[pos].is_ascii_whitespace());
            ErrorKind::DisallowedWhitespace
        };
        err.with_position(pos..pos + 1)
    }

    /// Peeks the first non-whitespace / comment char after the specified position.
    const fn peek_whitespace(&self, mut pos: usize) -> Option<char> {
        let mut is_in_comment = false;
        while !self.is_eof() {
            let Some((ch, next_pos)) = split_first_char(self.regex_bytes, pos) else {
                break; // reached EOF
            };

            if is_in_comment {
                if ch == '\n' {
                    is_in_comment = false;
                }
                pos = next_pos;
            } else if self.ignore_whitespace && ch.is_ascii_whitespace() {
                // TODO: support non-ASCII whitespace? `char::is_whitespace` is const only since Rust 1.87
                pos = next_pos;
            } else if self.ignore_whitespace && ch == '#' {
                is_in_comment = true;
                pos = next_pos;
            } else {
                return Some(ch);
            }
        }
        None
    }

    /// Parses uncounted repetition operation, e.g. `*` or `+?`.
    const fn parse_uncounted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        // `pos` is currently at one of `?`, `*` or `+` (all ASCII chars)
        self.pos += 1;
        if self.is_empty_last_item {
            return Err(self.error(self.pos - 1, ErrorKind::MissingRepetition));
        }
        // Parse optional non-greedy marker `?`
        self.gobble(b"?");

        const_try!(self.push_ast(start_pos, Ast::UncountedRepetition));
        Ok(())
    }

    /// Parses counted repetition, e.g., `{2}`, `{2,}` or `{2,5}`.
    const fn parse_counted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'{');
        self.pos += 1; // gobble '{'

        if self.is_empty_last_item {
            return Err(self.error(start_pos, ErrorKind::MissingRepetition));
        }
        const_try!(self.gobble_whitespace_and_comments());

        // Minimum or exact count
        let (min_count, min_count_span) = const_try!(self.parse_decimal());
        let min_count = match min_count {
            Some(count) => count,
            None => {
                return Err(
                    ErrorKind::EmptyDecimal.with_position(min_count_span.start..min_count_span.end)
                )
            }
        };
        const_try!(self.gobble_whitespace_and_comments());

        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(start_pos, ErrorKind::UnfinishedRepetition)),
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
                Ast::CountedRepetition(match max_count_span {
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
    const fn parse_decimal(&mut self) -> Result<(Option<u32>, Range), Error> {
        while !self.is_eof() && self.regex_bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }

        let start_pos = self.pos;
        let mut pos = self.pos;
        let mut decimal = 0_u32;
        while pos < self.regex_bytes.len() && self.regex_bytes[pos].is_ascii_digit() {
            let new_decimal = match decimal.checked_mul(10) {
                Some(dec) => dec,
                None => return Err(ErrorKind::InvalidDecimal.with_position(start_pos..pos + 1)),
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

        Ok((decimal, Range::new(start_pos, pos)))
    }

    const fn parse_primitive(&mut self, ch: char, next_pos: usize) -> Result<(), Error> {
        match ch {
            '\\' => {
                const_try!(self.parse_escape());
                Ok(())
            }
            '.' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::Dot));
                Ok(())
            }
            '^' | '$' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::LineAssertion));
                Ok(())
            }
            _ => {
                self.pos = next_pos;
                Ok(())
            }
        }
    }

    const fn parse_escape(&mut self) -> Result<PrimitiveKind, Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'\\');
        self.pos += 1;

        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(start_pos, ErrorKind::UnfinishedEscape)),
        };
        // Gobble the escaped single ASCII char
        self.pos += 1;

        match current_char {
            b'0'..=b'9' => Err(self.error(start_pos, ErrorKind::UnsupportedBackref)),
            b'x' | b'u' | b'U' => {
                let ch = const_try!(self.parse_hex_escape(start_pos, current_char));
                const_try!(self.push_ast(start_pos, Ast::HexEscape));
                Ok(PrimitiveKind::Literal(ch))
            }
            b'p' | b'P' => Err(self.error(start_pos, ErrorKind::UnicodeClassesNotSupported)),
            b'd' | b's' | b'w' | b'D' | b'S' | b'W' => {
                const_try!(self.push_ast(start_pos, Ast::PerlClass));
                Ok(PrimitiveKind::PerlClass)
            }

            b'n' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\n'))
            }
            b't' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\t'))
            }
            b'r' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\r'))
            }
            b'a' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x07'))
            }
            b'f' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0C'))
            }
            b'v' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0B'))
            }

            b'A' | b'z' | b'B' | b'<' | b'>' => {
                const_try!(self.push_ast(start_pos, Ast::StdAssertion));
                Ok(PrimitiveKind::Other)
            }
            b'b' => {
                if matches!(self.ascii_char(), Some(b'{')) {
                    const_try!(self.try_parse_word_boundary(start_pos));
                }
                Ok(PrimitiveKind::Other)
            }
            ch if is_meta_char(ch) => {
                const_try!(self.push_ast(start_pos, Ast::EscapedChar { meta: true }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            ch if is_escapable_char(ch) => {
                const_try!(self.push_ast(start_pos, Ast::EscapedChar { meta: false }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            _ => Err(self.error(start_pos, ErrorKind::UnsupportedEscape)),
        }
    }

    const fn try_parse_word_boundary(&mut self, escape_start: usize) -> Result<(), Error> {
        const fn is_valid_char(ch: u8) -> bool {
            matches!(ch, b'A'..=b'Z' | b'a'..=b'z' | b'-')
        }

        const KNOWN_BOUNDARIES: &[&[u8]] = &[b"start", b"end", b"start-half", b"end-half"];

        let backup = self.backup();
        debug_assert!(self.regex_bytes[self.pos] == b'{');
        self.pos += 1;

        const_try!(self.gobble_whitespace_and_comments());
        let start_pos = self.pos;
        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedWordBoundary));
        }

        if !is_valid_char(self.regex_bytes[self.pos]) {
            self.restore(backup);
            return Ok(()); // not a word boundary specifier
        }

        while !self.is_eof() && is_valid_char(self.regex_bytes[self.pos]) {
            self.pos += 1;
        }
        let end_pos = self.pos;
        const_try!(self.gobble_whitespace_and_comments());

        if self.ignore_whitespace {
            // `regex-syntax` allows whitespace / comments *inside* the specifier, which looks weird, so we don't allow it.
            if let Some(ch) = self.peek_whitespace(self.pos) {
                if ch.is_ascii() && is_valid_char(ch as u8) {
                    return Err(self.disallowed_error(end_pos));
                }
            }
        }

        if self.is_eof() || self.regex_bytes[self.pos] != b'}' {
            return Err(self.error(start_pos, ErrorKind::UnfinishedWordBoundary));
        }

        // Check whether the boundary specification is known.
        if !self.matches_any(start_pos..end_pos, KNOWN_BOUNDARIES) {
            return Err(ErrorKind::UnknownWordBoundary.with_position(start_pos..end_pos));
        }

        self.pos += 1; // gobble '}'
        const_try!(self.push_ast(escape_start, Ast::StdAssertion));
        Ok(())
    }

    /// Parses a hex-escaped char. The parser position is after the marker ('x', 'u' or 'U').
    ///
    /// Unlike `regex-syntax`, we don't allow any whitespace / comments *inside* the escape, so it's closer to Rust syntax,
    /// and doesn't lead to terribly looking regexes:
    ///
    /// ```text
    /// \u # can you guess
    ///   0 # this is
    /// 1 2 3 # a hex escape?
    /// ```
    const fn parse_hex_escape(&mut self, start_pos: usize, marker_ch: u8) -> Result<char, Error> {
        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(start_pos, ErrorKind::UnfinishedEscape)),
        };
        if current_char == b'{' {
            // escape with braces, e.g., \u{123}
            self.parse_hex_brace(start_pos)
        } else {
            let expected_digits = match marker_ch {
                b'x' => 2,
                b'u' => 4,
                b'U' => 8,
                _ => unreachable!(),
            };
            self.parse_hex_digits(start_pos, expected_digits)
        }
    }

    const fn parse_hex_brace(&mut self, start_pos: usize) -> Result<char, Error> {
        self.pos += 1; // gobble '{'

        let first_digit_pos = self.pos;
        let mut hex = 0_u32;
        while self.pos < self.regex_bytes.len() && self.regex_bytes[self.pos] != b'}' {
            let digit = self.regex_bytes[self.pos];
            self.pos += 1;
            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ if self.ignore_whitespace && digit.is_ascii_whitespace() => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedWhitespace));
                }
                b'#' if self.ignore_whitespace => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedComment));
                }
                _ => return Err(self.error(start_pos, ErrorKind::InvalidHex)),
            };
            if self.pos >= first_digit_pos + 8 {
                return Err(self.error(start_pos, ErrorKind::NonUnicodeHex));
            }
            // No overflow can happen due to the check above
            hex = hex * 16 + digit as u32;
        }

        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
        }

        // Gobble the terminating '}'
        debug_assert!(self.regex_bytes[self.pos] == b'}');
        self.pos += 1;

        if self.pos == first_digit_pos + 1 {
            Err(self.error(start_pos, ErrorKind::EmptyHex))
        } else {
            match char::from_u32(hex) {
                Some(ch) => Ok(ch),
                None => Err(self.error(start_pos, ErrorKind::NonUnicodeHex)),
            }
        }
    }

    const fn parse_hex_digits(
        &mut self,
        start_pos: usize,
        expected_digits: usize,
    ) -> Result<char, Error> {
        let first_digit_pos = self.pos;
        let mut hex = 0_u32;
        while self.pos - first_digit_pos < expected_digits {
            if self.is_eof() {
                return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
            }
            let digit = self.regex_bytes[self.pos];
            self.pos += 1; // Advance immediately to get the correct error span

            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ if self.ignore_whitespace && digit.is_ascii_whitespace() => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedWhitespace));
                }
                b'#' if self.ignore_whitespace => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedComment));
                }
                _ => return Err(self.error(start_pos, ErrorKind::InvalidHex)),
            };
            // No overflow can happen.
            hex = hex * 16 + digit as u32;
        }

        match char::from_u32(hex) {
            Some(ch) => Ok(ch),
            None => Err(self.error(start_pos, ErrorKind::NonUnicodeHex)),
        }
    }

    const fn is_eof(&self) -> bool {
        self.pos == self.regex_bytes.len()
    }

    const fn parse_group_start_or_flags(&mut self) -> Result<(), Error> {
        const LOOKAROUND_PREFIXES: &[&[u8]] = &[b"?=", b"?!", b"?<=", b"?<!"];
        const NAMED_PREFIXES: &[&[u8]] = &[b"?P<", b"?<"];

        // Gobble the opening '('
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'(');
        self.pos += 1;

        let start_ast_idx = self.ast_len();
        const_try!(self.push_ast(
            start_pos,
            Ast::GroupStart {
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
            let start = Range::new(name_start, self.pos);
            let name_ast = const_try!(self.parse_capture_name(start));
            if let Some(spans) = &mut self.spans {
                if let Ast::GroupStart { name, .. } = &mut spans.index_mut(start_ast_idx).node {
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
                spanned_flags = Some((flags, Range::new(flags_start, self.pos)));
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
        };

        if let Some(spans) = &mut self.spans {
            if let (Ast::GroupStart { flags, .. }, Some((_, span))) =
                (&mut spans.index_mut(start_ast_idx).node, &spanned_flags)
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
    const fn parse_capture_name(&mut self, start: Range) -> Result<GroupName, Error> {
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
            name: Range::new(start_pos, self.pos - 1),
            end: Range::new(self.pos - 1, self.pos),
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

    const fn end_group(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b')');
        self.pos += 1;

        if let Some(popped) = self.groups.pop() {
            self.ignore_whitespace = popped.prev_ignore_whitespace;
        } else {
            return Err(self.error(start_pos, ErrorKind::NonMatchingGroupEnd));
        }
        self.push_ast(start_pos, Ast::GroupEnd)
    }

    /// Parses the start of the set class, including the opening `[` and any specially handled chars
    /// (`^`, `-` and `]`).
    const fn parse_set_class_start(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'[');
        self.pos += 1;

        let ast_idx = self.ast_len();
        const_try!(self.push_ast(start_pos, Ast::SetStart { negation: None }));

        const_try!(self.gobble_whitespace_and_comments());
        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedSet));
        }

        if self.regex_bytes[self.pos] == b'^' {
            self.pos += 1;
            let negation_range = Range::new(self.pos - 1, self.pos);
            const_try!(self.gobble_whitespace_and_comments());
            if self.is_eof() {
                return Err(self.error(start_pos, ErrorKind::UnfinishedSet));
            }

            if let Some(spans) = &mut self.spans {
                if let Ast::SetStart { negation } = &mut spans.index_mut(ast_idx).node {
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

    const fn set_step(&mut self) -> Result<(), Error> {
        debug_assert!(self.set_depth > 0);

        const_try!(self.gobble_whitespace_and_comments());
        if self.is_eof() {
            return Err(self.error(self.pos, ErrorKind::UnfinishedSet));
        }

        let op_start = self.pos;
        if self.gobble_any(&[b"&&", b"--", b"~~"]) {
            const_try!(self.push_ast(op_start, Ast::SetOp));
            return Ok(());
        }

        let ch = self.regex_bytes[self.pos];
        match ch {
            b'[' => {
                // Try parse the ASCII char class first. If that fails, treat it as an embedded class.
                if self.try_parse_ascii_class() {
                    const_try!(self.push_ast(op_start, Ast::AsciiClass));
                } else {
                    self.pos = op_start; // Restore the parser position
                    const_try!(self.parse_set_class_start());
                    self.set_depth += 1;
                }
            }
            b']' => {
                self.pos += 1;
                const_try!(self.push_ast(op_start, Ast::SetEnd));
                self.set_depth -= 1;
            }
            _ => const_try!(self.parse_set_class_range()),
        }
        Ok(())
    }

    /// Parses an ASCII char class, e.g., `[:alnum:]`. If successful, advances the parser beyond the closing `]`.
    ///
    /// **Important.** The caller is responsible for rewinding the parser position if `Ok(false)` is returned.
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

        let is_known_class = self.gobble_any(CLASSES);
        // ^ Immediately rewind the parse position so we don't forget about it.
        if !is_known_class {
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
        const_try!(self.push_ast(self.pos - 1, Ast::SetRange));
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

    pub(crate) const fn step(&mut self) -> Result<ops::ControlFlow<()>, Error> {
        if self.set_depth > 0 {
            const_try!(self.set_step());
            return Ok(ops::ControlFlow::Continue(()));
        }

        const_try!(self.gobble_whitespace_and_comments());

        let Some((current_ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
            if self.groups.len() != 0 {
                return Err(self.error(self.regex_bytes.len(), ErrorKind::UnfinishedGroup));
            }
            return Ok(ops::ControlFlow::Break(()));
        };
        match current_ch {
            '(' => {
                const_try!(self.parse_group_start_or_flags());
                // This works with standalone flags (e.g., `(?-x)`) as well; it's invalid to have a repetition after these.
                self.is_empty_last_item = true;
            }
            ')' => {
                const_try!(self.end_group());
                self.is_empty_last_item = false;
            }
            '|' => {
                // Gobble the alteration.
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::Alteration));
                self.is_empty_last_item = true;
            }
            '[' => {
                const_try!(self.parse_set_class_start());
                self.set_depth = 1;
                self.is_empty_last_item = false;
            }
            '?' | '*' | '+' => {
                const_try!(self.parse_uncounted_repetition());
                self.is_empty_last_item = false;
            }
            '{' => {
                const_try!(self.parse_counted_repetition());
                self.is_empty_last_item = false;
            }
            _ => {
                const_try!(self.parse_primitive(current_ch, next_pos));
                self.is_empty_last_item = false;
            }
        }
        Ok(ops::ControlFlow::Continue(()))
    }

    pub(crate) const fn into_spans(self) -> Syntax<CAP> {
        match self.spans {
            Some(spans) => spans,
            None => Syntax::new(SyntaxSpan::DUMMY),
        }
    }
}
