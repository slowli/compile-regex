//! Regex parsing logic. Heavily inspired by AST parsing in the `regex-syntax` crate:
//!
//! <https://github.com/rust-lang/regex/blob/master/regex-syntax/src/ast/parse.rs>

use core::ops;

use self::types::{Backup, GroupFrame, GroupNames, SyntaxOrLen};
use crate::{
    ast::{Node, Span, Spanned, Syntax},
    utils::{ceil_char_boundary, is_char_boundary, split_first_char, Stack},
    Error, ErrorKind, Parsed,
};

mod escapes;
mod groups;
mod repetition;
mod sets;
#[cfg(test)]
mod tests;
mod types;

/// Result of [validating](RegexOptions::validate()) a regular expression.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidationOutput {
    /// Number of syntax [`Node`]s in the expression.
    pub node_count: usize,
}

/// Regular expression parsing options.
///
/// # Examples
///
/// Initializing a regex with the "ignore whitespace" flag enabled:
///
/// ```
/// use compile_regex::{ast::{Node, Syntax}, RegexOptions};
///
/// const SYNTAX: Syntax = RegexOptions::DEFAULT
///     .ignore_whitespace(true)
///     .parse(r"(?<digits> # This is a comment
///         [ \d - ]+ # since `-` is a last non-whitespace char in a set,
///                   ## it's a literal '-'
///     )");
///
/// let comment_count = SYNTAX
///     .iter()
///     .filter(|spanned| matches!(spanned.node, Node::Comment))
///     .count();
/// // Sequential comments are glued together, so the number of comment nodes is 2
/// // rather than 3.
/// assert_eq!(comment_count, 2);
/// ```
#[derive(Debug, Default)]
pub struct RegexOptions {
    ignore_whitespace: bool,
}

impl RegexOptions {
    /// Default options.
    pub const DEFAULT: Self = Self {
        ignore_whitespace: false,
    };

    /// Sets whether whitespace should be ignored when parsing. This is equivalent to setting `(?x)` flag
    /// at the start of the regex.
    #[must_use]
    pub const fn ignore_whitespace(mut self, yes: bool) -> Self {
        self.ignore_whitespace = yes;
        self
    }

    /// Tries to validate the provided regular expression.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided `regex` is not a valid regular expression.
    pub const fn try_validate(&self, regex: &str) -> Result<ValidationOutput, Error> {
        let mut state = <ParseState>::new(regex, self);
        loop {
            match state.step() {
                Err(err) => return Err(err),
                Ok(ops::ControlFlow::Break(())) => break,
                Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
            }
        }

        Ok(ValidationOutput {
            node_count: state.syntax.len(),
        })
    }

    /// Validates the provided regular expression, panicking on errors. This is a shortcut for
    /// [`Self::try_validate()`]`.unwrap()`.
    ///
    /// # Panics
    ///
    /// Panics if the provided `regex` is not a valid regular expression.
    #[track_caller]
    pub const fn validate(&self, regex: &str) -> ValidationOutput {
        match self.try_validate(regex) {
            Err(err) => err.compile_panic(regex),
            Ok(output) => output,
        }
    }

    /// Tries to parse the provided regular expression.
    ///
    /// The `CAP` constant specifies the capacity of the produced [`Syntax`]. If it is exceeded,
    /// the method will return [`AstOverflow`](ErrorKind::AstOverflow). Use the [`parse!`](crate::parse!) macro
    /// to determine the capacity automatically.
    ///
    /// # Errors
    ///
    /// - Returns an error if the provided `regex` is not a valid regular expression.
    /// - Errors if one of internal limits is hit (e.g., the number of [syntax spans](Spanned)
    ///   or the number of named captures).
    pub const fn try_parse<'r, const CAP: usize>(
        &self,
        regex: &'r str,
    ) -> Result<Parsed<'r, Syntax<CAP>>, Error> {
        let mut state = ParseState::custom(regex, self, true);
        loop {
            match state.step() {
                Err(err) => return Err(err),
                Ok(ops::ControlFlow::Break(())) => {
                    return Ok(Parsed::new_unchecked(regex, state.into_syntax()))
                }
                Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
            }
        }
    }

    /// Parses the provided regular expression, panicking on errors. This is a shortcut for
    /// [`Self::try_parse()`]`.unwrap()`.
    ///
    /// # Panics
    ///
    /// Panics in the same situations in which [`Self::try_parse()`] returns an error.
    #[track_caller]
    pub const fn parse<'r, const CAP: usize>(&self, regex: &'r str) -> Parsed<'r, Syntax<CAP>> {
        match self.try_parse(regex) {
            Ok(spans) => spans,
            Err(err) => err.compile_panic(regex),
        }
    }

    /// Parses `regex` without restricting the number of produced [spans](Spanned).
    ///
    /// # Errors
    ///
    /// Returns an error if the provided `regex` is not a valid regular expression.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn try_parse_to_vec<'r>(&self, regex: &'r str) -> Result<Parsed<'r, Vec<Spanned>>, Error> {
        use core::mem;

        use crate::alloc::Vec;

        /// Max number of AST spans added during a single parsing step. This is roughly
        /// 2x the max number of "main" / non-comment spans that can be added on a single step
        /// (note that we glue line comments together).
        const STEP_CAP: usize = 8;

        let mut state = ParseState::<STEP_CAP>::custom(regex, self, true);
        let mut syntax = Vec::new();
        loop {
            let step_result = state.step()?;
            // Empty all captured spans to `syntax`. Since we never read from spans in the parser,
            // this doesn't influence subsequent steps.
            #[allow(clippy::missing_panics_doc)] // `syntax` is always set by design
            let SyntaxOrLen::Syntax(new_syntax) = &mut state.syntax
            else {
                panic!("cannot happen");
            };
            let new_syntax = mem::replace(new_syntax, Syntax::new(Spanned::DUMMY));
            syntax.extend_from_slice(new_syntax.as_slice());

            if step_result.is_break() {
                return Ok(Parsed::new_unchecked(regex, syntax));
            }
        }
    }
}

/// Maximum supported group depth.
const GROUP_DEPTH: usize = 16;
/// Maximum supported number of named groups.
const MAX_NAMED_GROUPS: usize = 64;

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
    syntax: SyntaxOrLen<CAP>,
}

impl<'a> ParseState<'a> {
    pub(crate) const fn new(regex: &'a str, options: &RegexOptions) -> Self {
        Self::custom(regex, options, false)
    }
}

impl<'a, const CAP: usize> ParseState<'a, CAP> {
    pub(crate) const fn custom(regex: &'a str, options: &RegexOptions, with_syntax: bool) -> Self {
        Self {
            regex_bytes: regex.as_bytes(),
            pos: 0,
            groups: Stack::new(GroupFrame::DUMMY),
            group_names: GroupNames::new(),
            set_depth: 0,
            is_empty_last_item: true,
            ignore_whitespace: options.ignore_whitespace,
            syntax: SyntaxOrLen::new(with_syntax),
        }
    }

    const fn backup(&self) -> Backup {
        Backup {
            pos: self.pos,
            span_count: self.syntax.len(),
        }
    }

    const fn restore(&mut self, backup: &Backup) {
        debug_assert!(self.pos >= backup.pos);

        self.pos = backup.pos;
        self.syntax.trim(backup.span_count);
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

    const fn push_ast(&mut self, start_pos: usize, node: Node) -> Result<(), Error> {
        self.push_custom_ast(Span::new(start_pos, self.pos), node)
    }

    const fn push_custom_ast(&mut self, span: Span, node: Node) -> Result<(), Error> {
        match &mut self.syntax {
            SyntaxOrLen::Syntax(syntax) => {
                let spanned = Spanned { node, span };
                if syntax.push(spanned).is_err() {
                    return Err(self.error(span.start, ErrorKind::AstOverflow));
                }
            }
            SyntaxOrLen::Len(len) => *len += 1,
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
        let mut comment_range = None::<Span>;
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
                    comment_range = Some(Span::new(self.pos, self.pos + 1));
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
            const_try!(self.push_custom_ast(range, Node::Comment));
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

    const fn parse_primitive(&mut self, ch: char, next_pos: usize) -> Result<(), Error> {
        match ch {
            '\\' => {
                const_try!(self.parse_escape());
                Ok(())
            }
            '.' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Node::Dot));
                Ok(())
            }
            '^' | '$' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Node::LineAssertion));
                Ok(())
            }
            _ => {
                self.pos = next_pos;
                Ok(())
            }
        }
    }

    const fn is_eof(&self) -> bool {
        self.pos == self.regex_bytes.len()
    }

    pub(crate) const fn step(&mut self) -> Result<ops::ControlFlow<()>, Error> {
        if self.set_depth > 0 {
            const_try!(self.set_step());
            return Ok(ops::ControlFlow::Continue(()));
        }

        const_try!(self.gobble_whitespace_and_comments());

        let Some((current_ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
            if !self.groups.is_empty() {
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
                const_try!(self.push_ast(self.pos - 1, Node::Alternation));
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

    pub(crate) const fn into_syntax(self) -> Syntax<CAP> {
        match self.syntax {
            SyntaxOrLen::Syntax(syntax) => syntax,
            SyntaxOrLen::Len(_) => Syntax::new(Spanned::DUMMY),
        }
    }
}
