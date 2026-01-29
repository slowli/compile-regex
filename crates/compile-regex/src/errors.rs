//! Error types.

use core::{fmt, ops, str};

use compile_fmt::{compile_panic, Ascii};

/// Error when parsing / validating regular expressions.
#[derive(Debug)]
pub struct Error {
    pos: ops::Range<usize>,
    kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid regex at {:?}: {}", self.pos, self.kind)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Error {
    /// Returns the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Returns byte offsets in the regex string that correspond to this error.
    pub fn pos(&self) -> ops::Range<usize> {
        self.pos.clone()
    }

    #[track_caller]
    pub(crate) const fn compile_panic(self, regex: &str) -> ! {
        let (_, hl) = regex.as_bytes().split_at(self.pos.start);
        let (hl, _) = hl.split_at(self.pos.end - self.pos.start);
        let Ok(hl) = str::from_utf8(hl) else {
            panic!("internal error: invalid error range");
        };

        compile_panic!(
            "invalid regex at ",
            self.pos.start => compile_fmt::fmt::<usize>(), "..", self.pos.end => compile_fmt::fmt::<usize>(),
            " ('", hl => compile_fmt::clip(64, "…"),
            "'): ", self.kind.as_ascii_str() => compile_fmt::clip_ascii(32, "")
        );
    }
}

/// Kind of a regex validation [`Error`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Missing node for repetition, e.g. in `*`.
    MissingRepetition,
    /// Unfinished repetition, e.g. in `.{`.
    UnfinishedRepetition,
    /// Empty decimal in a counted repetition, e.g. in `.{}`.
    EmptyDecimal,
    /// Invalid decimal in a counted repetition, e.g. in `.{2x}`.
    InvalidDecimal,
    /// Empty hexadecimal escape, e.g. `\x{}`.
    EmptyHex,
    /// Invalid hexadecimal escape, e.g. `\u{what}`.
    InvalidHex,
    /// Hexadecimal escape does not map to a Unicode char, e.g. `\U99999999`.
    NonUnicodeHex,
    /// Invalid counted repetition range, e.g. in `.{3,2}`.
    InvalidRepetitionRange,
    /// Unfinished escape, e.g. `\u1`.
    UnfinishedEscape,
    /// Backreferences, e.g. `\1`, are not supported (same as in the `regex` crate).
    UnsupportedBackref,
    /// Unsupported escape, e.g. `\Y`.
    UnsupportedEscape,
    /// Unfinished word boundary, e.g. `\b{start`.
    UnfinishedWordBoundary,
    /// Unknown word boundary, e.g. `\b{what}`.
    UnknownWordBoundary,
    /// Unicode classes like `\pN` or `\p{Digit}` are not supported.
    UnicodeClassesNotSupported,
    /// Lookaround groups are not supported (same as in the `regex` crate).
    LookaroundNotSupported,
    /// Unfinished capture name, e.g. in `(?<what`.
    UnfinishedCaptureName,
    /// Empty capture name, e.g. in `(?P<>.)`.
    EmptyCaptureName,
    /// Invalid capture name, e.g. in `(?< what >.)`.
    InvalidCaptureName,
    /// Non-ASCII chars in the capture name.
    NonAsciiCaptureName,
    /// Duplicate capture name, e.g., in `(?<test>.)(?<test>.)`.
    DuplicateCaptureName {
        /// Byte range of the previous capture name definition.
        prev_pos: ops::Range<usize>,
    },
    /// Unfinished group, e.g. in `(.`.
    UnfinishedGroup,
    /// Non-matching group end, e.g. in `(.))`.
    NonMatchingGroupEnd,
    /// Unfinished set, e.g. in `[0-9`.
    UnfinishedSet,
    /// Invalid set range start, e.g. in `[\d-9]` (`\d` doesn't correspond to a single char).
    InvalidRangeStart,
    /// Invalid set range end, e.g. in `[0-\D]` (`\D` doesn't correspond to a single char).
    InvalidRangeEnd,
    /// Invalid range, e.g., in `[9-0]`.
    InvalidRange,
    /// Invalid escape encountered in a character set, e.g. in `[0\b]` (`\b` is an *assertion*, it doesn't map to a char
    /// or a set of chars).
    InvalidEscapeInSet,
    /// Unfinished flags, e.g., `(?x`.
    UnfinishedFlags,
    /// Unfinished negation in flags, e.g. `(?-)`.
    UnfinishedFlagsNegation,
    /// Repeated negation in flags, e.g. `(?--x)`.
    RepeatedFlagNegation,
    /// Unsupported flag, e.g. in `(?Y)`.
    UnsupportedFlag,
    /// Repeated flag, e.g. in `(?xx)`.
    RepeatedFlag {
        /// Do the flag mentions contradict each other?
        contradicting: bool,
    },

    /// Disallowed whitespace, e.g. in `\u{1 2 3}`. This is technically supported by `regex`,
    /// but makes literals harder to read.
    DisallowedWhitespace,
    /// Disallowed comment, e.g.
    ///
    /// ```text
    /// \U{1# one!
    /// 23}
    /// ```
    ///
    /// This is technically supported by `regex`, but makes literals harder to read.
    DisallowedComment,

    /// Regex contains too many spans for the capacity specified in [`parse()`](crate::parse()) etc.
    AstOverflow,
    /// Regex contains too deeply nested groups.
    GroupDepthOverflow,
    /// Regex contains too many named captures / groups.
    NamedGroupOverflow,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ErrorKind {
    pub(crate) const fn with_position(self, pos: ops::Range<usize>) -> Error {
        Error { pos, kind: self }
    }

    const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingRepetition => "missing repetition",
            Self::UnfinishedRepetition => "unfinished repetition",
            Self::EmptyDecimal => "empty decimal number",
            Self::InvalidDecimal => "invalid decimal number",
            Self::EmptyHex => "empty hex escape",
            Self::InvalidHex => "invalid hex escape",
            Self::NonUnicodeHex => "non-Unicode hex escape",
            Self::InvalidRepetitionRange => "invalid repetition range",
            Self::UnfinishedEscape => "unfinished escape",
            Self::UnsupportedBackref => "backreferences (e.g., \\1) are not supported",
            Self::UnsupportedEscape => "escape is not supported",
            Self::UnfinishedWordBoundary => "unfinished word boundary",
            Self::UnknownWordBoundary => "unknown word boundary",
            Self::UnicodeClassesNotSupported => "Unicode classes are not supported",
            Self::LookaroundNotSupported => "lookaround groups are not supported",
            Self::UnfinishedCaptureName => "unfinished capture name",
            Self::EmptyCaptureName => "empty capture name",
            Self::InvalidCaptureName => "invalid capture name",
            Self::NonAsciiCaptureName => "non-ASCII capture names are not supported",
            Self::DuplicateCaptureName { .. } => "duplicate capture name",
            Self::UnfinishedGroup => "unfinished group",
            Self::NonMatchingGroupEnd => "non-matching group end",
            Self::GroupDepthOverflow => "too deeply nested group",
            Self::UnfinishedSet => "unfinished set",
            Self::InvalidEscapeInSet => "invalid escape in set [..]",
            Self::InvalidRangeStart => "invalid range start",
            Self::InvalidRangeEnd => "invalid range end",
            Self::InvalidRange => "invalid range",
            Self::UnfinishedFlags => "unfinished flags",
            Self::UnfinishedFlagsNegation => "unfinished flags negation",
            Self::RepeatedFlagNegation => "repeated flag negation",
            Self::UnsupportedFlag => "unsupported flag",
            Self::RepeatedFlag {
                contradicting: true,
            } => "contradicting flag value",
            Self::RepeatedFlag {
                contradicting: false,
            } => "repeated flag value",
            Self::DisallowedWhitespace => "disallowed whitespace (e.g., inside a hex escape)",
            Self::DisallowedComment => "disallowed comment (e.g., inside a hex escape)",
            Self::AstOverflow => "too many AST nodes",
            Self::NamedGroupOverflow => "too many named groups",
        }
    }

    const fn as_ascii_str(&self) -> Ascii<'static> {
        Ascii::new(self.as_str())
    }
}
