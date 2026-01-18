use core::{fmt, ops, str};

use compile_fmt::{compile_panic, Ascii};

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

impl std::error::Error for Error {}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn pos(&self) -> ops::Range<usize> {
        self.pos.clone()
    }

    #[track_caller]
    pub(crate) const fn compile_panic(self, regex: &str) -> ! {
        let (_, hl) = regex.as_bytes().split_at(self.pos.start);
        let (hl, _) = hl.split_at(self.pos.end - self.pos.start);
        let hl = match str::from_utf8(hl) {
            Ok(hl) => hl,
            Err(_) => panic!("internal error: invalid error range"),
        };

        compile_panic!(
            "invalid regex at ",
            self.pos.start => compile_fmt::fmt::<usize>(), "..", self.pos.end => compile_fmt::fmt::<usize>(),
            " ('", hl => compile_fmt::clip(64, "…"),
            "'): ", self.kind.as_ascii_str() => compile_fmt::clip_ascii(32, "")
        );
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    MissingRepetition,
    UnfinishedRepetition,
    EmptyDecimal,
    InvalidDecimal,
    EmptyHex,
    InvalidHex,
    NonUnicodeHex,
    InvalidRepetitionRange,
    UnfinishedEscape,
    UnsupportedBackref,
    UnsupportedEscape,
    UnfinishedWordBoundary,
    UnknownWordBoundary,
    UnicodeClassesNotSupported,
    LookaroundNotSupported,
    UnfinishedCaptureName,
    InvalidCaptureName,
    NonAsciiCaptureName,
    UnfinishedGroup,
    NonMatchingGroupEnd,
    UnfinishedSet,
    InvalidRangeStart,
    InvalidRangeEnd,
    InvalidRange,

    AstOverflow,
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
            Self::InvalidCaptureName => "invalid capture name",
            Self::NonAsciiCaptureName => "non-ASCII capture names are not supported",
            Self::UnfinishedGroup => "unfinished group",
            Self::NonMatchingGroupEnd => "non-matching group end",
            Self::UnfinishedSet => "unfinished set",
            Self::InvalidRangeStart => "invalid range start",
            Self::InvalidRangeEnd => "invalid range end",
            Self::InvalidRange => "invalid range",
            Self::AstOverflow => "too many AST nodes",
        }
    }

    const fn as_ascii_str(&self) -> Ascii<'static> {
        Ascii::new(self.as_str())
    }
}
