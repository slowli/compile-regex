use core::ops;

#[derive(Debug)]
pub struct Error {
    pos: ops::Range<usize>,
    kind: ErrorKind,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn pos(&self) -> ops::Range<usize> {
        self.pos.clone()
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
    NonMatchingGroup,
}

impl ErrorKind {
    pub(crate) const fn with_position(self, pos: ops::Range<usize>) -> Error {
        Error { pos, kind: self }
    }
}
