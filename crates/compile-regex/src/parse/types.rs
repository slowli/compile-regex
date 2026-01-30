//! Internal types used during parsing.

use core::fmt;

use crate::{
    ast::{Span, Spanned, Syntax},
    Error, ErrorKind,
};

#[derive(Debug)]
pub(super) enum PrimitiveKind {
    Literal(char),
    PerlClass,
    Other,
}

impl PrimitiveKind {
    pub(super) const fn is_valid_set_member(&self) -> bool {
        matches!(self, Self::Literal(_) | Self::PerlClass)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Flags {
    pub(super) is_empty: bool,
    pub(super) ignore_whitespace: Option<bool>,
}

/// Parser state backup.
#[derive(Debug)]
pub(super) struct Backup {
    pub(super) pos: usize,
    pub(super) span_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct GroupFrame {
    /// `ignore_whitespace` value when the group was pushed to the stack (= one that should be set
    /// when the group is popped from the stack).
    pub(super) prev_ignore_whitespace: bool,
}

impl GroupFrame {
    pub(super) const DUMMY: Self = Self {
        prev_ignore_whitespace: false,
    };
}

pub(super) struct GroupNames<const CAP: usize> {
    items: [Span; CAP],
    len: usize,
}

impl<const CAP: usize> fmt::Debug for GroupNames<CAP> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (items, _) = self.items.split_at(self.len);
        formatter.debug_list().entries(items).finish()
    }
}

impl<const CAP: usize> GroupNames<CAP> {
    pub(super) const fn new() -> Self {
        Self {
            items: [Span::new(0, 0); CAP],
            len: 0,
        }
    }

    pub(super) const fn insert(&mut self, item: Span, regex_bytes: &[u8]) -> Result<(), Error> {
        const fn bytes_eq(bytes: &[u8], x: Span, y: Span) -> bool {
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
pub(super) enum SyntaxOrLen<const CAP: usize> {
    Syntax(Syntax<CAP>),
    Len(usize),
}

impl<const CAP: usize> SyntaxOrLen<CAP> {
    pub(super) const fn new(with_syntax: bool) -> Self {
        if with_syntax {
            Self::Syntax(Syntax::new(Spanned::DUMMY))
        } else {
            Self::Len(0)
        }
    }

    pub(super) const fn len(&self) -> usize {
        match self {
            Self::Syntax(syntax) => syntax.len(),
            Self::Len(len) => *len,
        }
    }

    pub(super) const fn trim(&mut self, new_len: usize) {
        debug_assert!(self.len() >= new_len);
        match self {
            Self::Syntax(syntax) => syntax.trim(new_len),
            Self::Len(len) => *len = new_len,
        }
    }
}
