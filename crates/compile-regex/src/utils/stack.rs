//! Bounded stack implementation with `const fn`s.

use core::{fmt, slice};

#[derive(Debug)]
pub(crate) struct PushError;

/// Bounded-capacity stack with `const fn` operations. Used to store [syntax spans](crate::ast::Span)
/// via [`Syntax` type alias](crate::ast::Syntax).
pub struct Stack<T, const N: usize = 128> {
    inner: [T; N],
    len: usize,
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Stack<T, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), formatter)
    }
}

impl<T: Copy, const N: usize> Stack<T, N> {
    pub(crate) const fn new(filler: T) -> Self {
        Self {
            inner: [filler; N],
            len: 0,
        }
    }

    pub(crate) const fn push(&mut self, item: T) -> Result<(), PushError> {
        if self.len == N {
            Err(PushError)
        } else {
            self.inner[self.len] = item;
            self.len += 1;
            Ok(())
        }
    }

    pub(crate) const fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(self.inner[self.len])
        }
    }
}

impl<T, const N: usize> Stack<T, N> {
    /// Returns the underlying slice of elements.
    pub const fn as_slice(&self) -> &[T] {
        let (start, _) = self.inner.split_at(self.len);
        start
    }

    /// Iterates over elements in this stack in the order of their insertion.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator + '_ {
        self.as_slice().iter()
    }

    /// Checks whether the stack is empty (has 0 elements).
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of elements in the stack.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn trim(&mut self, new_len: usize) {
        self.len = new_len;
    }

    pub(crate) const fn index_mut(&mut self, idx: usize) -> &mut T {
        assert!(idx < self.len, "index out of range");
        &mut self.inner[idx]
    }
}

impl<T, const N: usize> AsRef<[T]> for Stack<T, N> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: PartialEq, const N: usize> PartialEq for Stack<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Stack<T, N> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}
