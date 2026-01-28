//! Bounded stack implementation with `const fn`s.

use core::fmt;

#[derive(Debug)]
pub(crate) struct PushError;

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
}

impl<T, const N: usize> Stack<T, N> {
    pub const fn as_slice(&self) -> &[T] {
        let (start, _) = self.inner.split_at(self.len);
        start
    }

    pub(crate) const fn len(&self) -> usize {
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
