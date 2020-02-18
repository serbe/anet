use std::ops::{Index, Range};

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub struct RangeUsize {
    pub start: usize,
    pub end: usize,
}

impl RangeUsize {
    pub const fn new(start: usize, end: usize) -> RangeUsize {
        RangeUsize { start, end }
    }
}

impl From<RangeUsize> for Range<usize> {
    fn from(range: RangeUsize) -> Range<usize> {
        Range {
            start: range.start,
            end: range.end,
        }
    }
}

impl Index<RangeUsize> for String {
    type Output = str;

    #[inline]
    fn index(&self, index: RangeUsize) -> &str {
        &self[..][Range::from(index)]
    }
}

pub fn get_chunks<'a>(
    s: &'a str,
    range: Option<RangeUsize>,
    separator: &'a str,
    cut: bool,
    allow_empty: bool,
) -> (Option<RangeUsize>, Option<RangeUsize>) {
    if let Some(r) = range {
        let range = Range::from(r);
        let c = if cut { 0 } else { 1 };

        match s[range.clone()].find(separator) {
            Some(i) => {
                let mid = r.start + i + separator.len();
                let before = Some(RangeUsize::new(r.start, mid - 1)).filter(|r| r.start != r.end);
                let after = if allow_empty {
                    Some(RangeUsize::new(mid - c, r.end))
                } else {
                    Some(RangeUsize::new(mid - c, r.end)).filter(|r| r.start != r.end)
                };
                (before, after)
            }
            None => {
                if !s[range].is_empty() {
                    (Some(r), None)
                } else {
                    (None, None)
                }
            }
        }
    } else {
        (None, None)
    }
}
