use crate::bits::Bits11;

pub struct WordList {
    inner: Vec<&'static str>,
}

impl WordList {
    pub fn new() -> Self {
        Self {
            inner: include_str!("words.txt").split_whitespace().collect(),
        }
    }
    pub fn get_word(&self, bits: Bits11) -> &'static str {
        self.inner[usize::from(bits.bits())]
    }
}
