pub struct ChecksumBits {
    pub byte: u8,
    pub pos: usize,
    pub len: usize,
}

impl Iterator for ChecksumBits {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.pos == self.len {
            return None;
        }

        let shift = 7 - self.pos;
        let bit = (self.byte >> shift) & 1;

        self.pos += 1;

        Some(bit)
    }
}

pub struct BitsIter<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
}

pub struct Bits11Iter<I> {
    pub bits: I,
}

#[derive(Clone, Copy, Debug)]
pub struct Bits11(u16);

impl Bits11 {
    pub fn bits(self) -> u16 {
        self.0
    }
}

// stream 1 bit at a time
impl Iterator for BitsIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = &self.bytes;
        let pos = self.pos;
        if pos >= bytes.len() * 8 {
            return None;
        }

        let byte_index = pos / 8;
        let bit_index = pos % 8;
        // i  7 6 5 4 3 2 1 0
        // b' 1 0 1 0 0 0 1 0
        // need MSB first
        let shift = 7 - bit_index;

        let byte = bytes[byte_index];

        // b' 1 0 1 0 0 0 1 0 >> shift
        // b' 0 0 0 0 0 0 0 1 Moves MSB to the right
        //
        // b' 0 0 0 0 0 0 0 1
        // b' 0 0 0 0 0 0 0 1 & (1 mask)
        // -------------------
        // b' 0 0 0 0 0 0 0 1
        // Gives us bit at the right most pos
        let bit = (byte >> shift) & 1;

        self.pos += 1;

        Some(bit)
    }
}

// stream 11 bits at a time
impl<I> Iterator for Bits11Iter<I>
where
    I: Iterator<Item = u8>,
{
    type Item = Bits11;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = 0;

        for _ in 0..11 {
            let bit = self.bits.next()?;

            buffer <<= 1;

            buffer |= u16::from(bit);
        }

        Some(Bits11(buffer))
    }
}
