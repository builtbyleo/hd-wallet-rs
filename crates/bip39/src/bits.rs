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

        let bit = bit_at_msb(self.byte, self.pos);

        self.pos += 1;

        Some(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

pub struct BitsIter<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
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
        let byte = bytes[byte_index];

        let bit = bit_at_msb(byte, self.pos % 8);

        self.pos += 1;

        Some(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let total_bits = self.bytes.len() * 8;
        let remaining = total_bits.saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

pub struct Bits11Iter<I> {
    pub bits: I,
}

#[derive(Clone, Copy, Debug)]
pub struct Bits11(u16);

impl Bits11 {
    pub fn index(self) -> usize {
        self.0 as usize
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
            // Bitshift:
            //
            // shift left one: makes space for one bit
            //
            // ORs bit with buffer: adds it to
            // the buffer at that new space
            buffer = (buffer << 1) | u16::from(bit);
        }

        Some(Bits11(buffer))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.bits.size_hint();
        (lower / 11, upper.map(|upper| upper / 11))
    }
}

// i  7 6 5 4 3 2 1 0
// b' 1 0 1 0 0 0 1 0
// need MSB first
// let shift = 7 - index;
// b' 1 0 1 0 0 0 1 0 >> shift
// b' 0 0 0 0 0 0 0 1 Moves MSB to the right
//
// b' 0 0 0 0 0 0 0 1
// b' 0 0 0 0 0 0 0 1 & (1 mask)
// -------------------
// b' 0 0 0 0 0 0 0 1
// Gives us bit at the right most pos
// bit = (byte >> shift) & 1;
fn bit_at_msb(byte: u8, pos: usize) -> u8 {
    let shift = 7 - pos;
    (byte >> shift) & 1
}
