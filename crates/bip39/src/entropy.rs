use rand::{Rng, rng};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub enum EntropySize {
    Bits128,
    Bits160,
    Bits192,
    Bits224,
    Bits256,
}

impl EntropySize {
    pub const fn bits(self) -> usize {
        match self {
            Self::Bits128 => 128,
            Self::Bits160 => 160,
            Self::Bits192 => 192,
            Self::Bits224 => 224,
            Self::Bits256 => 256,
        }
    }

    pub const fn bytes(self) -> usize {
        self.bits() / 8
    }

    pub const fn checksum_bits(self) -> usize {
        self.bits() / 32
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Entropy {
    bytes: Vec<u8>,
}

impl Entropy {
    pub fn generate(size: EntropySize) -> Self {
        let mut bytes = vec![0; size.bytes()];
        rng().fill_bytes(&mut bytes);

        Self { bytes }
    }

    pub fn bits11_iter(&self) -> Bits11Iter<'_> {
        Bits11Iter {
            bits: self.bits_iter(),
        }
    }

    fn bits_iter(&self) -> BitsIter<'_> {
        BitsIter {
            bytes: &self.bytes,
            pos: 0,
        }
    }

    pub fn checksum(&self, size: EntropySize) -> u8 {
        // let checksum = size.checksum_bits();
        todo!()
    }

    fn hash(&self) -> Vec<u8> {
        Sha256::digest(&self.bytes).to_vec()
    }
}

pub struct BitsIter<'a> {
    bytes: &'a [u8],
    pos: usize,
}

pub struct Bits11Iter<'a> {
    bits: BitsIter<'a>,
}

// stream 1 bit at a time
impl Iterator for BitsIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.bytes;
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

        return Some(bit);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Bits11(u16);

// stream 11 bits at a time
impl<'a> Iterator for Bits11Iter<'a> {
    type Item = Bits11;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = 0;

        for _ in 0..11 {
            let bit = self.bits.next()?;

            buffer <<= 1;

            buffer |= bit as u16;
        }

        Some(Bits11(buffer))
    }
}

#[cfg(test)]
mod test {
    use crate::entropy::{Entropy, EntropySize};

    #[test]
    fn entropy_size_bytes_are_correct() {
        assert_eq!(EntropySize::Bits128.bytes(), 128 / 8);
        assert_eq!(EntropySize::Bits160.bytes(), 160 / 8);
        assert_eq!(EntropySize::Bits192.bytes(), 192 / 8);
        assert_eq!(EntropySize::Bits224.bytes(), 224 / 8);
        assert_eq!(EntropySize::Bits256.bytes(), 256 / 8);
    }

    #[test]
    fn entropy_outputs_desired_size() {
        let allowed_sizes = vec![
            EntropySize::Bits128,
            EntropySize::Bits160,
            EntropySize::Bits192,
            EntropySize::Bits224,
            EntropySize::Bits256,
        ];

        for size in allowed_sizes {
            let entropy = Entropy::generate(size);
            assert_eq!(
                entropy.bytes.len(),
                size.bytes(),
                "generated entropy length for {:?} should be {} bytes",
                size,
                size.bytes()
            );
        }
    }

    #[test]
    fn entropy_generation_is_not_constant() {
        let first = Entropy::generate(EntropySize::Bits128);
        let second = Entropy::generate(EntropySize::Bits128);

        assert_ne!(
            first, second,
            "two generated entropy values should not be identical"
        );
    }
}
