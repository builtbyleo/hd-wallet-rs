use rand::{Rng, rng};
use sha2::{Digest, Sha256};

use crate::bits::{Bits11Iter, BitsIter, ChecksumBits};

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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn bits_iter(&self) -> BitsIter<'_> {
        BitsIter {
            bytes: &self.bytes,
            pos: 0,
        }
    }

    pub fn word_indices(&self) -> Bits11Iter<impl Iterator<Item = u8> + '_> {
        Bits11Iter {
            bits: self.bits_iter().chain(self.checksum_bits()),
        }
    }

    pub fn checksum_bits(&self) -> ChecksumBits {
        let hash = Sha256::digest(&self.bytes);
        let first_byte = hash[0];

        ChecksumBits {
            byte: first_byte,
            pos: 0,
            len: self.checksum_len(),
        }
    }

    fn checksum_len(&self) -> usize {
        self.bytes.len() * 8 / 32
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
