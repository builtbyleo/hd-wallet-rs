use rand::{Rng, rng};

#[derive(Debug, Clone, Copy)]
pub enum EntropySize {
    Bits128,
    Bits160,
    Bits192,
    Bits224,
    Bits256,
}

impl EntropySize {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits160 => 20,
            Self::Bits192 => 24,
            Self::Bits224 => 28,
            Self::Bits256 => 32,
        }
    }
}

struct Entropy;

impl Entropy {
    pub fn generate(entropy_size: EntropySize) -> Vec<u8> {
        let mut entropy = vec![0u8; entropy_size.bytes()];

        rng().fill_bytes(&mut entropy);

        entropy
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
                entropy.len(),
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
