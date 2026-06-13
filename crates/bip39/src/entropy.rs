use rand::{Rng, rng};

#[derive(Debug, Clone, Copy)]
enum EntropySize {
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
    fn entropy_outputs_desired_size() {
        let allowed_sizes = vec![
            EntropySize::Bits128,
            EntropySize::Bits160,
            EntropySize::Bits192,
            EntropySize::Bits224,
            EntropySize::Bits256,
        ];

        for size in allowed_sizes {
            let generated_entropy = Entropy::generate(size);
            assert_eq!(generated_entropy.len(), size.bytes());
        }
    }
}
