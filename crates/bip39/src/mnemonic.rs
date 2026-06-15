use crate::entropy::{Entropy, EntropySize};

#[derive(Debug, Copy, Clone)]
pub enum MnemonicLength {
    W12,
    W15,
    W18,
    W21,
    W24,
}

pub struct Mnemonic {
    pub words: String,
}

// 2048 words, = 2^11. We need 11 bits to represent every word index.
// 128/ 8 ~= 11. 128 + checksum  / 8 === 11.
// checksum is entropy + (sha256(entropy) per 32bits)
impl From<MnemonicLength> for EntropySize {
    fn from(length: MnemonicLength) -> Self {
        match length {
            MnemonicLength::W12 => EntropySize::Bits128,
            MnemonicLength::W15 => EntropySize::Bits160,
            MnemonicLength::W18 => EntropySize::Bits192,
            MnemonicLength::W21 => EntropySize::Bits224,
            MnemonicLength::W24 => EntropySize::Bits256,
        }
    }
}

impl From<MnemonicLength> for Mnemonic {
    fn from(num_words: MnemonicLength) -> Self {
        let entropy_size: EntropySize = num_words.into();
        let mut entropy = Entropy::generate(entropy_size);

        let wordlist: Vec<&'static str> = include_str!("words.txt").split_whitespace().collect();

        // TODO: split into 11 bits and map to word list

        todo!()
    }
}

impl Mnemonic {
    pub fn phrase(&self) -> &str {
        &self.words
    }
}
