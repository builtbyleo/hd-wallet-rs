use crate::{
    entropy::{Entropy, EntropySize},
    words::WordList,
};

#[derive(Debug, Copy, Clone)]
pub enum MnemonicLength {
    W12,
    W15,
    W18,
    W21,
    W24,
}

#[derive(Debug)]
pub enum Error {
    InvalidEntropyLength(usize),
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
        Mnemonic::new(num_words)
    }
}

impl MnemonicLength {
    /// # Errors
    ///
    /// Returns `InvalidEntropyLength` if entropy not a valid length
    pub fn from_entropy(entropy: &Entropy) -> Result<MnemonicLength, Error> {
        let size = entropy.size() * 8;
        let mnemonic_type = match size {
            128 => MnemonicLength::W12,
            160 => MnemonicLength::W15,
            192 => MnemonicLength::W18,
            224 => MnemonicLength::W21,
            256 => MnemonicLength::W24,
            _ => Err(Error::InvalidEntropyLength(size))?,
        };

        Ok(mnemonic_type)
    }
}

impl Mnemonic {
    #[must_use]
    pub fn new(num_words: MnemonicLength) -> Self {
        let entropy_size: EntropySize = num_words.into();
        let entropy = Entropy::generate(entropy_size);
        Self::generate_words(&entropy)
    }

    /// # Errors
    ///
    /// Returns `InvalidEntropyLength` if entropy not a valid length
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Intentionally consumes Entropy so it cannot be reused after phrase generation"
    )]
    pub fn from_entropy(entropy: Entropy) -> Result<Self, Error> {
        MnemonicLength::from_entropy(&entropy)?;

        Ok(Self::generate_words(&entropy))
    }

    fn generate_words(entropy: &Entropy) -> Self {
        let words_list = WordList::new();

        let words = entropy
            .word_indices()
            .map(|bits| words_list.get_word(bits))
            .collect::<Vec<_>>()
            .join(" ");

        Self { words }
    }

    #[must_use]
    pub fn phrase(&self) -> &str {
        &self.words
    }
}

#[cfg(test)]
mod test {
    use crate::{Mnemonic, entropy::Entropy};

    #[test]
    fn known_words_from_known_entropy() {
        let known_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let known_bytes = [0u8; 16];
        let entropy = Entropy::from_bytes(&known_bytes);

        let mnemonic = Mnemonic::from_entropy(entropy).unwrap();

        assert_eq!(mnemonic.phrase(), known_mnemonic);
    }
}
