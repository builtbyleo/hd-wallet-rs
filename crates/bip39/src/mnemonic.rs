use crate::entropy::EntropySize;

#[derive(Debug, Copy, Clone)]
pub enum MnemonicLength {
    W12,
    W15,
    W18,
    W21,
    W24,
}
// 2048 words, = 2^11. We need 11 bits to represent every word index.
// 128/ 8 ~= 11. 128 + checksum  / 8 === 11.
impl From<EntropySize> for MnemonicLength {
    fn from(key_size: EntropySize) -> Self {
        match key_size {
            EntropySize::Bits128 => MnemonicLength::W12,
            EntropySize::Bits160 => MnemonicLength::W15,
            EntropySize::Bits192 => MnemonicLength::W18,
            EntropySize::Bits224 => MnemonicLength::W21,
            EntropySize::Bits256 => MnemonicLength::W24,
        }
    }
}
