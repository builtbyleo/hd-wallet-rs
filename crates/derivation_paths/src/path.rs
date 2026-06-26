use std::fmt::{Display, Formatter, Result};

#[derive(Default)]
enum Purpose {
    #[default]
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}

impl Purpose {
    fn number(&self) -> u32 {
        match self {
            Purpose::Bip44 => 44,
            Purpose::Bip49 => 49,
            Purpose::Bip84 => 84,
            Purpose::Bip86 => 86,
        }
    }
}

struct BipPath {
    purpose: Purpose,
    coin_type: u32,
    account: u32,
    change: u32,
    index: u32,
}

impl Default for BipPath {
    fn default() -> Self {
        Self::new()
    }
}

impl BipPath {
    pub fn new() -> Self {
        Self {
            purpose: Purpose::default(),
            coin_type: 0,
            account: 0,
            change: 0,
            index: 0,
        }
    }

    pub fn purpose(mut self, purpose: Purpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn coin_type(mut self, coin_type: u32) -> Self {
        self.coin_type = coin_type;
        self
    }

    pub fn account(mut self, account: u32) -> Self {
        self.account = account;
        self
    }

    pub fn change(mut self, change: u32) -> Self {
        self.change = change;
        self
    }

    pub fn index(mut self, index: u32) -> Self {
        self.index = index;
        self
    }
}

impl Display for BipPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose.number(),
            self.coin_type,
            self.account,
            self.change,
            self.index,
        )
    }
}
