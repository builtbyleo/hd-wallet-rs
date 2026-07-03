use std::fmt::{Display, Formatter, Result};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    #[default]
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    #[default]
    External,
    Internal,
}

impl Change {
    pub const fn number(self) -> u32 {
        match self {
            Change::External => 0,
            Change::Internal => 1,
        }
    }
}

impl Purpose {
    pub fn number(self) -> u32 {
        match self {
            Purpose::Bip44 => 44,
            Purpose::Bip49 => 49,
            Purpose::Bip84 => 84,
            Purpose::Bip86 => 86,
        }
    }
}

pub struct BipPath {
    purpose: Purpose,
    coin_type: u32,
    account: u32,
    change: Change,
    index: u32,
}

impl BipPath {
    pub fn new() -> Self {
        Self {
            purpose: Purpose::default(),
            coin_type: 0,
            account: 0,
            change: Change::default(),
            index: 0,
        }
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    pub fn account(&self) -> u32 {
        self.account
    }

    pub fn change(&self) -> Change {
        self.change
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn with_purpose(mut self, purpose: Purpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn with_coin_type(mut self, coin_type: u32) -> Self {
        self.coin_type = coin_type;
        self
    }

    pub fn with_account(mut self, account: u32) -> Self {
        self.account = account;
        self
    }

    pub fn with_change(mut self, change: Change) -> Self {
        self.change = change;
        self
    }

    pub fn with_index(mut self, index: u32) -> Self {
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
            self.change.number(),
            self.index,
        )
    }
}
