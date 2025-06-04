//! Mock runtime for pallet-jwt unit tests.

#![cfg(test)]

use crate as pallet_jwt;

use frame_support::{
    derive_impl,
    parameter_types,
    runtime, // `#[runtime]` proc-macro
    traits::{ConstU32, ConstU64, Everything},
    weights::constants::RocksDbWeight,
};
use frame_system::mocking::MockBlock;
use pallet_session;
use sp_runtime::BuildStorage;

// ─────────────────────────────────────────
// Type aliases
// ─────────────────────────────────────────
pub type AccountId = u64;
pub type Balance = u128;
pub type BlockNumber = u32;

// ─────────────────────────────────────────
// Test runtime
// ─────────────────────────────────────────
#[runtime]
mod test_runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask
    )]
    // #[runtime::event_derive(pallet_session)]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type Balances = pallet_balances;
    #[runtime::pallet_index(2)]
    pub type Session = pallet_session;
    #[runtime::pallet_index(3)]
    pub type Jwt = pallet_jwt;
}

// ─────────────────────────────────────────
// Parameter constants
// ─────────────────────────────────────────
parameter_types! {
    pub const BlockHashCount: u64             = 250;
    pub const MaxLengthIssuerDomain: u32      = 100;
    pub const MaxLengthIssuerOpenIdURL: u32   = 200;
    pub const MaxLengthIssuerJWKS: u32        = 1_000;
    pub const MinUpdateInterval: u32          = 10;
    pub const MaxUpdateInterval: u32          = 1_000;
    pub const MaxProposersPerIssuer: u32      = 10;
    pub const ExistentialDeposit: Balance     = 1;
}

// ─────────────────────────────────────────
// frame_system::Config
// ─────────────────────────────────────────
#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type AccountId = AccountId;
    type BaseCallFilter = Everything;
    type Block = MockBlock<Test>;
    type BlockHashCount = BlockHashCount;
    type DbWeight = RocksDbWeight;
    type AccountData = pallet_balances::AccountData<Balance>;
    type MaxConsumers = ConstU32<16>;
}

// ─────────────────────────────────────────
// pallet_balances::Config
// ─────────────────────────────────────────
#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type AccountStore = System;
    type ExistentialDeposit = ExistentialDeposit;
}

// ─────────────────────────────────────────
// pallet_session::Config
// ─────────────────────────────────────────
impl pallet_session::Config for Test {
    type ValidatorId = AccountId;
    type SessionManager = ();
    type WeightInfo = ();
    type RuntimeEvent = RuntimeEvent;
    type ValidatorIdOf = sp_runtime::traits::ConvertInto;
    type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<10>, ConstU64<0>>;
    type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<10>, ConstU64<0>>;
    type SessionHandler = pallet_session::TestSessionHandler;
    type Keys = sp_runtime::testing::UintAuthorityId;
    type DisablingStrategy = ();
}

// ─────────────────────────────────────────
// pallet_jwt::Config
// ─────────────────────────────────────────
impl pallet_jwt::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type BlockNumber = BlockNumber;
    type MaxLengthIssuerDomain = MaxLengthIssuerDomain;
    type MaxLengthIssuerOpenIdURL = MaxLengthIssuerOpenIdURL;
    type MaxLengthIssuerJWKS = MaxLengthIssuerJWKS;
    type MinUpdateInterval = MinUpdateInterval;
    type MaxUpdateInterval = MaxUpdateInterval;
    type MaxProposersPerIssuer = MaxProposersPerIssuer;
    type RegisterOrigin = frame_system::EnsureSigned<AccountId>;
    type JwtOrigin = RuntimeOrigin;
    type Validators = pallet_session::Pallet<Test>;
}

// ─────────────────────────────────────────
// TestExternalities helper
// ─────────────────────────────────────────
#[allow(dead_code)]
pub fn new_test_ext() -> sp_io::TestExternalities {
    // use frame_support::traits::BuildGenesisConfig;

    // System genesis
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    // Balances genesis (now with `dev_accounts`)
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000_000_000_000), (2, 1_000_000_000_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    // Start every test at block 1
    let mut ext = sp_io::TestExternalities::new(storage);
    ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
    ext
}
