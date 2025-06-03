#![cfg(test)]

use crate as pallet_jwt;
use frame::{
    deps::frame_support::{
        derive_impl, runtime,
        traits::{ConstU32, Everything},
        weights::constants::RocksDbWeight,
    },
    runtime::prelude::*,
};
use frame_system::mocking::MockBlock;
// use sp_runtime::BuildStorage;

// ─── Alias de tipos ─────────────────────────────────────────────────────────
pub type AccountId = u64;
pub type Balance = u128;
pub type BlockNumber = u32; // ← ahora es u32

// ─── Runtime de prueba ──────────────────────────────────────────────────────
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
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type Balances = pallet_balances;
    #[runtime::pallet_index(2)]
    pub type Jwt = pallet_jwt;
}

// ─── Constantes del pallet JWT ──────────────────────────────────────────────
parameter_types! {
    pub const MaxLengthIssuerDomain   : u32 = 100;
    pub const MaxLengthIssuerOpenIdURL: u32 = 200;
    pub const MaxLengthIssuerJWKS     : u32 = 1_000;
    pub const MinUpdateInterval       : u32 = 10;
    pub const MaxUpdateInterval       : u32 = 1_000;
    pub const MaxProposersPerIssuer   : u32 = 10;
    pub const BlockHashCount          : u64 = 250;
    pub const ExistentialDeposit      : Balance = 1;
}

// ─── frame_system::Config ───────────────────────────────────────────────────
#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type AccountId = AccountId;
    type BaseCallFilter = Everything;
    type Nonce = u64;
    type Block = MockBlock<Test>;
    type BlockHashCount = BlockHashCount;
    type DbWeight = RocksDbWeight;
    type AccountData = pallet_balances::AccountData<Balance>;
    type MaxConsumers = ConstU32<16>;
}

// ─── pallet_balances::Config ────────────────────────────────────────────────
#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type AccountStore = System;
    type ExistentialDeposit = ExistentialDeposit;
}

// ─── pallet_jwt::Config ─────────────────────────────────────────────────────
impl pallet_jwt::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type BlockNumber = BlockNumber;
    type MaxLengthIssuerDomain = MaxLengthIssuerDomain;
    type MaxLengthIssuerOpenIdURL = MaxLengthIssuerOpenIdURL;
    type MaxLengthIssuerJWKS = MaxLengthIssuerJWKS;
    type MinUpdateInterval = MinUpdateInterval;
    type MaxUpdateInterval = MaxUpdateInterval;
    type MaxProposersPerIssuer = MaxProposersPerIssuer;
    type AuthorityOrigin = frame_system::EnsureRoot<AccountId>;
    type JwtOrigin = RuntimeOrigin; // ← alias generado
}

// ─── Helper de génesis ──────────────────────────────────────────────────────
pub fn new_test_ext() -> sp_io::TestExternalities {
    // use frame_support::traits::BuildStorage;
    use sp_runtime::BuildStorage;

    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000_000_000_000), (2, 1_000_000_000_000)],
        dev_accounts: None, // ← nuevo campo
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    let mut ext = sp_io::TestExternalities::new(storage);
    ext.execute_with(|| System::set_block_number(1));
    ext
}
