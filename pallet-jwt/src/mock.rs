use crate::frame_system::{GenesisConfig, mocking::MockBlock};
use frame::{
    deps::frame_support::{derive_impl, runtime, weights::constants::RocksDbWeight},
    runtime::prelude::*,
    testing_prelude::*,
};

use frame::deps::sp_io;
use frame_system::pallet;
// use frame_system::pallet;

// Configure a mock runtime to test the pallet.
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
    pub type Jwt = crate;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Nonce = u64;
    type Block = MockBlock<Test>;
    type BlockHashCount = ConstU64<250>;
    type DbWeight = RocksDbWeight;
    type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type IssuerId = JohanToCheckInMock;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}
