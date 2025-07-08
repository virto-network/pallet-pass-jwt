//! Mock runtime for pallet-jwt unit tests.

#![cfg(test)]

use crate::*;
use crate::{self as pallet_jwt, crypto};

use frame_support::{
    derive_impl,
    parameter_types,
    runtime, // `#[runtime]` proc-macro
    traits::{ConstU32, ConstU64},
};

// use frame_system::offchain;

use pallet_session;
use sp_runtime::{BuildStorage, testing::UintAuthorityId};
use sp_runtime::{
    testing::TestXt,
    traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
};

use sp_core::{H256, sr25519::Signature};

type Block = frame_system::mocking::MockBlock<Test>;

// ─────────────────────────────────────────
// Type aliases
// ─────────────────────────────────────────
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type BlockNumber = u32;
pub type Public = UintAuthorityId;

// ─────────────────────────────────────────
// Test runtime
// ─────────────────────────────────────────
#[runtime]
mod runtime {
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
    pub const MaxLengthIssuerURL: u32   = 200;
    pub const MaxLengthIssuerJWKS: u32        = 1_000;
    pub const MinUpdateInterval: u32          = 10;
    pub const MaxUpdateInterval: u32          = 1_000;
    pub const MaxProposersPerIssuer: u32      = 10;
    pub const ExistentialDeposit: Balance     = 1;

    pub const MinimalConsensusPercentage: u32 = 70;
}

// ─────────────────────────────────────────
// frame_system::Config
// ─────────────────────────────────────────
#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = sp_core::sr25519::Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
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

type Extrinsic = TestXt<RuntimeCall, ()>;

// ─────────────────────────────────────────
// SigningTypes implementation
// ─────────────────────────────────────────
impl frame_system::offchain::SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

// ─────────────────────────────────────────
// CreateTransactionBase implementation
// ─────────────────────────────────────────
impl<LocalCall> frame_system::offchain::CreateTransactionBase<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type RuntimeCall = RuntimeCall;
    type Extrinsic = Extrinsic;
}

// ─────────────────────────────────────────
// CreateSignedTransaction implementation
// ─────────────────────────────────────────
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    fn create_signed_transaction<
        C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
    >(
        call: RuntimeCall,
        _public: <Signature as Verify>::Signer,
        _account: AccountId,
        nonce: u64,
    ) -> Option<Extrinsic> {
        Some(Extrinsic::new_signed(call, nonce, (), ()))
    }
}

// ─────────────────────────────────────────
// pallet_jwt::Config
// ─────────────────────────────────────────
impl pallet_jwt::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type BlockNumber = BlockNumber;
    type MaxLengthIssuerDomain = MaxLengthIssuerDomain;
    type MaxLengthIssuerURL = MaxLengthIssuerURL;
    type MaxLengthIssuerJWKS = MaxLengthIssuerJWKS;
    type MinUpdateInterval = MinUpdateInterval;
    type MaxUpdateInterval = MaxUpdateInterval;
    type MaxProposersPerIssuer = MaxProposersPerIssuer;
    type RegisterOrigin = frame_system::EnsureSigned<AccountId>;
    type UpdaterOrigin = frame_system::EnsureSigned<AccountId>;
    type ProposerOrigin = frame_system::EnsureSigned<AccountId>;
    type JwtOrigin = RuntimeOrigin;
    type Validators = pallet_session::Pallet<Test>;
    type NativeBalance = Balances;
    type AuthorityId = crypto::TestAuthId;
    type MinimalConsensusPercentage = MinimalConsensusPercentage;
}

// ─────────────────────────────────────────
// TestExternalities helper
// ─────────────────────────────────────────
#[allow(dead_code)]
pub fn new_test_ext() -> sp_io::TestExternalities {
    // use frame_support::traits::BuildGenesisConfig;

    // System genesis
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    // // Balances genesis (now with `dev_accounts`)
    // pallet_balances::GenesisConfig::<Test> {
    //     balances: vec![
    //         (sp_core::sr25519::Public::from_raw([1u8; 32]), 1_000_000_000_000),
    //         (sp_core::sr25519::Public::from_raw([2u8; 32]), 1_000_000_000_000),
    //     ],
    //     dev_accounts: None,
    // }
    // .assimilate_storage(&mut storage)
    // .unwrap();

    // Start every test at block 1
    let mut ext = sp_io::TestExternalities::new(storage);
    ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
    ext
}
