#![cfg_attr(not(feature = "std"), no_std)]

// Re-export all pallet parts, this is needed to properly import the pallet into the runtime.
pub use pallet::*;

use frame::prelude::*;
use frame_support::traits::fungible::{Inspect, Mutate};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame::pallet]
pub mod pallet {

    use frame_support::sp_runtime::traits::BlakeTwo256;

    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type TheBalance: Inspect<Self::AccountId> + Mutate<Self::AccountId>;
        type IssuerId: JohanToCheck;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type StorageMap<T: Config> = StorageValue<
        _,
        BlakeTwo256,
        IssuerId,
        Option<(T::AccountId, T::Balance)>,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RegisteredNewIssuer,
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Error names should be descriptive.
        NoneValue,
        /// Errors should have helpful documentation associated with them.
        ErrorTransfering,

        /// Error issuance increasing above max
        ErrorIncreasingIssuance,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::default())]
        pub fn register(origin: OriginFor<T>, id: u128) -> DispatchResultWithPostInfo {
            // Check the origin of the call is a signed user.
            let who = ensure_signed(origin)?;
            Ok(().into())
        }

        /// An example dispatchable that may throw a custom error.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::default())]
        pub fn set_metadata(
            origin: OriginFor<T>,
            name: String,
            url: String,
            
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            // let deposit_base: T::MetadataDepositBase;
            // let deposit_bytes: T::MetadataDepositBytes;

            // Emit an event
            Self::deposit_event(Event::TransferedTokens);
            Ok(().into())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(Weight::default())]
        pub fn set_keys(origin: OriginFor<T>, keys: Vec<T::key> ) -> DispatchResultWithPostInfo {
            // Check the origin of the call is a signed user.
            let who = ensure_signed(origin)?;

            // let key_deposit_base: T::KeyDepositBase;
            // let key_deposit_bytes: T::KeyDepositBytes;

            Ok(().into())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::default())]
        pub fn destroy(origin: OriginFor<T>, issuer: T::issuer ) -> DispatchResultWithPostInfo {
            // Check the origin of the call is a signed user.
            let who = ensure_signed(origin)?;

            

            Ok(().into())
        }

        
    }
}
