#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
use frame_support::{BoundedVec, ensure, traits::Get, dispatch::DispatchResult};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::AtLeast32BitUnsigned;

#[frame::pallet]
pub mod pallet {
    use super::*;
    use frame::prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // Configuration trait for the pallet.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        // Defines the event type for the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type BlockNumber: From<u32> + Into<u32> + AtLeast32BitUnsigned + Copy + MaxEncodedLen;

        // <Example of constant>
        // Defines the maximum value the counter can hold.
        #[pallet::constant]
        type CounterMaxValue: Get<u32>;
        // </Example of constant>

        #[pallet::constant]
        type MaxLengthIssuerName: Get<u32>;

        #[pallet::constant]
        type MaxLengthIssuerDomain: Get<u32>;

        #[pallet::constant]
        type MaxLengthIssuerOpenIdURL: Get<u32>;

        #[pallet::constant]
        type MaxLengthIssuerJWKS: Get<u32>;

        #[pallet::constant]
        type MinUpdateInterval: Get<u32>;

        #[pallet::constant]
        type MaxUpdateInterval: Get<u32>;
    }

    // Structs
    #[derive(Clone, Debug, PartialEq, TypeInfo, Encode, Decode, MaxEncodedLen, Default)]
    #[scale_info(skip_type_params(T))]
    pub struct Issuer<T: Config> {
        // To Do: Makes sense have this public?
        // Issuer name, like "Google", "Facebook", "Apple", etc.
        pub name: BoundedVec<u8, T::MaxLengthIssuerName>,
        // Issuer domain, like "google.com", "facebook.com", "apple.com", etc.
        pub domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        // Issuer OpenID URL, like "https://accounts.google.com/.well-known/openid-configuration", "https://account.apple.com/.well-known/openid-configuration", etc.
        pub open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        // Issuer JWKS, like the one in "https://www.googleapis.com/oauth2/v3/certs"
        pub jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
        // How many blocks to wait before the issuer can be updated
        pub update_interval: BlockNumberFor<T>,
        // Auto update enabled or not
        pub auto_update: bool,
        // Issuer is active or not for validating JWT
        pub status: bool,
        // To Do: discuss if the following fields make sense, could make sense in case of freezed balance for registering issuer
        // // The account who created the issuer
        // pub created_by: AccountId<T>,
        // // The account who modified the issuer
        // pub modified_by: AccountId<T>,
        // The block number when the issuer was created
        // pub created_at: BlockNumberFor<T>,
        // // The block number when the issuer was updated
        // pub updated_at: BlockNumberFor<T>,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        // <Example of event>
        /// The counter value has been set to a new value by Root.
        CounterValueSet {
            /// The new value set.
            counter_value: u32,
        },
        /// A user has successfully incremented the counter.
        CounterIncremented {
            /// The new value set.
            counter_value: u32,
            /// The account who incremented the counter.
            who: T::AccountId,
            /// The amount by which the counter was incremented.
            incremented_amount: u32,
        },
        /// A user has successfully decremented the counter.
        CounterDecremented {
            /// The new value set.
            counter_value: u32,
            /// The account who decremented the counter.
            who: T::AccountId,
            /// The amount by which the counter was decremented.
            decremented_amount: u32,
        },
        // </Example of event>
        IssuerRegistered {
            /// The account who registered the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        },

        IssuerUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        },

        IssuerDeleted {
            /// The account who deleted the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        },

        IssuerStatusUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            /// The new status.
            status: bool,
        },

        IssuerAutoUpdateUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            /// The new auto update status.
            auto_update: bool,
        },

        IssuerUpdateIntervalUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
        },

        IssuerJWKSUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        },

        IssuerOpenIdURLUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        },
    }

    // <Example of storage>
    /// Storage for the current value of the counter.
    #[pallet::storage]
    pub type CounterValue<T> = StorageValue<_, u32>;

    /// Storage map to track the number of interactions performed by each account.
    #[pallet::storage]
    pub type UserInteractions<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, u32>;
    // </Example of storage>

    #[pallet::storage]
    pub type IssuerMap<T: Config> =
        StorageMap<_, Twox64Concat, BoundedVec<u8, T::MaxLengthIssuerName>, Issuer<T>>;

    #[pallet::storage]
    pub type JksMap<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BoundedVec<u8, T::MaxLengthIssuerName>,
        BoundedVec<u8, T::MaxLengthIssuerJWKS>,
    >;

    #[pallet::storage]
    pub type JksProposals<T: Config> = CountedStorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerName>>, // Issuer Name
            NMapKey<Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerJWKS>>, // JKS
            NMapKey<Blake2_128Concat, T::AccountId>,                           // AccountId
        ),
        (),
    >;

    #[pallet::error]
    pub enum Error<T> {
        // <Example of error>
        /// The counter value exceeds the maximum allowed value.
        CounterValueExceedsMax,
        /// The counter value cannot be decremented below zero.
        CounterValueBelowZero,
        /// Overflow occurred in the counter.
        CounterOverflow,
        /// Overflow occurred in user interactions.
        UserInteractionOverflow,
        // </Example of error>

        // Issuer errors
        IssuerAlreadyExists,
        IssuerNameTooLong,
        IssuerDomainTooLong,
        IssuerJWKSTooLong,
        IssuerOpenIdURLTooLong,
        IssuerDoesNotExist,
        IssuerAutoUpdateAlreadyEnabled,
        IssuerAutoUpdateAlreadyDisabled,
        IssuerUpdateIntervalAboveMax,
        IssuerUpdateIntervalBelowMin, // To Do: Is this needed?
        IssuerUpdateIntervalNotMultipleOfBlock,
        IssuerOpenIdURLOrJWKSNotProvided,
        IssuerUpdated,
        OnlyGovernanceCanUpdateIssuer,
        OnlyGovernanceCanDeleteIssuer,
        InvalidJsonFormatForJWKS,
        InvalidJsonFormatForOpenIdURL,
        AlreadyVotedForJWKS,
        OnlyValidatorsCanVoteForJWKS,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // Register a new issuer
        // The dispatch origin of this call must be _any AccountId_.
        // The issuer name, domain, open_id_url and jwks are validated against the corresponding max length.
        // The issuer is registered in the storage map.
        // The event IssuerRegistered is emitted.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::default())]
        pub fn register_issuer(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            update_interval: BlockNumberFor<T>,
            auto_update: bool,
            status: bool,
        ) -> DispatchResult {
            // ensure_root(origin)?;
            let who = ensure_signed(origin)?;

            Self::validate_all(
                &name,
                &domain,
                &open_id_url,
                &jwks,
                &update_interval,
                &auto_update,
                &status,
            )?;

            // Create the issuer
            let issuer = Issuer {
                name: name.clone(),
                domain,
                open_id_url,
                jwks,
                update_interval,
                auto_update,
                status,
            };

            IssuerMap::<T>::insert(&name, issuer);

            Self::deposit_event(Event::<T>::IssuerRegistered { who: who, name });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::default())]
        pub fn update_issuer(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            update_interval: BlockNumberFor<T>,
            auto_update: bool,
            status: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the issuer

            Self::validate_all(
                &name,
                &domain,
                &open_id_url,
                &jwks,
                &update_interval,
                &auto_update,
                &status,
            )?;

            // Create the issuer
            let issuer = Issuer {
                name: name.clone(),
                domain,
                open_id_url,
                jwks,
                update_interval,
                auto_update,
                status,
            };

            IssuerMap::<T>::insert(&name, issuer);

            Self::deposit_event(Event::<T>::IssuerUpdated { who, name });

            Ok(())
        }

        /// Decrement the counter by a specified amount.
        ///
        /// This function can be called by any signed account.
        ///
        /// - `amount_to_decrement`: The amount by which to decrement the counter.
        ///
        /// Emits `CounterDecremented` event when successful.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::default())]
        pub fn decrement(origin: OriginFor<T>, amount_to_decrement: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let current_value = CounterValue::<T>::get().unwrap_or(0);

            let new_value = current_value
                .checked_sub(amount_to_decrement)
                .ok_or(Error::<T>::CounterValueBelowZero)?;

            CounterValue::<T>::put(new_value);

            UserInteractions::<T>::try_mutate(&who, |interactions| -> Result<_, Error<T>> {
                let new_interactions = interactions
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(Error::<T>::UserInteractionOverflow)?;
                *interactions = Some(new_interactions); // Store the new value.

                Ok(())
            })?;

            Self::deposit_event(Event::<T>::CounterDecremented {
                counter_value: new_value,
                who,
                decremented_amount: amount_to_decrement,
            });

            Ok(())
        }
        // </Example of call>
    }
}

impl<T: Config> Pallet<T> {
    fn validate_issuer_name(name: &BoundedVec<u8, T::MaxLengthIssuerName>) -> DispatchResult {
        ensure!(
            name.len() <= T::MaxLengthIssuerName::get() as usize,
            Error::<T>::IssuerNameTooLong
        );
        Ok(())
    }

    fn validate_issuer_domain(domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>) -> DispatchResult {
        ensure!(
            domain.len() <= T::MaxLengthIssuerDomain::get() as usize,
            Error::<T>::IssuerDomainTooLong
        );
        Ok(())
    }

    fn validate_issuer_open_id_url(
        open_id_url: &Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
    ) -> DispatchResult {
        if let Some(open_id_url) = open_id_url {    
            ensure!(
                open_id_url.len() <= T::MaxLengthIssuerOpenIdURL::get() as usize,
                Error::<T>::IssuerOpenIdURLTooLong
            );
        }
        Ok(())
    }

    fn validate_issuer_jwks(jwks: &Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>) -> DispatchResult {
        if let Some(jwks) = jwks {
            ensure!(
                jwks.len() <= T::MaxLengthIssuerJWKS::get() as usize,
                Error::<T>::IssuerJWKSTooLong
            );
        }
        Ok(())  
    }

    fn validate_issuer_open_id_url_or_jwks(
        open_id_url: &Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        jwks: &Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
    ) -> DispatchResult {
        Self::validate_issuer_open_id_url(&open_id_url)?;
        Self::validate_issuer_jwks(&jwks)?;
        Ok(())
    }

    fn validate_update_interval(update_interval: &BlockNumberFor<T>) -> DispatchResult {
        // Ensure the update interval is not above the max
        ensure!(
            *update_interval <= T::MaxUpdateInterval::get().into(),
            Error::<T>::IssuerUpdateIntervalAboveMax
        );

        // Ensure the update interval is not below the min
        ensure!(
            *update_interval >= T::MinUpdateInterval::get().into(),
            Error::<T>::IssuerUpdateIntervalBelowMin
        );
        Ok(())
    }

    fn validate_all(
        name: &BoundedVec<u8, T::MaxLengthIssuerName>,
        domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
        open_id_url: &Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        jwks: &Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
        update_interval: &BlockNumberFor<T>,
        _auto_update: &bool,
        _status: &bool,
    ) -> DispatchResult {
        Self::validate_issuer_name(name)?;
        Self::validate_issuer_domain(domain)?;
        Self::validate_issuer_open_id_url_or_jwks(open_id_url, jwks)?;
        Self::validate_update_interval(update_interval)?;
        Ok(())
    }
}
