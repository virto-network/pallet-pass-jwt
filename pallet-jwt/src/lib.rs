#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{BoundedVec, dispatch::DispatchResult, ensure, traits::Get};
use frame_system::pallet_prelude::*;
use log::info;
pub use pallet::*;
use sp_runtime::traits::AtLeast32BitUnsigned;

#[frame::pallet]
pub mod pallet {
    use super::*;
    use frame::prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        // Defines the event type for the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type BlockNumber: From<u32> + Into<u32> + AtLeast32BitUnsigned + Copy + MaxEncodedLen;

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
            /// The issuer name.
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            /// The new update interval.
            update_interval: BlockNumberFor<T>,
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
            NMapKey<Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerJWKS>>, // JWKS
            NMapKey<Blake2_128Concat, T::AccountId>,                           // AccountId
        ),
        (),
        OptionQuery,
    >;

    #[pallet::error]
    pub enum Error<T> {
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

            // Check if the issuer already exists
            if IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerAlreadyExists.into());
            }

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

            // Update Issuer storage only if the issuer exists
            if IssuerMap::<T>::contains_key(&name) {
                IssuerMap::<T>::insert(&name, issuer);
            } else {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            Self::deposit_event(Event::<T>::IssuerUpdated { who, name });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(Weight::default())]
        pub fn delete_issuer(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to delete the issuer

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Delete the issuer
            IssuerMap::<T>::remove(&name);

            Self::deposit_event(Event::<T>::IssuerDeleted { who, name });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::default())]
        pub fn set_update_interval(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            update_interval: BlockNumberFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to delete the issuer

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;
            Self::validate_update_interval(&update_interval)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the update interval
            IssuerMap::<T>::get(&name).unwrap().update_interval = update_interval;

            Self::deposit_event(Event::<T>::IssuerUpdateIntervalUpdated {
                who,
                name,
                update_interval,
            });

            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(Weight::default())]
        pub fn set_auto_update(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            auto_update: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the auto update

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the auto update
            IssuerMap::<T>::get(&name).unwrap().auto_update = auto_update;

            Self::deposit_event(Event::<T>::IssuerAutoUpdateUpdated {
                who,
                name,
                auto_update,
            });

            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(Weight::default())]
        pub fn set_status(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            status: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the status

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the status
            IssuerMap::<T>::get(&name).unwrap().status = status;

            Self::deposit_event(Event::<T>::IssuerStatusUpdated { who, name, status });

            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(Weight::default())]
        pub fn set_open_id_url(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            open_id_url: BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the open id url

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the open id url
            IssuerMap::<T>::get(&name).unwrap().open_id_url = Some(open_id_url);

            Self::deposit_event(Event::<T>::IssuerOpenIdURLUpdated { who, name });

            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(Weight::default())]
        pub fn propose_jwks(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
            jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to propose the jwks Validators only!!!

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Validate the jwks
            Self::validate_issuer_jwks(&Some(jwks.clone()))?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Check if the jwks is already proposed
            let jwks = jwks.clone();
            if JksProposals::<T>::contains_key((name.clone(), jwks.clone(), who.clone())) {
                return Err(Error::<T>::AlreadyVotedForJWKS.into());
            }

            // Propose the jwks
            JksProposals::<T>::insert((name, jwks, who), ());

            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(Weight::default())]
        pub fn set_jwks(
            origin: OriginFor<T>,
            name: BoundedVec<u8, T::MaxLengthIssuerName>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the jwks

            // Validate the issuer name
            Self::validate_issuer_name(&name)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&name) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            let most_voted_jwks = Self::get_jwks_with_higher_count(&name);

            // Insert the most voted jwks in the JksMap
            JksMap::<T>::insert(&name, most_voted_jwks);

            Self::deposit_event(Event::<T>::IssuerJWKSUpdated { who, name });

            Ok(())
        }
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

    fn validate_issuer_jwks(
        jwks: &Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
    ) -> DispatchResult {
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

    pub fn count_accounts_for_issuer_jwks(
        issuer_name: BoundedVec<u8, T::MaxLengthIssuerName>,
        issuer_jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
    ) -> u32 {
        let prefix = (issuer_name, issuer_jwks);

        let count = JksProposals::<T>::iter_prefix(prefix).count();

        count as u32
    }

    pub fn get_jwks_with_higher_count(
        issuer_name: &BoundedVec<u8, T::MaxLengthIssuerName>,
    ) -> BoundedVec<u8, T::MaxLengthIssuerJWKS> {
        info!("get_jwks_with_higher_count for {:?}", issuer_name);
        // Create empty jwks
        let jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS> = BoundedVec::new();

        jwks
    }
}
