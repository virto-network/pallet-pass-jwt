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
        // Issuer OpenID URL, like "https://accounts.google.com/.well-known/openid-configuration", "https://account.apple.com/.well-known/openid-configuration", etc.
        pub open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        // How many blocks to wait before the issuer can be updated
        pub update_interval: BlockNumberFor<T>,
        // Auto update enabled or not
        pub auto_update: bool,
        // Issuer is active or not for validating JWT
        pub status: bool,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IssuerRegistered {
            /// The account who registered the issuer.
            who: T::AccountId,
            /// The issuer name.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        },

        IssuerUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        },

        IssuerDeleted {
            /// The account who deleted the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        },

        IssuerStatusUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new status.
            status: bool,
        },

        IssuerAutoUpdateUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new auto update status.
            auto_update: bool,
        },

        IssuerUpdateIntervalUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new update interval.
            update_interval: BlockNumberFor<T>,
        },

        IssuerJWKSUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        },

        IssuerOpenIdURLUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        },
    }

    #[pallet::storage]
    pub type IssuerMap<T: Config> =
        StorageMap<_, Twox64Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, Issuer<T>>; // Domain of the issuer -> Issuer

    #[pallet::storage]
    pub type JwksMap<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>, // Domain of the issuer
        BoundedVec<u8, T::MaxLengthIssuerJWKS>,   // JWKS
    >;

    #[pallet::storage]
    pub type JksProposals<T: Config> = CountedStorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>>, // Issuer Domain
            NMapKey<Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerJWKS>>,   // JWKS
            NMapKey<Blake2_128Concat, T::AccountId>,                             // AccountId
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
            if IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerAlreadyExists.into());
            }

            Self::validate_all(
                &domain,
                &open_id_url,
                &jwks,
                &update_interval,
                &auto_update,
                &status,
            )?;

            // Create the issuer
            let issuer = Issuer {
                open_id_url,
                update_interval,
                auto_update,
                status,
            };

            IssuerMap::<T>::insert(&domain, issuer);

            Self::deposit_event(Event::<T>::IssuerRegistered { who: who, domain });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::default())]
        pub fn update_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            update_interval: BlockNumberFor<T>,
            auto_update: bool,
            status: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the issuer

            Self::validate_all(
                &domain,
                &open_id_url,
                &jwks,
                &update_interval,
                &auto_update,
                &status,
            )?;

            // Create the issuer
            let issuer = Issuer {
                open_id_url,
                update_interval,
                auto_update,
                status,
            };

            // Update Issuer storage only if the issuer exists
            if IssuerMap::<T>::contains_key(&domain) {
                IssuerMap::<T>::insert(&domain, issuer);
            } else {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            Self::deposit_event(Event::<T>::IssuerUpdated { who, domain });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(Weight::default())]
        pub fn delete_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to delete the issuer

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Delete the issuer
            IssuerMap::<T>::remove(&domain);

            Self::deposit_event(Event::<T>::IssuerDeleted { who, domain });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::default())]
        pub fn set_update_interval(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            update_interval: BlockNumberFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to delete the issuer

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;
            Self::validate_update_interval(&update_interval)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the update interval
            IssuerMap::<T>::get(&domain).unwrap().update_interval = update_interval;

            Self::deposit_event(Event::<T>::IssuerUpdateIntervalUpdated {
                who,
                domain,
                update_interval,
            });

            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(Weight::default())]
        pub fn set_auto_update(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            auto_update: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the auto update

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the auto update
            IssuerMap::<T>::get(&domain).unwrap().auto_update = auto_update;

            Self::deposit_event(Event::<T>::IssuerAutoUpdateUpdated {
                who,
                domain,
                auto_update,
            });

            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(Weight::default())]
        pub fn set_status(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            status: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the status

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the status
            IssuerMap::<T>::get(&domain).unwrap().status = status;

            Self::deposit_event(Event::<T>::IssuerStatusUpdated {
                who,
                domain,
                status,
            });

            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(Weight::default())]
        pub fn set_open_id_url(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the open id url

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the open id url
            IssuerMap::<T>::get(&domain).unwrap().open_id_url = Some(open_id_url);

            Self::deposit_event(Event::<T>::IssuerOpenIdURLUpdated { who, domain });

            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(Weight::default())]
        pub fn propose_jwks(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to propose the jwks Validators only!!!

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Validate the jwks
            Self::validate_issuer_jwks(&Some(jwks.clone()))?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Check if the jwks is already proposed
            let jwks = jwks.clone();
            if JksProposals::<T>::contains_key((domain.clone(), jwks.clone(), who.clone())) {
                return Err(Error::<T>::AlreadyVotedForJWKS.into());
            }

            // Propose the jwks
            JksProposals::<T>::insert((domain.clone(), jwks.clone(), who.clone()), ());

            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(Weight::default())]
        pub fn set_jwks(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?; // ToDo: Check if the who has rights to update the jwks

            // Validate the issuer domain
            Self::validate_issuer_domain(&domain)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            let most_voted_jwks = Self::get_jwks_with_higher_count(&domain);

            // Insert the most voted jwks in the JksMap
            JwksMap::<T>::insert(&domain, most_voted_jwks);

            Self::deposit_event(Event::<T>::IssuerJWKSUpdated { who, domain });

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_n: BlockNumberFor<T>) {
            // Set the jwks in the JksMap
            // Self::set_jwks();

            // Clear all JWKS proposals
            // JksProposals::<T>::clear();

            info!("Cleaning all JWKS proposals");
        }

        // // Here comes the offchain worker for getting the jwks from internet
        // fn on_initialize(n: BlockNumberFor<T>) {
        //     info!("Initializing the offchain worker for getting the jwks from internet");
        //     // Iterate on all the registered issuers
        //     for issuer in IssuerMap::<T>::iter() {
        //         let jskw_url;
        //         // Get the open id url
        //         let open_id_url = Self::get_open_id_url(&issuer.name);
        //         if let Some(open_id_url) = open_id_url {
        //             if let Some(jwks_url) = jwks_url {
        //                 // Get the jwks from the internet
        //                 // let jwks = Self::get_jwks_from_internet(jwks_url);
        //             }
        //         } else {
        //             jskw_url = Self::get_jwks_url(&issuer.name);
        //             if let Some(jwks_url) = jwks_url {
        //                 // Get the jwks from the internet
        //                 // let jwks = Self::get_jwks_from_internet(jwks_url);
        //             } else {
        //                 info!("No jwks url found for issuer {:?}", issuer.name);
        //                 continue; // Continue to the next issuer, JWKS is not provided and can not get fetched from internet
        //             }
        //         }
        //         // Store the jwks in the proposal storage(JksProposals)
        //         // JksProposals::<T>::insert((issuer.name, jwks_url, who), ());

        //     }
        // }
    }
}

impl<T: Config> Pallet<T> {
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
        domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
        open_id_url: &Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        jwks: &Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
        update_interval: &BlockNumberFor<T>,
        _auto_update: &bool,
        _status: &bool,
    ) -> DispatchResult {
        Self::validate_issuer_domain(domain)?;
        Self::validate_issuer_open_id_url_or_jwks(open_id_url, jwks)?;
        Self::validate_update_interval(update_interval)?;
        Ok(())
    }

    pub fn count_accounts_for_issuer_jwks(
        issuer_domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        issuer_jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
    ) -> u32 {
        let prefix = (issuer_domain, issuer_jwks);

        let count = JksProposals::<T>::iter_prefix(prefix).count();

        count as u32
    }

    pub fn get_jwks_with_higher_count(
        issuer_domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
    ) -> BoundedVec<u8, T::MaxLengthIssuerJWKS> {
        info!("get_jwks_with_higher_count for {:?}", issuer_domain);
        // Create empty jwks
        let jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS> = BoundedVec::new();

        jwks
    }

    // Here comes the function to get the jwks url from Issuer
    pub fn get_jwks_url(
        domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
    ) -> Option<BoundedVec<u8, <T as Config>::MaxLengthIssuerJWKS>> {
        // Get the issuer from the storage JwksMap
        let jwks = JwksMap::<T>::get(domain);
        // Return the jwks url
        if let Some(jwks) = jwks {
            Some(jwks)
        } else {
            None
        }
    }

    // Here comes the function to get the open id url from the Issuer
    pub fn get_open_id_url(
        domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
    ) -> Option<BoundedVec<u8, <T as Config>::MaxLengthIssuerOpenIdURL>> {
        // Get the issuer from the storage
        let issuer = IssuerMap::<T>::get(domain);
        // Return the open id url
        if let Some(issuer) = issuer {
            issuer.open_id_url
        } else {
            None
        }
    }
}
