#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use frame_support::{BoundedVec, dispatch::DispatchResult, ensure, traits::Get};
use frame_system::offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer};
use frame_system::pallet_prelude::*;
use log::info;
use miniserde::json;
pub use pallet::*;
// use sp_application_crypto::{AppPublic, AppSignature};
use sp_runtime::offchain::{Duration, http};
use sp_runtime::traits::AtLeast32BitUnsigned;

pub mod types;
use types::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame::pallet]
pub mod pallet {
    use super::*;
    use frame::{prelude::*, traits::ValidatorSet};
    use frame_support::Blake2_128Concat;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // Configs

    #[pallet::config]
    pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
        // Defines the event type for the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The type to be used for cryptographic signature related to off-chain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        type RegisterOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

        type UpdaterOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>; // It's a recommended idea to be able to accomplish this root/governance

        type ProposerOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>; // ToDo: Create a new origin for proposers handled from runtime

        type BlockNumber: From<u32> + Into<u32> + AtLeast32BitUnsigned + Copy + MaxEncodedLen;

        type Validators: ValidatorSet<Self::AccountId, ValidatorId = Self::AccountId>;

        #[pallet::constant]
        type MaxLengthIssuerDomain: Get<u32>;

        #[pallet::constant]
        type MaxLengthIssuerURL: Get<u32>;

        #[pallet::constant]
        type MaxLengthIssuerJWKS: Get<u32>;

        #[pallet::constant]
        type MinUpdateInterval: Get<u32>;

        #[pallet::constant]
        type MaxUpdateInterval: Get<u32>;

        #[pallet::constant]
        type MaxProposersPerIssuer: Get<u32>;

        #[pallet::constant]
        type MinimalConsensusPercentage: Get<u32>;

        /// The caller origin, overarching type of all pallets origins.
        type JwtOrigin: From<frame_system::Origin<Self>>;

        // Pending to define if use this to freeze/
        type NativeBalance: fungible::Inspect<Self::AccountId>
            + fungible::Mutate<Self::AccountId>
            + fungible::hold::Inspect<Self::AccountId>
            + fungible::hold::Mutate<Self::AccountId>
            + fungible::freeze::Inspect<Self::AccountId, Id = ()>
            + fungible::freeze::Mutate<Self::AccountId>
            + fungible::MutateFreeze<Self::AccountId>;
    }
    // Structs
    #[derive(Clone, Debug, PartialEq, TypeInfo, Encode, Decode, MaxEncodedLen, Default)]
    #[scale_info(skip_type_params(T))]
    pub struct Issuer<T: Config> {
        // Issuer OpenID URL, like "https://accounts.google.com/.well-known/openid-configuration", "https://account.apple.com/.well-known/openid-configuration", etc.
        pub url: BoundedVec<u8, T::MaxLengthIssuerURL>,
        // URL type:
        pub url_type: UrlType,
        // How many blocks to wait before the issuer can be updated
        pub interval_update: Option<u32>, // None means no auto update.
        // Issuer is active or not for validating JWT
        pub is_enabled: bool,
        // // Initial JWKS value -> ToDo: check if this is a good idea
        // pub initial_jwks_value: BoundedVec<u8,T::MaxLengthIssuerJWKS>
    }

    // Events

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

        IssuerEnabledUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new status.
            is_enabled: bool,
        },

        IssuerAutoUpdateUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new auto update status.
            auto_update: bool,
        },

        IssuerIntervalUpdateUpdated {
            /// The account who updated the issuer.
            who: T::AccountId,
            /// The issuer domain.
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            /// The new update interval.
            interval_update: Option<u32>,
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

    // Storages
    // Non volatile storage after time: IssuerMap, IssuerCreator, JwksMap

    // Store an alias to a an Issuer Struct, eg: Google->Issuer{...}
    #[pallet::storage]
    #[pallet::getter(fn get_issuer_map)]
    pub type IssuerMap<T: Config> =
        StorageMap<_, Twox64Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, Issuer<T>>; // Domain of the issuer -> Issuer struct

    // Store IssuerCreator to the alias, eg: Google->Alice
    #[pallet::storage]
    #[pallet::getter(fn get_issuer_creator)]
    pub type IssuerCreator<T: Config> =
        StorageMap<_, Twox64Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, T::AccountId>; // Domain of the issuer -> Issuer struct

    // Store the JWKS file of an alias, eg: Google->{"keys":[...]}
    #[pallet::storage]
    #[pallet::getter(fn get_jwks_map)]
    pub type JwksMap<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>, // Domain of the issuer
        BoundedVec<u8, T::MaxLengthIssuerJWKS>,   // JWKS
    >;

    // Volatile storage after some time(blocks):
    //    - DomainAccsVec
    //    - JwksHash
    //    - CounterProposedJwksHash
    //    - CounterIntervalUpdateIssuer
    //    - DomainAccJwksHash

    // Store which accounts have proposed a jwks for an issuer alias, eg: Google -> Vec[Alice, Bob, Charlie]
    #[pallet::storage]
    #[pallet::getter(fn get_domain_accs_vec)]
    pub type DomainAccsVec<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        BoundedVec<T::AccountId, T::MaxProposersPerIssuer>,
    >; // Domain of the issuer => List of accounts that proposed the jwks

    // Store a double map of: Domain->H256(JWKS)->JWKS
    #[pallet::storage]
    #[pallet::getter(fn get_jwks_hash)]
    pub type JwksHash<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        Blake2_128Concat,
        H256,
        BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        OptionQuery,
    >;

    // Store a double map for couting the proposed times of a JWKS. Domain => H(JWKS) => Counter
    #[pallet::storage]
    #[pallet::getter(fn get_counter_proposed_jwks_hash)]
    pub type CounterProposedJwksHash<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        Blake2_128Concat,
        H256,
        u32,
        OptionQuery,
    >;

    // Store the block counter for triggering the JWKS fetch.
    // This is a cyclic count down from n to 0.
    #[pallet::storage]
    #[pallet::getter(fn get_counter_interval_update_issuer)]
    pub type CounterIntervalUpdateIssuer<T: Config> =
        StorageMap<_, Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, u32, ValueQuery>;

    // Store the proposed Jwks (its hash) by an AccountId for an issuer domain.
    // IssuerDomain => AccountId => Jwks
    #[pallet::storage]
    #[pallet::getter(fn get_domain_acc_jwks_hash)]
    pub type DomainAccJwksHash<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        Blake2_128Concat,
        T::AccountId,
        H256,
        OptionQuery,
    >;

    // Errors

    #[pallet::error]
    pub enum Error<T> {
        // Issuer errors
        IssuerAlreadyExists,
        IssuerDomainTooLong,
        IssuerJWKSTooLong,
        IssuerOpenIdURLTooLong,
        IssuerDoesNotExist,
        IssuerUpdateIntervalAboveMax,
        IssuerUpdateIntervalNotMultipleOfBlock,
        IssuerOpenIdURLOrJWKSNotProvided,
        OnlyGovernanceCanUpdateIssuer,
        OnlyGovernanceCanDeleteIssuer,
        InvalidJson,
        JsonTooLong,
        AlreadyProposedForJWKS,
        OnlyValidatorsCanProposeJWKS,
        DomainNotRegistered,
        MaxProposersPerIssuerExceeded,
        NoValidators,
        DuplicateJWKSProposal,
    }

    // Calls

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // Register a new issuer
        // The dispatch origin of this call must be _any AccountId_.
        // The issuer name, domain, url and jwks are validated against the corresponding max length.
        // The issuer is registered in the storage map.
        // The event IssuerRegistered is emitted.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::default())] // -> #[pallet::weight(<T as Config>::WeightInfo::register_issuer())]
        pub fn register_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            url: BoundedVec<u8, T::MaxLengthIssuerURL>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            url_type: UrlType,
            mut interval_update: Option<u32>,
            // is_enabled: bool,
        ) -> DispatchResult {
            let who = T::RegisterOrigin::ensure_origin(origin)?;

            // ── 1. mutate-or-fail in a single storage access ───────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |slot| -> DispatchResult {
                // Check if already exist the ID
                ensure!(slot.is_none(), Error::<T>::IssuerAlreadyExists);

                Self::validate_interval_update(&mut interval_update);

                // insert the freshly built Issuer
                *slot = Some(Issuer {
                    url: url.clone(),
                    interval_update,
                    is_enabled: true, // is_enabled by default is true
                    url_type: url_type.clone(),
                });

                Ok(())
            })?;

            // ── 2. secondary tables (JWKS, counter)  ───────────────────────────────
            if let Some(mut jwks) = jwks {
                // Check if the jwks is valid
                Self::validate_json(&mut jwks)?;
                JwksMap::<T>::insert(&domain, jwks);
            }

            // Store the account who created the domain  // ToDo: Needed?
            IssuerCreator::<T>::insert(&domain, who.clone());

            // Set CounterIntervalUpdateIssuer storage
            CounterIntervalUpdateIssuer::<T>::try_mutate_exists(
                &domain,
                |slot| -> DispatchResult {
                    ensure!(slot.is_none(), Error::<T>::IssuerAlreadyExists);

                    let interval_value = match interval_update {
                        Some(value) => value,
                        None => 0,
                    };

                    *slot = Some(interval_value);
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::<T>::IssuerRegistered { who, domain });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::update_issuer())] // use real benchmarked weight
        pub fn update_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            url: BoundedVec<u8, T::MaxLengthIssuerURL>,
            url_type: UrlType,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            mut interval_update: Option<u32>,
            is_enabled: bool,
        ) -> DispatchResult {
            let who = T::UpdaterOrigin::ensure_origin(origin)?;

            //----------------------------------------------------------------------
            // 1. update the Issuer entry in ONE storage access
            //----------------------------------------------------------------------
            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                // a) bail out if the issuer does not exist
                let issuer = maybe_issuer
                    .as_mut()
                    .ok_or(Error::<T>::IssuerDoesNotExist)?;

                // b) run field-level validation
                Self::validate_interval_update(&mut interval_update);

                // c) overwrite the fields (your semantics: "replace, even with None")
                issuer.url = url.clone();
                issuer.interval_update = interval_update;
                issuer.is_enabled = is_enabled;
                issuer.url_type = url_type;

                Ok(())
            })?;

            //----------------------------------------------------------------------
            // 2. synchronise JWKS table
            //----------------------------------------------------------------------
            match jwks {
                Some(mut new_jwks) => {
                    Self::validate_json(&mut new_jwks)?;
                    JwksMap::<T>::insert(&domain, new_jwks)
                }
                None => JwksMap::<T>::remove(&domain),
            }

            //----------------------------------------------------------------------
            // 3. CounterIntervalUpdateIssuer storage
            //----------------------------------------------------------------------
            CounterIntervalUpdateIssuer::<T>::try_mutate_exists(
                &domain,
                |maybe_slot| -> DispatchResult {
                    let interval_value = match interval_update {
                        Some(value) => value,
                        None => 0,
                    };

                    *maybe_slot = Some(interval_value);
                    Ok(())
                },
            )?;

            //----------------------------------------------------------------------
            // 4. emit the event
            //----------------------------------------------------------------------
            Self::deposit_event(Event::<T>::IssuerUpdated { who, domain });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::delete_issuer())]
        pub fn delete_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        ) -> DispatchResult {
            let who = T::UpdaterOrigin::ensure_origin(origin)?;

            // ── 1. remove from IssuerMap in one storage access ────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                ensure!(maybe_issuer.is_some(), Error::<T>::IssuerDoesNotExist);
                *maybe_issuer = None; // delete the key
                Ok(())
            })?;

            // ── 2. clean up auxiliary tables (they may or may not be present) ─────
            IssuerCreator::<T>::remove(&domain);
            JwksMap::<T>::remove(&domain);

            // ── 3. emit an event ──────────────────────────────────────────────────
            Self::deposit_event(Event::<T>::IssuerDeleted { who, domain });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_update_interval())]
        pub fn set_interval_update(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            mut interval_update: Option<u32>,
        ) -> DispatchResult {
            let who = T::UpdaterOrigin::ensure_origin(origin)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                // a) bail out if the issuer does not exist
                let issuer = maybe_issuer
                    .as_mut()
                    .ok_or(Error::<T>::IssuerDoesNotExist)?;

                // b) run field-level validation
                Self::validate_interval_update(&mut interval_update);

                // c) overwrite the interval update
                issuer.interval_update = interval_update;
                Ok(())
            })?;

            CounterIntervalUpdateIssuer::<T>::try_mutate_exists(
                &domain,
                |maybe_slot| -> DispatchResult {
                    // Already validated interval update, not needed to be done again

                    let interval_value = match interval_update {
                        Some(value) => value,
                        None => 0,
                    };

                    *maybe_slot = Some(interval_value);
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::<T>::IssuerIntervalUpdateUpdated {
                who,
                domain,
                interval_update,
            });

            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_enabled())]          // benchmarked weight
        pub fn set_enabled(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            is_enabled: bool,
        ) -> DispatchResult {
            let who = T::UpdaterOrigin::ensure_origin(origin)?;

            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                // fail if the domain is unknown
                let issuer = maybe_issuer
                    .as_mut()
                    .ok_or(Error::<T>::IssuerDoesNotExist)?;

                // optional micro-optimisation: return early if no change
                if issuer.is_enabled == is_enabled {
                    return Ok(());
                }

                issuer.is_enabled = is_enabled;
                Ok(())
            })?;

            // ── 2. emit the event ────────────────────────────────────────────────
            Self::deposit_event(Event::<T>::IssuerEnabledUpdated {
                who,
                domain,
                is_enabled,
            });

            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_open_id_url())]
        pub fn set_url(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            url: BoundedVec<u8, T::MaxLengthIssuerURL>,
        ) -> DispatchResult {
            let who = T::UpdaterOrigin::ensure_origin(origin)?;

            // ── 2. mutate the issuer entry atomically ────────────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                // bail out if the issuer is unknown
                let issuer = maybe_issuer
                    .as_mut()
                    .ok_or(Error::<T>::IssuerDoesNotExist)?;

                // micro-optimisation: no change, no write, no event
                if issuer.url == url {
                    return Ok(());
                }

                issuer.url = url.clone();
                Ok(())
            })?; // any error (e.g. DoesNotExist) bubbles up

            // ── 3. emit the event ────────────────────────────────────────────────
            Self::deposit_event(Event::<T>::IssuerOpenIdURLUpdated { who, domain });

            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::propose_jwks())]   // replace with Weight::default() until you benchmark
        pub fn propose_jwks(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            mut jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        ) -> DispatchResult {
            //------------------------------------------------------------------
            // 0. origin – only validators should be allowed to call this
            //------------------------------------------------------------------
            let who = T::ProposerOrigin::ensure_origin(origin)?;

            //------------------------------------------------------------------
            // 1. the issuer must exist
            //------------------------------------------------------------------
            ensure!(
                IssuerMap::<T>::contains_key(&domain),
                Error::<T>::IssuerDoesNotExist
            );

            //------------------------------------------------------------------
            // 2. hash the JWKS document so we can deduplicate storage
            //------------------------------------------------------------------
            Self::validate_json(&mut jwks)?;
            let jwks_hash = H256::from(blake2_256(jwks.as_slice()));

            //------------------------------------------------------------------
            // 3. record that THIS validator has already proposed for THIS domain
            //------------------------------------------------------------------
            let mut acc_already_proposed = false;
            DomainAccsVec::<T>::try_mutate(&domain, |opt_vec| -> DispatchResult {
                // lazily create an empty bounded‐vec when the first proposal arrives
                let vec = opt_vec.get_or_insert_with(
                    BoundedVec::<T::AccountId, T::MaxProposersPerIssuer>::default,
                );

                if !vec.contains(&who) {
                    vec.try_push(who.clone())
                        .map_err(|_| Error::<T>::MaxProposersPerIssuerExceeded)?;
                } else {
                    acc_already_proposed = true;
                }

                Ok(())
            })?;

            if acc_already_proposed {
                // Get the previous hash for this validator and domain
                if let Some(prev_hash) = DomainAccJwksHash::<T>::get(&domain, &who) {
                    if prev_hash == jwks_hash {
                        return Err(Error::<T>::DuplicateJWKSProposal.into());
                    }

                    // Decrease the counter for the previous hash
                    CounterProposedJwksHash::<T>::mutate(&domain, prev_hash, |count| {
                        if let Some(c) = count.as_mut() {
                            if *c > 0 {
                                *c = c.saturating_sub(1);
                            }
                        }
                    });

                    // If counter reaches zero, remove the hash from storage
                    if let Some(0) = CounterProposedJwksHash::<T>::get(&domain, prev_hash) {
                        CounterProposedJwksHash::<T>::remove(&domain, prev_hash);
                        JwksHash::<T>::remove(&domain, prev_hash);
                    }
                }
            }

            // Update the hash for this validator and domain
            DomainAccJwksHash::<T>::insert(&domain, who.clone(), jwks_hash);

            //------------------------------------------------------------------
            // 4. store the JWKS bytes if we haven't seen this hash before
            //------------------------------------------------------------------
            JwksHash::<T>::try_mutate(&domain, jwks_hash, |slot| -> DispatchResult {
                if slot.is_none() {
                    *slot = Some(jwks.clone());
                }
                Ok(())
            })?;

            //------------------------------------------------------------------
            // 5. bump the (domain, hash) counter atomically
            //------------------------------------------------------------------
            CounterProposedJwksHash::<T>::mutate(&domain, jwks_hash, |count| {
                if let Some(c) = count.as_mut() {
                    *c = c.saturating_add(1);
                } else {
                    *count = Some(1);
                }
            });

            //------------------------------------------------------------------
            // 6. emit an event
            //------------------------------------------------------------------
            Self::deposit_event(Event::<T>::IssuerJWKSUpdated { who, domain });

            Ok(())
        }

        // This should be called only by governance
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_jwks())]   // replace with Weight::default() until you benchmark
        pub fn set_jwks(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            mut jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        ) -> DispatchResult {
            //------------------------------------------------------------------
            // 0. origin.
            //------------------------------------------------------------------
            let who = T::UpdaterOrigin::ensure_origin(origin)?; // ToDo: Signed by sudo/governance?

            //------------------------------------------------------------------
            // 1. the issuer must exist
            //------------------------------------------------------------------
            ensure!(
                IssuerMap::<T>::contains_key(&domain),
                Error::<T>::IssuerDoesNotExist
            );

            //------------------------------------------------------------------
            // 2. Validate JWKS
            //------------------------------------------------------------------
            Self::validate_json(&mut jwks)?;

            //------------------------------------------------------------------
            // 3. write to JwksMap only if it changed
            //------------------------------------------------------------------
            let mut changed: bool = false;
            JwksMap::<T>::try_mutate(&domain, |slot| -> DispatchResult {
                if slot.as_ref() == Some(&jwks) {
                    // No change, skip write & later event
                    return Ok(());
                }
                *slot = Some(jwks.clone());
                changed = true;
                Ok(())
            })?;

            //------------------------------------------------------------------
            // 4. emit event only when we actually updated the JWKS
            //------------------------------------------------------------------
            if changed {
                Self::deposit_event(Event::<T>::IssuerJWKSUpdated { who, domain });
            }

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_n: BlockNumberFor<T>) {
            info!("Cleaning all JWKS proposals");
            // For each issuer in IssuerMap
            for (domain, issuer) in IssuerMap::<T>::iter() {
                // Get the current counter for this issuer
                CounterIntervalUpdateIssuer::<T>::mutate(&domain, |counter| {
                    if *counter > 0 {
                        // Decrease by 1 if greater than 0
                        *counter -= 1;
                    } else {
                        // If counter is 0, reset to interval_update (if set)
                        if let Some(interval) = issuer.interval_update {
                            *counter = interval;
                        }

                        // Only proceed if counter was zero (i.e., time to process)
                        // Check if DomainAccsVec count >= MinimalConsensusPercentage
                        let min_consensus = T::MinimalConsensusPercentage::get();
                        if let Some(accs_vec) = DomainAccsVec::<T>::get(&domain) {
                            if accs_vec.len() as u32 >= min_consensus {
                                // Find the Hash with the greatest value in CounterProposedJwksHash
                                let mut max_count = 0u32;
                                let mut selected_hash = None;
                                for (hash, count) in
                                    CounterProposedJwksHash::<T>::iter_prefix(&domain)
                                {
                                    if count > max_count {
                                        max_count = count;
                                        selected_hash = Some(hash);
                                    }
                                }

                                if let Some(hash) = selected_hash {
                                    // Copy the value for that Hash in JwksHash into JwksMap
                                    if let Some(jwks) = JwksHash::<T>::get(&domain, &hash) {
                                        // Overwrite JwksMap for this domain
                                        let _ = JwksMap::<T>::insert(&domain, jwks);
                                    }
                                }

                                // Clear the storage for the issuer in the relevant storages
                                let _ = DomainAccsVec::<T>::remove(&domain);
                                let _ = JwksHash::<T>::clear_prefix(&domain, u32::MAX, None);
                                let _ = CounterProposedJwksHash::<T>::clear_prefix(
                                    &domain,
                                    u32::MAX,
                                    None,
                                );
                                let _ =
                                    DomainAccJwksHash::<T>::clear_prefix(&domain, u32::MAX, None);
                            }
                        }
                    }
                });
            }
        }

        fn offchain_worker(n: BlockNumberFor<T>) {
            info!("Running offchain worker at block {}", n);

            // Check if not proposed yet for this domain
            // let validators = T::Validators::validators();

            // Get validator account from keystore
            let signer = Signer::<T, T::AuthorityId>::any_account();

            // Iterate on all the registered issuers
            for issuer in IssuerMap::<T>::iter() {
                // Check if issuer is disabled
                if !issuer.1.is_enabled || issuer.1.interval_update.is_none() {
                    continue;
                }

                // Process this issuer
                let url = &issuer.1.url;
                let url_type = &issuer.1.url_type;

                if let Ok(url_str) = sp_std::str::from_utf8(url.as_slice()) {
                    if let Err(e) =
                        Self::fetch_and_propose_jwks(&signer, url_str, &issuer.0, url_type.clone())
                    {
                        log::error!("Failed to fetch JWKS for {}: {:?}", url_str, e);
                    }
                }

                // Increase number if processed
                CounterIntervalUpdateIssuer::<T>::mutate(&issuer.0, |counter| {
                    *counter = (*counter + 1) % issuer.1.interval_update.unwrap();
                });
            }
        }

        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            Weight::default()
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn validate_json<Len>(json_buf: &mut BoundedVec<u8, Len>) -> DispatchResult
    where
        Len: Get<u32>,
    {
        // Parse JSON (keys will be sorted automatically)

        // Parsing
        let value: serde_json::Value =
            serde_json::from_slice(json_buf.as_slice()).map_err(|_| Error::<T>::InvalidJson)?;

        // Serialize in compact/sorted form
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::<T>::InvalidJson)?;

        // Check length
        ensure!(bytes.len() <= Len::get() as usize, Error::<T>::JsonTooLong);

        // Save the buffer
        *json_buf = BoundedVec::<u8, Len>::try_from(bytes).map_err(|_| Error::<T>::JsonTooLong)?;

        Ok(())
    }

    pub fn validate_interval_update(interval_update: &mut Option<u32>) {
        let lower = T::MinUpdateInterval::get();
        let upper = T::MaxUpdateInterval::get();

        if let Some(v) = interval_update {
            // If the value is zero, set to None
            if *v == 0 {
                *interval_update = None;
            } else {
                // First raise the value to the lower bound,
                // then cut it down to the upper bound.
                *v = (*v).max(lower).min(upper);
            }
        }
    }

    /// Returns a vector of all registered issuer domains. -> ["Google", "Apple", "Facebook"]
    pub fn get_issuers_vec() -> Vec<BoundedVec<u8, T::MaxLengthIssuerDomain>> {
        // Iterate over all issuers in the storage and collect their domains
        IssuerMap::<T>::iter_keys().collect()
    }

    /// Return the JWKS document that has the highest proposal count for
    /// the given issuer domain.  
    /// If the issuer has no JWKS proposals yet, this returns an *empty*
    /// `BoundedVec`, which the caller can interpret as "no winner".
    pub fn get_jwks_with_higher_count(
        issuer_domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
    ) -> BoundedVec<u8, T::MaxLengthIssuerJWKS> {
        use frame::hashing::H256;

        // 1. Walk over all (hash, counter) pairs under `issuer_domain`
        let mut best: Option<(H256, u32)> = None;
        for (hash, counter) in CounterProposedJwksHash::<T>::iter_prefix(issuer_domain) {
            match best {
                // keep the hash with the strictly highest counter
                Some((_, best_cnt)) if counter <= best_cnt => {}
                _ => best = Some((hash, counter)), // If the counter is higher, update the best
            }
        }

        // 2. Resolve the winning hash back to raw JWKS bytes
        if let Some((winning_hash, _)) = best {
            if let Some(jwks) = JwksHash::<T>::get(issuer_domain, winning_hash) {
                return jwks; // ← success path
            }
        }

        // 3. Otherwise return an empty bounded vector
        BoundedVec::<u8, T::MaxLengthIssuerJWKS>::default()
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

    fn fetch_and_propose_jwks(
        // ToDo: optimize memory usage -> avoid clones and json Value usages.
        signer: &Signer<T, T::AuthorityId>,
        url: &str,
        domain: &BoundedVec<u8, T::MaxLengthIssuerDomain>,
        url_type: UrlType,
    ) -> Result<(), http::Error> {
        let jwks_uri = match url_type {
            UrlType::OPENID => {
                // Fetch OpenID configuration
                let openid_config = Self::fetch_openid_json(url)?;

                // Extract jwks_uri from OpenID configuration
                openid_config.jwks_uri
            }
            UrlType::JWKS => {
                // Directly fetch JWKS from the provided URL
                url.to_string()
            }
        };

        // 3. Fetch JWKS from jwks_uri
        let jwks = Self::fetch_jwks_json(&jwks_uri)?;

        let jwks_bytes = json::to_string(&jwks).into_bytes();
        let jwks_bound_vec = BoundedVec::<u8, T::MaxLengthIssuerJWKS>::try_from(jwks_bytes)
            .map_err(|_| http::Error::Unknown)?;

        // ToDo: Search the H256(jwks) for the signer to check if already proposed this recently
        // ToDo: Store in local storage the jwks proposed to avoid propose already proposed values.

        // 4. Propose the JWKS
        // Send extrinsic to propose_jwks using the validator account
        let _results = signer.send_signed_transaction(move |_account| Call::propose_jwks {
            domain: domain.clone(),
            jwks: jwks_bound_vec.clone(),
        });

        Ok(())
    }

    /// Make HTTP request with optimized error handling
    fn make_http_request(url: &str) -> Result<String, http::Error> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000)); // ToDo: Think about this hardcoded value
        let request = http::Request::get(url);

        let pending = request
            .deadline(deadline)
            .send()
            .map_err(|_| http::Error::IoError)?;

        let response = pending
            .try_wait(deadline)
            .map_err(|_| http::Error::DeadlineReached)??;
        if response.code != 200 {
            log::warn!("Unexpected status code: {}", response.code);
            return Err(http::Error::Unknown);
        }

        // Next we want to fully read the response body and collect it to a vector of bytes.
        // Note that the return object allows you to read the body in chunks as well
        // with a way to control the deadline.
        let body = response.body().collect::<Vec<u8>>();

        // Create a str slice from the body.
        let body_str = alloc::str::from_utf8(&body).map_err(|_| {
            log::warn!("No UTF8 body");
            http::Error::Unknown
        })?;
        // Collect response body efficiently
        Ok(body_str.to_owned())
    }

    fn fetch_openid_json(url: &str) -> Result<OpenIdConfig, http::Error> {
        let response_data = Self::make_http_request(url)?;
        json::from_str(&response_data).map_err(|_| http::Error::Unknown)
    }

    fn fetch_jwks_json(url: &str) -> Result<Jwks, http::Error> {
        let response_data = Self::make_http_request(url)?;
        json::from_str(&response_data).map_err(|_| http::Error::Unknown)
    }
}
