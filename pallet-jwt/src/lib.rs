#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{BoundedVec, dispatch::DispatchResult, ensure, traits::Get};
use frame_system::pallet_prelude::*;
use log::info;
pub use pallet::*;
use sp_runtime::traits::AtLeast32BitUnsigned;

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
    pub trait Config: frame_system::Config {
        // Defines the event type for the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type RegisterOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

        type BlockNumber: From<u32> + Into<u32> + AtLeast32BitUnsigned + Copy + MaxEncodedLen;

        type Validators: ValidatorSet<Self::AccountId, ValidatorId = Self::AccountId>;

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

        #[pallet::constant]
        type MaxProposersPerIssuer: Get<u32>;

        /// The caller origin, overarching type of all pallets origins.
        type JwtOrigin: From<frame_system::Origin<Self>>;
    }

    // Structs
    #[derive(Clone, Debug, PartialEq, TypeInfo, Encode, Decode, MaxEncodedLen, Default)]
    #[scale_info(skip_type_params(T))]
    pub struct Issuer<T: Config> {
        // Issuer OpenID URL, like "https://accounts.google.com/.well-known/openid-configuration", "https://account.apple.com/.well-known/openid-configuration", etc.
        pub open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
        // How many blocks to wait before the issuer can be updated
        pub interval_update: Option<u32>, // None means no auto update.
        // Issuer is active or not for validating JWT
        pub is_enabled: bool,
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

    #[pallet::storage]
    pub type IssuerMap<T: Config> =
        StorageMap<_, Twox64Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, Issuer<T>>; // Domain of the issuer -> Issuer struct

    #[pallet::storage]
    pub type JwksMap<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>, // Domain of the issuer
        BoundedVec<u8, T::MaxLengthIssuerJWKS>,   // JWKS
    >;

    #[pallet::storage]
    pub type AccountsProposedForIssuer<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        BoundedVec<T::AccountId, T::MaxProposersPerIssuer>,
    >; // Domain of the issuer => List of accounts that proposed the jwks

    // Hash of the jwks => JWKS. JWKS can be reused! Saving a lot of space.
    #[pallet::storage]
    pub type JwksHash<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, BoundedVec<u8, T::MaxLengthIssuerJWKS>>;

    // IssuerDomain => Hash of the jwks proposed => Counter
    #[pallet::storage]
    pub type CounterProposedJwksHash<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxLengthIssuerDomain>,
        Blake2_128Concat,
        H256,
        u32,
        ValueQuery,
    >;

    // StorageMap for the interval update counter of each issuer
    #[pallet::storage]
    pub type CounterIntervalUpdateIssuer<T: Config> =
        StorageMap<_, Blake2_128Concat, BoundedVec<u8, T::MaxLengthIssuerDomain>, u32, ValueQuery>;

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
    }

    // Calls

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // Register a new issuer
        // The dispatch origin of this call must be _any AccountId_.
        // The issuer name, domain, open_id_url and jwks are validated against the corresponding max length.
        // The issuer is registered in the storage map.
        // The event IssuerRegistered is emitted.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::default())] // -> #[pallet::weight(<T as Config>::WeightInfo::register_issuer())]
        pub fn register_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            mut interval_update: Option<u32>,
            // is_enabled: bool,
        ) -> DispatchResult {
            let who = T::RegisterOrigin::ensure_origin(origin)?;

            // ── 1. mutate-or-fail in a single storage access ───────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |slot| -> DispatchResult {
                // duplicate?
                ensure!(slot.is_none(), Error::<T>::IssuerAlreadyExists);

                Self::validate_interval_update(&mut interval_update);

                // insert the freshly built Issuer
                *slot = Some(Issuer {
                    open_id_url: open_id_url.clone(), // we’ll need the originals later
                    interval_update,
                    is_enabled: true, // is_enabled by default is true
                });

                Ok(())
            })?; // <- propagate any error from the closure

            // ── 2. secondary tables (JWKS, counter)  ───────────────────────────────
            if let Some(mut jwks) = jwks {
                // Check if the jwks is valid
                Self::validate_json(&mut jwks)?;
                JwksMap::<T>::insert(&domain, jwks);
            }

            Self::deposit_event(Event::<T>::IssuerRegistered { who, domain });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::update_issuer())] // use real benchmarked weight
        pub fn update_issuer(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: Option<BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>>,
            jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>>,
            mut interval_update: Option<u32>,
            is_enabled: bool,
        ) -> DispatchResult {
            let who = T::RegisterOrigin::ensure_origin(origin)?;

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

                // c) overwrite the fields (your semantics: “replace, even with None”)
                issuer.open_id_url = open_id_url.clone();
                issuer.interval_update = interval_update;
                issuer.is_enabled = is_enabled;

                Ok(())
            })?;

            //----------------------------------------------------------------------
            // 2. synchronise JWKS table
            //----------------------------------------------------------------------
            match jwks {
                Some(new_jwks) => JwksMap::<T>::insert(&domain, new_jwks),
                None => JwksMap::<T>::remove(&domain),
            }

            //----------------------------------------------------------------------
            // 3. emit the event
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
            let who = T::RegisterOrigin::ensure_origin(origin)?;

            // ── 1. remove from IssuerMap in one storage access ────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                ensure!(maybe_issuer.is_some(), Error::<T>::IssuerDoesNotExist);
                *maybe_issuer = None; // delete the key
                Ok(())
            })?; // ← propagates the “does not exist” error

            // ── 2. clean up auxiliary tables (they may or may not be present) ─────
            JwksMap::<T>::remove(&domain);
            CounterIntervalUpdateIssuer::<T>::remove(&domain);

            // ── 3. emit an event ──────────────────────────────────────────────────
            Self::deposit_event(Event::<T>::IssuerDeleted { who, domain });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_update_interval())]
        pub fn set_update_interval(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            mut interval_update: Option<u32>,
        ) -> DispatchResult {
            let who = T::RegisterOrigin::ensure_origin(origin)?;

            // Check if the issuer exists
            if !IssuerMap::<T>::contains_key(&domain) {
                return Err(Error::<T>::IssuerDoesNotExist.into());
            }

            // Update the update interval
            IssuerMap::<T>::get(&domain).unwrap().interval_update = interval_update;

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
            let who = T::RegisterOrigin::ensure_origin(origin)?;

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
        pub fn set_open_id_url(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
            open_id_url: BoundedVec<u8, T::MaxLengthIssuerOpenIdURL>,
        ) -> DispatchResult {
            let who = T::RegisterOrigin::ensure_origin(origin)?;

            // ── 2. mutate the issuer entry atomically ────────────────────────────
            IssuerMap::<T>::try_mutate_exists(&domain, |maybe_issuer| -> DispatchResult {
                // bail out if the issuer is unknown
                let issuer = maybe_issuer
                    .as_mut()
                    .ok_or(Error::<T>::IssuerDoesNotExist)?;

                // micro-optimisation: no change, no write, no event
                if issuer.open_id_url.as_ref() == Some(&open_id_url) {
                    return Ok(());
                }

                issuer.open_id_url = Some(open_id_url.clone());
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
            jwks: BoundedVec<u8, T::MaxLengthIssuerJWKS>,
        ) -> DispatchResult {
            //------------------------------------------------------------------
            // 0. origin – only validators are allowed to call this
            //------------------------------------------------------------------
            let who = ensure_signed(origin)?;
            ensure!(
                T::Validators::validators().contains(&who),
                Error::<T>::OnlyValidatorsCanProposeJWKS
            );

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
            let jwks_hash = H256::from(blake2_256(jwks.as_slice()));

            //------------------------------------------------------------------
            // 3. record that THIS validator has already proposed for THIS domain
            //------------------------------------------------------------------
            AccountsProposedForIssuer::<T>::try_mutate(&domain, |opt_vec| -> DispatchResult {
                // lazily create an empty bounded‐vec when the first proposal arrives
                let vec = opt_vec.get_or_insert_with(
                    BoundedVec::<T::AccountId, T::MaxProposersPerIssuer>::default,
                );

                // duplicate proposal?
                ensure!(!vec.contains(&who), Error::<T>::AlreadyProposedForJWKS);

                // push – fail if MaxProposersPerIssuer is reached
                vec.try_push(who.clone())
                    .map_err(|_| Error::<T>::MaxProposersPerIssuerExceeded)?;

                Ok(())
            })?;

            //------------------------------------------------------------------
            // 4. store the JWKS bytes if we haven’t seen this hash before
            //------------------------------------------------------------------
            JwksHash::<T>::try_mutate(jwks_hash, |slot| -> DispatchResult {
                if slot.is_none() {
                    *slot = Some(jwks.clone());
                }
                Ok(())
            })?;

            //------------------------------------------------------------------
            // 5. bump the (domain, hash) counter atomically
            //------------------------------------------------------------------
            CounterProposedJwksHash::<T>::mutate(
                &domain,   // first key
                jwks_hash, // second key (by value or &jwks_hash)
                |count| {
                    *count = count.saturating_add(1);
                },
            );

            //------------------------------------------------------------------
            // 6. emit an event
            //------------------------------------------------------------------
            Self::deposit_event(Event::<T>::IssuerJWKSUpdated { who, domain });

            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(Weight::default())] // #[pallet::weight(<T as Config>::WeightInfo::set_jwks())]   // replace with Weight::default() until you benchmark
        pub fn set_jwks(
            origin: OriginFor<T>,
            domain: BoundedVec<u8, T::MaxLengthIssuerDomain>,
        ) -> DispatchResult {
            //------------------------------------------------------------------
            // 0. origin.
            //------------------------------------------------------------------
            let who = ensure_signed(origin)?;
            ensure!(
                T::Validators::validators().contains(&who),
                Error::<T>::OnlyValidatorsCanProposeJWKS
            );

            //------------------------------------------------------------------
            // 1. the issuer must exist
            //------------------------------------------------------------------
            ensure!(
                IssuerMap::<T>::contains_key(&domain),
                Error::<T>::IssuerDoesNotExist
            );

            //------------------------------------------------------------------
            // 2. pick the JWKS with the highest vote count
            //------------------------------------------------------------------
            let winning_jwks: Option<BoundedVec<u8, T::MaxLengthIssuerJWKS>> =
                Some(Self::get_jwks_with_higher_count(&domain));

            // No JWKS proposals yet?
            let winning_jwks = winning_jwks.ok_or(Error::<T>::AlreadyProposedForJWKS)?; // or introduce a new error

            //------------------------------------------------------------------
            // 3. write to JwksMap only if it changed
            //------------------------------------------------------------------
            let mut changed: bool = false;
            JwksMap::<T>::try_mutate(&domain, |slot| -> DispatchResult {
                if slot.as_ref() == Some(&winning_jwks) {
                    // No change, skip write & later event
                    return Ok(());
                }
                *slot = Some(winning_jwks.clone());
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
            // Set the jwks in the JwksMap
            // Self::set_jwks();

            // Clear all JWKS proposals
            // JwksProposals::<T>::clear();

            info!("Cleaning all JWKS proposals");
        }

        // fn on_initialize(n: BlockNumberFor<T>) {
        //     info!("Initializing the offchain worker for getting the jwks from internet");
        //     // Iterate on all the registered issuers
        //     for issuer in IssuerMap::<T>::iter() {
        //         if !issuer.1.is_enabled || issuer.1.interval_update.is_none() || issuer.1.interval_update.unwrap() == 0 {
        //             continue;
        //         }

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
        //         // Store the jwks in the proposal storage(JwksProposals)
        //         // JwksProposals::<T>::insert((issuer.name, jwks_url, who), ());

        //     }
        // }
    }
}

impl<T: Config> Pallet<T> {
    pub fn validate_json<Len>(json: &mut BoundedVec<u8, Len>) -> DispatchResult
    where
        Len: Get<u32>,
    {
        // Parse JSON (keys will be sorted automatically)
        let parsed = serde_json::from_slice::<serde_json::Value>(json.as_slice())
            .map_err(|_| Error::<T>::InvalidJson)?;

        // Serialize back into canonical form (keys ordered by BTreeMap)
        let serialized = serde_json::to_string(&parsed).map_err(|_| Error::<T>::InvalidJson)?;

        let bytes = serialized.as_bytes();

        if bytes.len() > Len::get() as usize {
            return Err(Error::<T>::JsonTooLong.into());
        }

        *json = BoundedVec::try_from(bytes.to_vec()).map_err(|_| Error::<T>::JsonTooLong)?;

        Ok(())
    }

    pub fn validate_interval_update(interval_update: &mut Option<u32>) {
        let lower = T::MinUpdateInterval::get();
        let upper = T::MaxUpdateInterval::get();

        if let Some(v) = interval_update {
            // First raise the value to the lower bound,
            // then cut it down to the upper bound.
            *v = (*v).max(lower).min(upper);
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
    /// `BoundedVec`, which the caller can interpret as “no winner”.
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
            if let Some(jwks) = JwksHash::<T>::get(winning_hash) {
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
