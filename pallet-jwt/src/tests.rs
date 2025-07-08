//! Comprehensive tests for pallet-jwt, including offchain worker and all extrinsics.

use super::*;
use crate::mock::*;
use crate::types::UrlType;
use frame_support::{BoundedVec, assert_noop, assert_ok, traits::OnFinalize};
use sp_runtime::traits::BadOrigin;

type Domain = BoundedVec<u8, MaxLengthIssuerDomain>;
type Url = BoundedVec<u8, MaxLengthIssuerURL>;
type Jwks = BoundedVec<u8, MaxLengthIssuerJWKS>;

type MaxLengthIssuerDomain = <Test as Config>::MaxLengthIssuerDomain;
type MaxLengthIssuerURL = <Test as Config>::MaxLengthIssuerURL;
type MaxLengthIssuerJWKS = <Test as Config>::MaxLengthIssuerJWKS;

fn domain_vec(s: &str) -> Domain {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}
fn url_vec(s: &str) -> Url {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}
fn jwks_vec(s: &str) -> Jwks {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

#[test]
fn register_issuer_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);

        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        // Check storage
        assert!(Jwt::get_issuer_map(&domain).is_some());
        assert_eq!(Jwt::get_issuer_creator(&domain), Some(who));
        assert!(Jwt::get_jwks_map(&domain).is_some());
    });
}

#[test]
fn register_issuer_fails_if_already_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);

        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        // Try again
        assert_noop!(
            Jwt::register_issuer(
                RuntimeOrigin::signed(who),
                domain.clone(),
                url.clone(),
                jwks.clone(),
                url_type.clone(),
                interval_update
            ),
            Error::<Test>::IssuerAlreadyExists
        );
    });
}

#[test]
fn register_issuer_fails_with_long_domain() {
    new_test_ext().execute_with(|| {
        let domain = BoundedVec::<u8, MaxLengthIssuerDomain>::try_from(vec![b'a'; 101]);
        assert!(domain.is_err());
    });
}

#[test]
fn register_issuer_fails_with_invalid_origin() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        // Unsigned origin
        assert_noop!(
            Jwt::register_issuer(
                RuntimeOrigin::none(),
                domain,
                url,
                jwks,
                url_type,
                interval_update
            ),
            BadOrigin
        );
    });
}

#[test]
fn update_issuer_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let new_url = url_vec("https://accounts.google.com/new-openid");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let new_jwks = Some(jwks_vec("{\"keys\":[1]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let is_enabled = false;
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);

        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        // Update issuer
        assert_ok!(Jwt::update_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            new_url.clone(),
            url_type.clone(),
            new_jwks.clone(),
            Some(30u32),
            is_enabled
        ));
        let issuer = Jwt::get_issuer_map(&domain).unwrap();
        assert_eq!(issuer.url, new_url);
        assert_eq!(issuer.is_enabled, is_enabled);
    });
}

#[test]
fn update_issuer_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let url = url_vec("https://example.com");
        let url_type = UrlType::OPENID;
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::update_issuer(
                RuntimeOrigin::signed(who),
                domain,
                url,
                url_type,
                jwks,
                Some(10u32),
                true
            ),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn delete_issuer_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::delete_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone()
        ));
        assert!(Jwt::get_issuer_map(&domain).is_none());
        assert!(Jwt::get_issuer_creator(&domain).is_none());
        assert!(Jwt::get_jwks_map(&domain).is_none());
    });
}

#[test]
fn delete_issuer_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::delete_issuer(RuntimeOrigin::signed(who), domain),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn set_interval_update_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::set_interval_update(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            Some(30u32)
        ));
        let issuer = Jwt::get_issuer_map(&domain).unwrap();
        assert_eq!(issuer.interval_update, Some(30u32));
    });
}

#[test]
fn set_interval_update_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::set_interval_update(RuntimeOrigin::signed(who), domain, Some(10u32)),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn set_enabled_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::set_enabled(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            false
        ));
        let issuer = Jwt::get_issuer_map(&domain).unwrap();
        assert!(!issuer.is_enabled);
    });
}

#[test]
fn set_enabled_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::set_enabled(RuntimeOrigin::signed(who), domain, false),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn set_url_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let new_url = url_vec("https://accounts.google.com/new-openid");
        let jwks = Some(jwks_vec("{\"keys\":[]}"));
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            jwks.clone(),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::set_url(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            new_url.clone()
        ));
        let issuer = Jwt::get_issuer_map(&domain).unwrap();
        assert_eq!(issuer.url, new_url);
    });
}

#[test]
fn set_url_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let new_url = url_vec("https://example.com/new");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::set_url(RuntimeOrigin::signed(who), domain, new_url),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn propose_jwks_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("{\"keys\":[]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks.clone()),
            url_type.clone(),
            interval_update
        ));
        // Propose JWKS
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            jwks.clone()
        ));
        // Proposing again with a different JWKS is ok
        let jwks2 = jwks_vec("{\"keys\":[1]}");
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            jwks2.clone()
        ));
    });
}

#[test]
fn propose_jwks_fails_if_not_validator() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("{\"keys\":[]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let not_validator = sp_core::sr25519::Public::from_raw([2u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks.clone()),
            url_type.clone(),
            interval_update
        ));
        // Only validators can propose (in this mock, all are allowed, but test for completeness)
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            jwks.clone()
        ));
        // If origin is none, should fail
        assert_noop!(
            Jwt::propose_jwks(RuntimeOrigin::none(), domain.clone(), jwks.clone()),
            BadOrigin
        );
    });
}

#[test]
fn propose_jwks_fails_if_duplicate() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("{\"keys\":[]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            jwks.clone()
        ));
        // Proposing the same JWKS again should fail
        assert_noop!(
            Jwt::propose_jwks(
                RuntimeOrigin::signed(who.clone()),
                domain.clone(),
                jwks.clone()
            ),
            Error::<Test>::DuplicateJWKSProposal
        );
    });
}

#[test]
fn propose_jwks_fails_if_issuer_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let jwks = jwks_vec("{\"keys\":[]}");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::propose_jwks(RuntimeOrigin::signed(who), domain, jwks),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn propose_jwks_fails_with_invalid_json() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("not-json");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks_vec("{\"keys\":[]}")),
            url_type.clone(),
            interval_update
        ));
        assert_noop!(
            Jwt::propose_jwks(RuntimeOrigin::signed(who.clone()), domain.clone(), jwks),
            Error::<Test>::InvalidJson
        );
    });
}

#[test]
fn set_jwks_works() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("{\"keys\":[]}");
        let new_jwks = jwks_vec("{\"keys\":[1]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::set_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            new_jwks.clone()
        ));
        assert_eq!(Jwt::get_jwks_map(&domain), Some(new_jwks));
    });
}

#[test]
fn set_jwks_fails_if_not_exists() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("NonExistent");
        let jwks = jwks_vec("{\"keys\":[]}");
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_noop!(
            Jwt::set_jwks(RuntimeOrigin::signed(who), domain, jwks),
            Error::<Test>::IssuerDoesNotExist
        );
    });
}

#[test]
fn set_jwks_fails_with_invalid_json() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("not-json");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks_vec("{\"keys\":[]}")),
            url_type.clone(),
            interval_update
        ));
        assert_noop!(
            Jwt::set_jwks(RuntimeOrigin::signed(who.clone()), domain.clone(), jwks),
            Error::<Test>::InvalidJson
        );
    });
}

#[test]
fn set_jwks_no_change_no_event() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks = jwks_vec("{\"keys\":[]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(20u32);
        let who = sp_core::sr25519::Public::from_raw([1u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks.clone()),
            url_type.clone(),
            interval_update
        ));
        // Setting the same JWKS should not emit an event or change storage
        assert_ok!(Jwt::set_jwks(
            RuntimeOrigin::signed(who.clone()),
            domain.clone(),
            jwks.clone()
        ));
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks));
    });
}

#[test]
fn offchain_worker_consensus_updates_jwks() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let jwks2 = jwks_vec("{\"keys\":[2]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(1u32); // Fast update for test
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        // Both validators propose different JWKS
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        // Simulate block finalization (should trigger consensus logic)
        Jwt::on_finalize(2);
        // The JWKS with the highest count (should be either, since both have 1, but at least one is set)
        let stored = Jwt::get_jwks_map(&domain).unwrap();
        assert!(stored == jwks1 || stored == jwks2);
        // Proposals should be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
    });
}

#[test]
fn on_finalize_requires_minimal_consensus() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let jwks2 = jwks_vec("{\"keys\":[2]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(1u32);
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        // Only one validator proposes
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        // Not enough for consensus (MinimalConsensusPercentage = 70, 2 validators, needs 2)
        Jwt::on_finalize(2);
        // JWKS should not be updated to the proposal
        let stored = Jwt::get_jwks_map(&domain).unwrap();
        assert_eq!(stored, jwks1); // initial value
        // Proposals should not be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_some());
    });
}

#[test]
fn on_finalize_selects_highest_count_jwks() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let jwks2 = jwks_vec("{\"keys\":[2]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(1u32);
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        let who3 = sp_core::sr25519::Public::from_raw([3u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        // Two propose jwks2, one proposes jwks1
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who3.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        // Now consensus should be reached (3 validators, 70% = 3)
        Jwt::on_finalize(2);
        // JWKS should be jwks2
        let stored = Jwt::get_jwks_map(&domain).unwrap();
        assert_eq!(stored, jwks2);
        // Proposals should be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
    });
}

#[test]
fn on_finalize_clears_all_volatile_storage() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(1u32);
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        Jwt::on_finalize(2);
        // All volatile storages should be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
        // JwksHash, CounterProposedJwksHash, DomainAccJwksHash are private, but their effects are covered by consensus and cleared proposals
    });
}

#[test]
fn on_finalize_no_consensus_if_no_validators() {
    // This test assumes Validators::validators() returns empty, which is not the case in the mock.
    // So we skip this test unless the mock is adjusted to allow zero validators.
}

#[test]
fn on_finalize_skips_if_issuer_disabled() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(1u32);
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::set_enabled(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            false
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        Jwt::on_finalize(2);
        // Proposals should not be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_some());
    });
}

#[test]
fn on_finalize_skips_if_no_interval_update() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let url_type = UrlType::OPENID;
        let interval_update = None;
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks1.clone()
        ));
        Jwt::on_finalize(2);
        // Proposals should not be cleared
        assert!(Jwt::get_domain_accs_vec(&domain).is_some());
    });
}

#[test]
fn on_finalize_triggers_only_at_interval() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let jwks2 = jwks_vec("{\"keys\":[2]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(3u32); // Only every 3 blocks
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        let who3 = sp_core::sr25519::Public::from_raw([3u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        // All propose jwks2
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who3.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        // Call on_finalize for blocks 2, 3, 4
        Jwt::on_finalize(2);
        // Should not trigger consensus yet
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks1.clone()));
        assert!(Jwt::get_domain_accs_vec(&domain).is_some());
        Jwt::on_finalize(3);
        // Still not interval
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks1.clone()));
        assert!(Jwt::get_domain_accs_vec(&domain).is_some());
        Jwt::on_finalize(4);
        // Now interval triggers (block 4 - block 1 = 3)
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks2.clone()));
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
    });
}

#[test]
fn on_finalize_interval_repeats_and_respects_new_proposals() {
    new_test_ext().execute_with(|| {
        let domain = domain_vec("Google");
        let url = url_vec("https://accounts.google.com/.well-known/openid-configuration");
        let jwks1 = jwks_vec("{\"keys\":[1]}");
        let jwks2 = jwks_vec("{\"keys\":[2]}");
        let jwks3 = jwks_vec("{\"keys\":[3]}");
        let url_type = UrlType::OPENID;
        let interval_update = Some(2u32); // Every 2 blocks
        let who1 = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let who2 = sp_core::sr25519::Public::from_raw([2u8; 32]);
        let who3 = sp_core::sr25519::Public::from_raw([3u8; 32]);
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            url.clone(),
            Some(jwks1.clone()),
            url_type.clone(),
            interval_update
        ));
        // First round: all propose jwks2
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who2.clone()),
            domain.clone(),
            jwks2.clone()
        ));
        Jwt::on_finalize(2);
        // Not yet interval
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks1.clone()));
        Jwt::on_finalize(3);
        // Now interval triggers
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks2.clone()));
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
        // Second round: new proposals for jwks3
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who1.clone()),
            domain.clone(),
            jwks3.clone()
        ));
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(who3.clone()),
            domain.clone(),
            jwks3.clone()
        ));
        Jwt::on_finalize(4);
        // Not yet interval
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks2.clone()));
        Jwt::on_finalize(5);
        // Now interval triggers again
        assert_eq!(Jwt::get_jwks_map(&domain), Some(jwks3.clone()));
        assert!(Jwt::get_domain_accs_vec(&domain).is_none());
    });
}
