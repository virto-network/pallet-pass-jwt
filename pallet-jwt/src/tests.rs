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

// More tests for update_issuer, delete_issuer, set_interval_update, set_enabled, set_url, propose_jwks, set_jwks, offchain worker, and all boundary/error cases will be added below.
