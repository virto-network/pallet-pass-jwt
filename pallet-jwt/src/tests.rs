use super::*;
use crate::mock::*;
use frame::runtime::testing_prelude::BuildStorage;
use frame_support::{assert_noop, assert_ok};
use frame_system::GenesisConfig;

// Helper function to create a test externalities
fn new_test_ext() -> sp_io::TestExternalities {
    GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

// Helper function to create a bounded vec from a string
fn bounded_vec<T: Get<u32>>(s: &str) -> BoundedVec<u8, T> {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

// Helper function to create a valid JWKS JSON
fn create_test_jwks() -> BoundedVec<u8, MaxLengthIssuerJWKS> {
    let jwks = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-1",
                "use": "sig",
                "n": "test-n",
                "e": "AQAB"
            }
        ]
    }"#;
    bounded_vec(jwks)
}

// Helper function to create a valid OpenID URL
fn create_test_openid_url() -> BoundedVec<u8, MaxLengthIssuerOpenIdURL> {
    bounded_vec("https://test.example.com/.well-known/openid-configuration")
}

#[test]
fn test_register_issuer_success() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer as root
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url.clone(),
            jwks.clone(),
            interval_update,
        ));

        // Verify storage
        let issuer = IssuerMap::<Test>::get(&domain).unwrap();
        assert_eq!(issuer.open_id_url, open_id_url);
        assert_eq!(issuer.interval_update, interval_update);
        assert!(issuer.is_enabled);

        // Verify JWKS storage
        assert_eq!(JwksMap::<Test>::get(&domain), jwks);
    });
}

#[test]
fn test_register_issuer_duplicate() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // First registration
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url.clone(),
            jwks.clone(),
            interval_update,
        ));

        // Try to register again
        assert_noop!(
            Jwt::register_issuer(
                RuntimeOrigin::root(),
                domain,
                open_id_url,
                jwks,
                interval_update,
            ),
            Error::<Test>::IssuerAlreadyExists
        );
    });
}

#[test]
fn test_update_issuer() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url.clone(),
            jwks.clone(),
            interval_update,
        ));

        // Update issuer
        let new_open_id_url = Some(bounded_vec::<MaxLengthIssuerOpenIdURL>(
            "https://new.example.com/.well-known/openid-configuration",
        ));
        let new_jwks = Some(create_test_jwks());
        let new_interval_update = Some(200);

        assert_ok!(Jwt::update_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            new_open_id_url.clone(),
            new_jwks.clone(),
            new_interval_update,
            true,
        ));

        // Verify storage
        let issuer = IssuerMap::<Test>::get(&domain).unwrap();
        assert_eq!(issuer.open_id_url, new_open_id_url);
        assert_eq!(issuer.interval_update, new_interval_update);
        assert!(issuer.is_enabled);

        // Verify JWKS storage
        assert_eq!(JwksMap::<Test>::get(&domain), new_jwks);
    });
}

#[test]
fn test_delete_issuer() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url,
            jwks.clone(),
            interval_update,
        ));

        // Delete issuer
        assert_ok!(Jwt::delete_issuer(RuntimeOrigin::root(), domain.clone()));

        // Verify storage is empty
        assert!(!IssuerMap::<Test>::contains_key(&domain));
        assert!(!JwksMap::<Test>::contains_key(&domain));
    });
}

#[test]
fn test_set_enabled() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url,
            jwks,
            interval_update,
        ));

        // Disable issuer
        assert_ok!(Jwt::set_enabled(
            RuntimeOrigin::root(),
            domain.clone(),
            false
        ));

        // Verify storage
        let issuer = IssuerMap::<Test>::get(&domain).unwrap();
        assert!(!issuer.is_enabled);

        // Enable issuer
        assert_ok!(Jwt::set_enabled(
            RuntimeOrigin::root(),
            domain.clone(),
            true
        ));

        // Verify storage
        let issuer = IssuerMap::<Test>::get(&domain).unwrap();
        assert!(issuer.is_enabled);
    });
}

#[test]
fn test_propose_jwks() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url,
            jwks,
            interval_update,
        ));

        // Propose new JWKS
        let new_jwks = create_test_jwks();
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(1),
            domain.clone(),
            new_jwks.clone(),
        ));

        // Verify storage
        let accounts = AccountsProposedForIssuer::<Test>::get(&domain).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0], 1);

        // Try to propose again with same account
        assert_noop!(
            Jwt::propose_jwks(RuntimeOrigin::signed(1), domain.clone(), new_jwks.clone(),),
            Error::<Test>::AlreadyProposedForJWKS
        );
    });
}

#[test]
fn test_set_jwks() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url,
            jwks,
            interval_update,
        ));

        // Propose new JWKS
        let new_jwks = create_test_jwks();
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(1),
            domain.clone(),
            new_jwks.clone(),
        ));

        // Set JWKS
        assert_ok!(Jwt::set_jwks(RuntimeOrigin::root(), domain.clone()));

        // Verify storage
        assert_eq!(JwksMap::<Test>::get(&domain), Some(new_jwks));
    });
}

#[test]
fn test_validate_json() {
    new_test_ext().execute_with(|| {
        // Valid JSON
        let mut valid_json = bounded_vec::<MaxLengthIssuerJWKS>(r#"{"key": "value"}"#);
        assert_ok!(Jwt::validate_json(&mut valid_json));

        // Invalid JSON
        let mut invalid_json = bounded_vec::<MaxLengthIssuerJWKS>(r#"{"key": "value""#);
        assert_noop!(
            Jwt::validate_json(&mut invalid_json),
            Error::<Test>::InvalidJson
        );
    });
}

#[test]
fn test_validate_interval_update() {
    new_test_ext().execute_with(|| {
        // Test minimum bound
        let mut interval = Some(5);
        Jwt::validate_interval_update(&mut interval);
        assert_eq!(interval, Some(10)); // Should be set to MinUpdateInterval

        // Test maximum bound
        let mut interval = Some(2000);
        Jwt::validate_interval_update(&mut interval);
        assert_eq!(interval, Some(1000)); // Should be set to MaxUpdateInterval

        // Test valid value
        let mut interval = Some(500);
        Jwt::validate_interval_update(&mut interval);
        assert_eq!(interval, Some(500)); // Should remain unchanged
    });
}

#[test]
fn test_get_issuers_vec() {
    new_test_ext().execute_with(|| {
        let domain1 = bounded_vec::<MaxLengthIssuerDomain>("example1.com");
        let domain2 = bounded_vec::<MaxLengthIssuerDomain>("example2.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register two issuers
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain1.clone(),
            open_id_url.clone(),
            jwks.clone(),
            interval_update,
        ));

        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain2.clone(),
            open_id_url,
            jwks,
            interval_update,
        ));

        // Get all issuers
        let issuers = Jwt::get_issuers_vec();
        assert_eq!(issuers.len(), 2);
        assert!(issuers.contains(&domain1));
        assert!(issuers.contains(&domain2));
    });
}

#[test]
fn test_get_jwks_with_higher_count() {
    new_test_ext().execute_with(|| {
        let domain = bounded_vec::<MaxLengthIssuerDomain>("example.com");
        let open_id_url = Some(create_test_openid_url());
        let jwks = Some(create_test_jwks());
        let interval_update = Some(100);

        // Register issuer
        assert_ok!(Jwt::register_issuer(
            RuntimeOrigin::root(),
            domain.clone(),
            open_id_url,
            jwks,
            interval_update,
        ));

        // Propose JWKS from multiple accounts
        let new_jwks = create_test_jwks();
        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(1),
            domain.clone(),
            new_jwks.clone(),
        ));

        assert_ok!(Jwt::propose_jwks(
            RuntimeOrigin::signed(2),
            domain.clone(),
            new_jwks.clone(),
        ));

        // Get JWKS with highest count
        let winning_jwks = Jwt::get_jwks_with_higher_count(&domain);
        assert_eq!(winning_jwks, new_jwks);
    });
}
