use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, TokenData, encode};
// use serde_json::json;
// use std::collections::HashMap;
use validator::*;

// Correct values
// p=61 q=53 n=p*q=3233
// phi(n) =(p-1)(q-1)=3120
// e=17 d=2753
fn create_correct_values() -> JwkSet {
    let correct_jwk_1: Jwk = Jwk {
        common: CommonParameters {
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some("ee193d4647ab4a3585aa9b2b3b484a87aa68bb42".to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: "3233".to_string(),
            e: "17".to_string(),
        }),
    };

    let correct_jwk_2: Jwk = Jwk {
        common: CommonParameters {
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some("ff204d4647ab4a3585aa9b2b3b484a87aa68cc37".to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: "3233".to_string(),
            e: "17".to_string(),
        }),
    };
    JwkSet {
        keys: vec![correct_jwk_1, correct_jwk_2],
    }
}
// Incorrect values

fn create_test_claims(exp: u64) -> Claims {
    Claims {
        aud: "test_audience".into(),
        sub: "user123".into(),
        company: "test_company".into(),
        exp,
        iss: "test_issuer".into(),
    }
}

fn create_test_jwk(kid: &str, n: &str, e: &str) -> Jwk {
    Jwk {
        common: CommonParameters {
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: n.to_string(),
            e: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_check_token() {
    //     let claims = create_test_claims(9999999999);
    //     let header = Header::new(Algorithm::RS256);
    //     let token_data = TokenData {
    //         claims: claims,
    //         header,
    //     };

    //     let result = check_token(&token_data);
    //     assert!(result.is_ok());
    //     assert!(result.unwrap().contains("user123"));
    // }

    #[test]
    fn test_get_kid_from_token_ok() {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("abc123".to_string());

        assert_eq!(get_kid_from_token(&header).unwrap(), "abc123");
    }

    #[test]
    fn test_get_kid_from_token_none() {
        let header = Header::new(Algorithm::RS256);
        assert_eq!(get_kid_from_token(&header), None);
    }

    #[test]
    fn test_get_kid_from_token_empty() {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("".to_string());
        assert_eq!(get_kid_from_token(&header), None);
    }

    // #[test]
    // fn test_has_token_expired_not_expired() {
    //     let claims = create_test_claims(u64::MAX); // way in the future
    //     let header = Header::default();
    //     let token_data = TokenData { claims, header };

    //     assert!(has_token_expired(&token_data).is_ok());
    // }

    // #[test]
    // fn test_has_token_expired_expired() {
    //     let claims = create_test_claims(0); // definitely in the past
    //     let header = Header::default();
    //     let token_data = TokenData { claims, header };

    //     assert!(matches!(
    //         has_token_expired(&token_data),
    //         Err(Error::TokenExpired)
    //     ));
    // }

    #[test]
    fn test_get_issuer_and_sub() {
        let claims = create_test_claims(9999999999);
        let header = Header::default();
        let token_data = TokenData { claims, header };

        assert_eq!(
            get_issuer(&token_data).unwrap_or(String::from("error")),
            "test_issuer"
        );
        assert_eq!(
            get_sub(&token_data).unwrap_or(String::from("error")),
            "user123"
        );
    }

    #[test]
    fn test_get_issuer_and_sub_empty() {
        let mut claims = create_test_claims(9999999999);
        claims.iss = "".to_string();
        claims.sub = "".to_string();
        let header = Header::default();
        let token_data = TokenData { claims, header };

        assert!(matches!(get_issuer(&token_data), Err(ErrorInJwt::NoIssuer)));
        assert!(matches!(get_sub(&token_data), Err(ErrorInJwt::NoSub)));
    }

    #[test]
    fn test_get_signature_and_message() {
        let token = "aaa.bbb.ccc";
        assert_eq!(get_signature(token).unwrap(), "ccc");
        assert_eq!(get_message(token).unwrap(), "bbb");
    }

    #[test]
    fn test_get_signature_and_message_invalid() {
        let invalid_tokens = vec!["", "aaa", "aaa.bbb", "aaa.bbb.ccc.ddd"];

        for token in invalid_tokens {
            assert_eq!(get_signature(token), None);
            assert_eq!(get_message(token), None);
        }
    }

    #[test]
    fn test_get_jwk_success() {
        let jwk = create_test_jwk("my_kid", "some_n", "some_e");
        let jwks = JwkSet {
            keys: vec![jwk.clone()],
        };

        let result = get_jwk("my_kid", &jwks);
        assert!(result.is_some());
        assert_eq!(result.unwrap().common.key_id.unwrap(), "my_kid");
    }

    #[test]
    fn test_get_jwk_failure() {
        let jwks = JwkSet { keys: vec![] };
        assert_eq!(get_jwk("missing_kid", &jwks), None);
    }

    #[test]
    fn test_verify_jwt_success() {
        let n = "3233"; // Example RSA modulus
        let e = "17"; // Example RSA public exponent
        let kid = "test_kid";
        let jwk = create_test_jwk(kid, n, e);
        let jwks = JwkSet { keys: vec![jwk] };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        let claims = create_test_claims(u64::MAX);
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(include_bytes!("../test_key.pem")).unwrap(),
        )
        .unwrap();

        let result = verify_jwt(&token, &jwks);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_jwt_failures() {
        let jwks = JwkSet { keys: vec![] };

        // Test invalid JWT format
        assert!(matches!(
            verify_jwt("invalid.jwt.format", &jwks),
            Err(ErrorInJwt::InvalidJwt)
        ));

        // Test missing KID
        let mut header = Header::new(Algorithm::RS256);
        let claims = create_test_claims(u64::MAX);
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(include_bytes!("../test_key.pem")).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_jwt(&token, &jwks),
            Err(ErrorInJwt::InvalidJwt)
        ));

        // Test missing JWK
        header.kid = Some("missing_kid".to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(include_bytes!("../test_key.pem")).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_jwt(&token, &jwks),
            Err(ErrorInJwt::NoJwkForKid)
        ));
    }
}
