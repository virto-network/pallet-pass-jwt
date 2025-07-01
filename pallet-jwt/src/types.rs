use frame::prelude::*;
use miniserde::{Deserialize, Serialize};

// Enum URL type
#[derive(
    Clone, Debug, PartialEq, TypeInfo, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, Default,
)]
pub enum UrlType {
    JWKS,
    #[default]
    OPENID,
}

// Not sure if #[serde(skip_serializing_if = "Option::is_none")] is available in miniserde
// If available, we can use it to skip serializing fields that are not present
// The only mandatory field right now is jwks_uri
#[derive(Serialize, Deserialize, Debug)]
pub struct OpenIdConfig {
    // pub issuer: String,
    // pub authorization_endpoint: String,
    // pub device_authorization_endpoint: String,
    // pub token_endpoint: String,
    // pub userinfo_endpoint: String,
    // pub revocation_endpoint: String,
    pub jwks_uri: String,
    // pub response_types_supported: Vec<String>,
    // pub subject_types_supported: Vec<String>,
    // pub id_token_signing_alg_values_supported: Vec<String>,
    // pub scopes_supported: Vec<String>,
    // pub token_endpoint_auth_methods_supported: Vec<String>,
    // pub claims_supported: Vec<String>,
    // pub code_challenge_methods_supported: Vec<String>,
    // pub grant_types_supported: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Jwk {
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
    pub kty: String,
    pub r#use: String,
}
