use jsonwebtoken::crypto::verify;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
// use jsonwebtoken::{Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header};
use jsonwebtoken::{DecodingKey, Header, TokenData, decode_header};
use serde::{Deserialize, Serialize};

pub enum ErrorInJwt {
    InvalidJwt,
    InvalidJwks,
    InvalidJwk,
    InvalidJson,
    InvalidToken,
    TokenExpired,
    AlgorithmNotSupported,
    NoIssuer,
    NoSub,
    NoJwkForKid,
    NotPossibleToGetDecodeKey,
    ErrorVerifying,
    NoSignaturePresent,
}

pub enum JwksEnum {
    Jwk(Jwk),
    Jwks(JwkSet),
    InnerKey(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub company: String,
    pub sub: String,
    pub exp: u64,
    pub iss: String,
}

fn get_public_key(jwk: &Jwk) -> Option<DecodingKey> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa_params) => {
            DecodingKey::from_rsa_components(&rsa_params.n, &rsa_params.e).ok()
        }
        _ => None,
    }
}

pub fn get_kid_from_token(the_header: &Header) -> Option<String> {
    match &the_header.kid {
        Some(kid) if !kid.is_empty() => Some(kid.clone()),
        _ => None,
    }
}

// JWT auxiliar functions
pub fn get_issuer(token: &TokenData<Claims>) -> Result<String, ErrorInJwt> {
    let res = if token.claims.iss.is_empty() {
        Err(ErrorInJwt::NoIssuer)
    } else {
        Ok(token.claims.iss.clone())
    };
    res
}

pub fn get_sub(token: &TokenData<Claims>) -> Result<String, ErrorInJwt> {
    let res = if token.claims.sub.is_empty() {
        Err(ErrorInJwt::NoSub)
    } else {
        Ok(token.claims.sub.clone())
    };
    res
}

// JWKs|JWK auxiliar functions
pub fn get_jwk(jwt_kid: &str, jwks: &JwkSet) -> Option<Jwk> {
    jwks.keys.iter().find_map(|jwk| {
        if jwk.common.key_id.as_deref() == Some(jwt_kid) {
            Some(jwk.clone())
        } else {
            None
        }
    })
}

pub fn get_signature(token: &str) -> Option<String> {
    match token.split('.').nth(2) {
        Some(signature) => Some(signature.into()),
        _ => None,
    }
}

pub fn get_message(token: &str) -> Option<String> {
    match token.split('.').nth(1) {
        Some(message) => Some(message.into()),
        _ => None,
    }
}

pub fn verify_jwt(token: &str, jwks: &JwkSet) -> Result<bool, ErrorInJwt> {
    let token_header = decode_header(token).map_err(|_| ErrorInJwt::InvalidJwt)?;
    let jwt_kid = get_kid_from_token(&token_header).ok_or(ErrorInJwt::InvalidJwt)?;
    let jwk = get_jwk(&jwt_kid, &jwks).ok_or(ErrorInJwt::NoJwkForKid)?;
    let decode_key = get_public_key(&jwk).ok_or(ErrorInJwt::NotPossibleToGetDecodeKey)?;
    // // Get JWT info to use from Pallet?
    // let token_data =decode::<Claims>(token, &decode_key, &Validation::new(Algorithm::RS256)).map_err(|_| ErrorInJwt::InvalidJwt)?;
    // let _issuer = get_issuer(&token_data)?;
    // let _subs = get_sub(&token_data)?;

    // Extract signature
    let signature = get_signature(&token).ok_or(ErrorInJwt::NoSignaturePresent)?;
    let message = get_message(&token).ok_or(ErrorInJwt::NoSignaturePresent)?;
    // Get JWK info
    verify(
        &signature,
        message.as_bytes(),
        &decode_key,
        jsonwebtoken::Algorithm::RS256,
    )
    .map_err(|_| ErrorInJwt::ErrorVerifying)
}
