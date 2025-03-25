use jsonwebtoken::crypto::verify;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header};
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

fn get_public_key(jwk: &Jwk) -> Result<DecodingKey, ErrorInJwt> {
    // Search the kid in the jwks
    let res = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa_params) => {
            Ok(DecodingKey::from_rsa_components(&rsa_params.n, &rsa_params.e).unwrap())
        }
        _ => Err(ErrorInJwt::NotPossibleToGetDecodeKey),
    };
    res
}

pub fn get_kid_from_token(the_header: &Header) -> Result<String, ErrorInJwt> {
    match the_header.kid.clone() {
        Some(kid) if !kid.is_empty() => Ok(kid.clone()),
        Some(_) => Err(ErrorInJwt::InvalidToken),
        None => Err(ErrorInJwt::InvalidToken),
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
pub fn get_jwk(jwt_kid: &String, jwks: &JwkSet) -> Option<Jwk> {
    jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_ref().map_or(false, |id| id == jwt_kid))
        .map(|jwk| jwk.clone())
}

pub fn get_signature(token: &str) -> Result<String, ErrorInJwt> {
    let signature = token.split('.').nth(2);
    match signature {
        Some(signature) => Ok(signature.into()),
        _ => Err(ErrorInJwt::NoSignaturePresent),
    }
}

pub fn get_message(token: &str) -> Result<String, ErrorInJwt> {
    let message = token.split('.').nth(1);
    match message {
        Some(message) => Ok(message.into()),
        _ => Err(ErrorInJwt::NoSignaturePresent),
    }
}

pub fn verify_jwt(token: &str, jwks: &JwkSet) -> Result<bool, ErrorInJwt> {
    let token_header = decode_header(token).unwrap(); // ToDo Handle error
    let jwt_kid = get_kid_from_token(&token_header)?;
    let jwk = get_jwk(&jwt_kid, &jwks).ok_or(ErrorInJwt::NoJwkForKid)?;
    let decode_key = get_public_key(&jwk)?;
    let token_data =
        decode::<Claims>(token, &decode_key, &Validation::new(Algorithm::RS256)).unwrap(); // ToDo Handle error
    // Get JWT info
    let _issuer = get_issuer(&token_data)?;
    let _subs = get_sub(&token_data)?;

    // Extract signature
    let signature = get_signature(&token)?;
    let message = get_message(&token)?;
    // Get JWK info
    verify(
        &signature,
        message.as_bytes(),
        &decode_key,
        jsonwebtoken::Algorithm::RS256,
    ).map_err(|_| ErrorInJwt::ErrorVerifying)
}
