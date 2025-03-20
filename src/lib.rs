use jsonwebtoken::crypto::verify;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{DecodingKey, TokenData};
use serde::{Deserialize, Serialize};
use serde_json::{self};

pub enum Error {
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
}

pub enum JwksEnum {
    Jwk(Jwk),
    Jwks(JwkSet),
    InnerKey(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    aud: String,
    sub: String,
    company: String,
    exp: u64,
    iss: String,
}

#[derive(Debug, Serialize)]
struct SerializableTokenData<'a> {
    header: &'a jsonwebtoken::Header,
    claims: &'a Claims,
}

fn get_public_key(kid: &str, jwk: &Jwk) -> Result<DecodingKey, Error> {
    // Search the kid in the jwks
    let res: Result<DecodingKey, Error>;

    res = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa_params) => {
            Ok(DecodingKey::from_rsa_components(&rsa_params.n, &rsa_params.e).unwrap())
        }

        _ => Err(Error::InvalidJwks),
    };
    res
}

pub fn check_token(token: &TokenData<Claims>) -> Result<String, Error> {
    let serializable = SerializableTokenData {
        header: &token.header,
        claims: &token.claims,
    };

    match serde_json::to_string(&serializable) {
        Ok(json) => Ok(json),
        Err(_) => Err(Error::InvalidJson),
    }
}

pub fn get_kid_from_token(token: &TokenData<Claims>) -> Result<String, Error> {
    match token.header.kid.as_ref() {
        Some(kid) if !kid.is_empty() => Ok(kid.clone()),
        Some(_) => Err(Error::InvalidToken),
        None => Err(Error::InvalidToken),
    }
}

pub fn has_token_expired(token: &TokenData<Claims>) -> Result<(), Error> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidToken)?
        .as_secs();

    if current_time < token.claims.exp {
        Ok(())
    } else {
        Err(Error::TokenExpired)
    }
}

// JWT auxiliar functions
pub fn get_issuer(token: &TokenData<Claims>) -> Result<String, Error> {
    let res = if token.claims.iss.is_empty() {
        Err(Error::NoIssuer)
    } else {
        Ok(token.claims.iss.clone())
    };
    res
}

pub fn get_sub(token: &TokenData<Claims>) -> Result<String, Error> {
    let res = if token.claims.sub.is_empty() {
        Err(Error::NoSub)
    } else {
        Ok(token.claims.sub.clone())
    };
    res
}

// Not sure if needed
// pub fn get_signature(token: &TokenData<Claims>) -> Result<String, Error> {
//     let res = if token. {
//         Err(Error::NoSub)
//     } else {
//         Ok(token.claims.sub.clone())
//     };
//     res
// }

// JWKs|JWK auxiliar functions

pub fn get_jwk(jwt_kid: &String, jwks: &JwkSet) -> Result<Jwk, Error> {
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_ref().map_or(false, |id| id == jwt_kid));
    let res = match jwk {
        Some(json_web_key) => Ok(json_web_key.clone()),
        None => Err(Error::NoJwkForKid),
    };
    res
}

pub fn get_crypto_pub_key() -> Result<DecodingKey, Error> {
    todo!()
}

pub fn verify_jwt(token: TokenData<Claims>, jwks: JwkSet) -> Result<bool, Error> {
    // Get JWT info
    check_token(&token)?;
    let jwt_kid = get_kid_from_token(&token)?;
    has_token_expired(&token)?;
    let issuer = get_issuer(&token)?;
    let subs = get_sub(&token)?;

    // Get JWK info
    let jwk = get_jwk(&jwt_kid, &jwks)?;
    let decode_key = get_public_key(&jwt_kid, &jwk)?;
    // let res = verify(signature, message, &decode_key, jsonwebtoken::Algorithm::RS256)?;

    todo!()
}
