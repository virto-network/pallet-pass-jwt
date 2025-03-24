use jsonwebtoken::crypto::verify;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::{self};

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

#[derive(Debug, Serialize)]
struct SerializableTokenData<'a> {
    header: &'a jsonwebtoken::Header,
    claims: &'a Claims,
}

fn get_public_key(jwk: &Jwk) -> Result<DecodingKey, ErrorInJwt> {
    // Search the kid in the jwks
    let res: Result<DecodingKey, ErrorInJwt>;

    res = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa_params) => {
            Ok(DecodingKey::from_rsa_components(&rsa_params.n, &rsa_params.e).unwrap())
        }

        _ => Err(ErrorInJwt::NotPossibleToGetDecodeKey),
    };
    res
}

pub fn check_token(token: &TokenData<Claims>) -> Result<String, ErrorInJwt> {
    let serializable = SerializableTokenData {
        header: &token.header,
        claims: &token.claims,
    };

    match serde_json::to_string(&serializable) {
        Ok(json) => Ok(json),
        Err(_) => Err(ErrorInJwt::InvalidJson),
    }
}

pub fn get_kid_from_token(the_header: &Header) -> Result<String, ErrorInJwt> {
    match the_header.kid.clone() {
        Some(kid) if !kid.is_empty() => Ok(kid.clone()),
        Some(_) => Err(ErrorInJwt::InvalidToken),
        None => Err(ErrorInJwt::InvalidToken),
    }
}

pub fn has_token_expired(token: &TokenData<Claims>) -> Result<(), ErrorInJwt> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ErrorInJwt::InvalidToken)?
        .as_secs();

    if current_time < token.claims.exp {
        Ok(())
    } else {
        Err(ErrorInJwt::TokenExpired)
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

// Not sure if needed
// pub fn get_signature(token: &TokenData<Claims>) -> Result<String, Error> {
//     let res = if token. {
//         Err(ErrorInJwt::NoSub)
//     } else {
//         Ok(token.claims.sub.clone())
//     };
//     res
// }

// JWKs|JWK auxiliar functions
pub fn get_jwk(jwt_kid: &String, jwks: &JwkSet) -> Result<Jwk, ErrorInJwt> {
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_ref().map_or(false, |id| id == jwt_kid));
    let res = match jwk {
        Some(json_web_key) => Ok(json_web_key.clone()),
        None => Err(ErrorInJwt::NoJwkForKid),
    };
    res
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

pub fn verify_jwt(token: &str, jwks: JwkSet) -> Result<bool, ErrorInJwt> {
    let token_header = decode_header(token).unwrap(); // ToDo Handle error
    let jwt_kid = get_kid_from_token(&token_header)?;
    let jwk = get_jwk(&jwt_kid, &jwks)?;
    let decode_key = get_public_key(&jwk)?;
    let token_data =
        decode::<Claims>(token, &decode_key, &Validation::new(Algorithm::RS256)).unwrap(); // ToDo Handle error
    // Get JWT info
    check_token(&token_data)?;

    has_token_expired(&token_data)?;
    let _issuer = get_issuer(&token_data)?;
    let _subs = get_sub(&token_data)?;

    // Extract signature
    let signature = get_signature(&token)?;
    let message = get_message(&token)?;
    // Get JWK info
    let res = verify(
        &signature,
        message.as_bytes(),
        &decode_key,
        jsonwebtoken::Algorithm::RS256,
    );
    match res {
        Ok(x) => Ok(x),
        _ => Err(ErrorInJwt::ErrorVerifying),
    }
}
