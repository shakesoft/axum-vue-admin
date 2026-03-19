// JWT工具

use crate::config::auth::{ACCESS_TOKEN_SECRET, CSRF_SECRET, REFRESH_TOKEN_SECRET};
use crate::errors::app_error::AppError;
use crate::schemas::auth::{Claims, CsrfPayload};
use crate::unauthorized;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};

pub fn create_access_token(data: Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let token = encode(
        &Header::default(),
        &data,
        &EncodingKey::from_secret(ACCESS_TOKEN_SECRET.as_ref()),
    )?;

    Ok(token)
}

pub fn verify_access_token(token: &str) -> Result<Claims, AppError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let decoded: TokenData<Claims> = decode(
        token,
        &DecodingKey::from_secret(ACCESS_TOKEN_SECRET.as_ref()),
        &validation,
    )
        .map_err(|e| {
            tracing::error!("verify_access_token error: {}", e);
            unauthorized!("Decode token error".to_string())
        })?;

    Ok(decoded.claims)
}

pub fn create_csrf_token(payload: CsrfPayload) -> Result<String, jsonwebtoken::errors::Error> {
    let token = encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(CSRF_SECRET.as_ref()),
    )?;
    Ok(token)
}

pub fn verify_csrf_token(token: &str) -> Result<CsrfPayload, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    let decoded = decode::<CsrfPayload>(
        token,
        &DecodingKey::from_secret(CSRF_SECRET.as_ref()),
        &validation,
    )
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::error!("verify_csrf_token error: {}", e);
            unauthorized!("Decode token error".to_string())
        })?;
    Ok(decoded)
}

pub fn create_refresh_token(payload: Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let token = encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(REFRESH_TOKEN_SECRET.as_ref()),
    )?;

    Ok(token)
}

pub fn verify_refresh_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let decoded = decode::<Claims>(
        token,
        &DecodingKey::from_secret(REFRESH_TOKEN_SECRET.as_ref()),
        &validation,
    )
        .map(|data| data.claims)?;

    Ok(decoded)
}
