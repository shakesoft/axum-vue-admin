use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

pub const REFRESH_TOKEN_SECRET: &str = "bc15e5644c71750ae12c2acb9678c2602f4d9b35cb1ae215bcadcfa66c6c734b";


#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

type UserUUID = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: UserUUID,
    pub iat: u64,
    pub exp: u64,
    pub jti: Uuid,
    pub name: String,
    pub dept_uuid: String,
    pub token_type: TokenType,
    pub is_super_admin: bool,
}

pub fn verify_refresh_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    debug!("Verifying refresh token: {}", token);
    let decoded = decode::<Claims>(
        token,
        &DecodingKey::from_secret(REFRESH_TOKEN_SECRET.as_ref()),
        &Validation::default(),
    )
        .map(|data| data.claims)?;

    Ok(decoded)
}
fn main() -> anyhow::Result<()> {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwZGQzNGQ2Yi05ZmY2LTRlNWEtYWIyYi0zYWUxN2Q3YjRmNTYiLCJpYXQiOjE3NjQxNDAwOTMsImV4cCI6MTgwMDQyODA5MywianRpIjoiMjExYmZmZDQtNDY3YS00NDUwLWJkYjgtYjk4YmRjZTg4ZjMzIiwibmFtZSI6InN1cGVyYWRtaW4iLCJkZXB0X3V1aWQiOiJlMDUxMzAzZC0xZTlmLTQwYmYtOTc5ZC1mNzYwY2RjMWU5NjgiLCJ0b2tlbl90eXBlIjoiUmVmcmVzaCIsImlzX3N1cGVyX2FkbWluIjp0cnVlfQ.uL4YKHKpCjPU_WxLhL_GA9VR4AsA235dTeVvrai0Pqc";
    let decoded = verify_refresh_token(token)?;
    Ok(())
}