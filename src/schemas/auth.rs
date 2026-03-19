use crate::schemas::user::UserUUID;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;


#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CsrfPayload {
    pub csrf_secret: String,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: UserUUID,
    pub iat: u64,
    pub exp: u64,
    pub jti: Uuid,
    pub name: String,
    pub email: String,
    pub dept_uuid: String,
    pub token_type: TokenType,
    pub is_super_admin: bool,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub sub: UserUUID,
    pub email: String,
    pub exp: u64,
    pub jti: Uuid,
}

impl From<Claims> for AuthUser {
    fn from(value: Claims) -> Self {
        Self {
            sub: value.sub,
            email: value.email,
            exp: value.exp,
            jti: value.jti,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct LogoutCommand {
    pub auth_user: AuthUser,
    pub session: Option<SessionContext>,
}

// ODIC

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub n: String,
    pub e: String,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}
// Microsoft JWKS Response
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

// Microsoft ID Token Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub aud: String,
    pub iss: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtHeader {
    pub kid: String,
    pub alg: String,
}

#[derive(Debug, Serialize)]
pub struct MicrosoftLoginUrlResponse {
    pub login_url: String,
    pub state: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct MicrosoftCallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftUserClaims {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub oid: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
}
