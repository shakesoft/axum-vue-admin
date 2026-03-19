use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use axum_extra::extract::CookieJar;
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use validator::Validate;

use crate::config::auth::REFRESH_TOKEN_EXPIRATION;
use crate::schemas::auth::{
    AuthResponse, AuthUser, Claims, Credentials, LogoutCommand, SessionContext, TokenPair,
};
use crate::schemas::response::ApiResponse;
use crate::{
    config::openapi::AUTH_TAG, errors::app_error::AppError, services::auth::basic::BasicAuthService,
};

fn with_refresh_cookie(jar: CookieJar, pair: &TokenPair) -> CookieJar {
    let refresh_cookie = Cookie::build(("refresh_token", pair.refresh_token.clone()))
        .path("/api/v1/auth")
        .max_age(CookieDuration::seconds(REFRESH_TOKEN_EXPIRATION))
        .same_site(SameSite::Strict)
        .http_only(true)
        .secure(true)
        .build();
    jar.add(refresh_cookie)
}

#[utoipa::path(
    post,
    path = "/login",
    request_body=Credentials,
    responses(( status=200, body=AuthResponse, description = "登陆成功"),
                (status=401, description = "认证失败"),),
    tag = AUTH_TAG
)]
pub async fn login(
    State(service): State<BasicAuthService>,
    jar: CookieJar,
    Json(dto): Json<Credentials>,
) -> Result<(CookieJar, ApiResponse<AuthResponse>), AppError> {
    dto.validate()?;
    let pair = service.authenticate(dto).await?;
    let cookie_jar = with_refresh_cookie(jar, &pair);
    let auth_response = AuthResponse {
        access_token: pair.access_token,
        username: pair.username,
    };
    Ok((
        cookie_jar,
        ApiResponse::success(auth_response, StatusCode::OK),
    ))
}

#[utoipa::path(
    post,
    path = "/refresh_token",
    responses(( status=200, body=AuthResponse, description = "刷新成功")),
    tag = AUTH_TAG
)]
pub async fn refresh_token(
    State(service): State<BasicAuthService>,
    jar: CookieJar,
) -> Result<(CookieJar, ApiResponse<AuthResponse>), AppError> {
    let refresh_token = jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or(crate::bad_request!("Refresh token not found".to_string()))?;
    let pair = service.refresh(SessionContext { refresh_token }).await?;
    let cookie_jar = with_refresh_cookie(jar, &pair);
    let auth_response = AuthResponse {
        access_token: pair.access_token,
        username: pair.username,
    };
    Ok((
        cookie_jar,
        ApiResponse::success(auth_response, StatusCode::OK),
    ))
}

#[utoipa::path(
    post,
    path = "/logout",
    responses(( status=200, description = "退出成功")),
    tag = AUTH_TAG,
    security(
          ("bearerAuth" = [])
        ),
)]
pub async fn logout(
    State(service): State<BasicAuthService>,
    jar: CookieJar,
    Extension(current_user): Extension<Claims>,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
    let session = jar.get("refresh_token").map(|cookie| SessionContext {
        refresh_token: cookie.value().to_string(),
    });
    service
        .logout(LogoutCommand {
            auth_user: AuthUser::from(current_user),
            session,
        })
        .await?;
    Ok((jar.remove(Cookie::from("refresh_token")), StatusCode::OK))
}
