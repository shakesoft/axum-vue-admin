use crate::schemas::response::ApiResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken;
use std::error;
use std::num::ParseIntError;
use std::str::Utf8Error;
use openssl::base64;
use tracing::error;

#[derive(Debug)]
pub enum ErrorType {
    BadRequest,           // 400 - 客户端请求错误
    Unauthorized,         // 401 - 未认证
    Forbidden,            // 403 - 无权限
    NotFound,             // 404 - 资源不存在
    Conflict,             // 409 - 资源冲突
    InternalServerError,  // 500 - 服务器内部错误
    TokenValidationError, // 500 SSO认证错误
}

// 自定义错误结构
#[derive(Debug)]
pub struct AppError {
    pub error_type: ErrorType,
    pub source: anyhow::Error,
}

impl AppError {
    pub fn new(error_type: ErrorType, source: anyhow::Error) -> Self {
        Self { error_type, source }
    }

    pub fn bad_request<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::BadRequest, err.into())
    }

    pub fn unauthorized<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::Unauthorized, err.into())
    }

    pub fn forbidden<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::Forbidden, err.into())
    }

    pub fn not_found<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::NotFound, err.into())
    }

    pub fn conflict<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::Conflict, err.into())
    }

    pub fn token_validation_error<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::TokenValidationError, err.into())
    }

    pub fn internal_server_error<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::new(ErrorType::InternalServerError, err.into())
    }

    pub fn status_code(&self) -> StatusCode {
        match self.error_type {
            ErrorType::BadRequest => StatusCode::BAD_REQUEST,
            ErrorType::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorType::Forbidden => StatusCode::FORBIDDEN,
            ErrorType::NotFound => StatusCode::NOT_FOUND,
            ErrorType::Conflict => StatusCode::CONFLICT,
            ErrorType::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorType::TokenValidationError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

// 只保留必要的From实现
impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::bad_request(anyhow::Error::from(err))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::bad_request(anyhow::Error::from(err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::internal_server_error(value)
    }
}

// 数据库错误默认为内部服务器错误
impl From<sea_orm::DbErr> for AppError {
    fn from(err: sea_orm::DbErr) -> Self {
        tracing::error!("Database error: {:?}", err);
        let sqlx_error = match &err {
            sea_orm::DbErr::Query(sea_orm::RuntimeErr::SqlxError(e)) => Some(e),
            sea_orm::DbErr::Exec(sea_orm::RuntimeErr::SqlxError(e)) => Some(e),
            _ => None,
        };

        if let Some(sqlx_err) = sqlx_error {
            if let sqlx::Error::Database(db_err) = sqlx_err {
                if db_err.is_unique_violation() {
                    return Self::conflict(anyhow::Error::msg("The data already exists."));
                }

                if db_err.is_foreign_key_violation() {
                    return Self::not_found(anyhow::Error::msg(
                        "The associated resource does not exist.",
                    ));
                }
            }
        }

        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        error!("jsonwebtoken error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

// Redis错误默认为内部服务器错误
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!("Redis error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

// PasswordHashError 处理
impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        tracing::error!("Password hash error: {:?}", err);
        Self::internal_server_error(anyhow::anyhow!(err))
    }
}

// Cedar policy 相关错误
impl From<cedar_policy::entities_errors::EntitiesError> for AppError {
    fn from(err: cedar_policy::entities_errors::EntitiesError) -> Self {
        tracing::warn!("Cedar entities error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::SchemaError> for AppError {
    fn from(err: cedar_policy::SchemaError) -> Self {
        tracing::error!("Cedar schema error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::ParseErrors> for AppError {
    fn from(err: cedar_policy::ParseErrors) -> Self {
        tracing::warn!("Cedar parse error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::CedarSchemaError> for AppError {
    fn from(err: cedar_policy::CedarSchemaError) -> Self {
        tracing::error!("Cedar schema error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::RequestValidationError> for AppError {
    fn from(err: cedar_policy::RequestValidationError) -> Self {
        tracing::warn!("Cedar request validation error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::ContextJsonError> for AppError {
    fn from(err: cedar_policy::ContextJsonError) -> Self {
        tracing::warn!("Cedar context JSON error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::EntityAttrEvaluationError> for AppError {
    fn from(err: cedar_policy::EntityAttrEvaluationError) -> Self {
        tracing::warn!("Cedar context JSON error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::RestrictedExpressionParseError> for AppError {
    fn from(err: cedar_policy::RestrictedExpressionParseError) -> Self {
        tracing::warn!("Cedar context JSON error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<cedar_policy::PolicySetError> for AppError {
    fn from(err: cedar_policy::PolicySetError) -> Self {
        tracing::warn!("Cedar policy set error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<core::convert::Infallible> for AppError {
    fn from(err: core::convert::Infallible) -> Self {
        tracing::warn!("Cedar context JSON error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(err: tokio::task::JoinError) -> Self {
        tracing::error!("Tokio join error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<askama::Error> for AppError {
    fn from(err: askama::Error) -> Self {
        tracing::error!("askama error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<lettre::transport::smtp::Error> for AppError {
    fn from(err: lettre::transport::smtp::Error) -> Self {
        tracing::error!("lettre error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}

impl From<ParseIntError> for AppError {
    fn from(err: ParseIntError) -> Self {
        tracing::error!("Parse int error: {:?}", err);
        Self::internal_server_error(anyhow::Error::from(err))
    }
}


impl From<std::string::FromUtf8Error> for AppError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::internal_server_error(anyhow::Error::from(value))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // 记录错误信息
        match self.error_type {
            ErrorType::InternalServerError => {
                tracing::error!("Internal server error: {:?}", self.source);

                // 开发环境显示详细错误，生产环境隐藏
                #[cfg(debug_assertions)]
                let error_message = format!("{:?}", self.source);

                #[cfg(not(debug_assertions))]
                let error_message = "Internal Server Error".to_string();

                let response = ApiResponse::<()>::error(status.as_u16(), error_message);
                (status, Json(response)).into_response()
            }
            _ => {
                tracing::warn!("Client error ({}): {}", status.as_u16(), self.source);
                let response = ApiResponse::<()>::error(status.as_u16(), self.source.to_string());
                (status, Json(response)).into_response()
            }
        }
    }
}

#[macro_export]
macro_rules! bad_request {
    ($msg:expr) => {
        AppError::bad_request(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::bad_request(anyhow::anyhow!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! unauthorized {
    ($msg:expr) => {
        AppError::unauthorized(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::unauthorized(anyhow::anyhow!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! forbidden {
    ($msg:expr) => {
        AppError::forbidden(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::forbidden(anyhow::anyhow!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! not_found {
    ($msg:expr) => {
        AppError::not_found(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::not_found(anyhow::anyhow!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! conflict {
    ($msg:expr) => {
        AppError::conflict(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::conflict(anyhow::anyhow!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! internal_server_error {
    ($msg:expr) => {
        AppError::internal_server_error(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::internal_server_error(anyhow::anyhow!($fmt, $($arg)*))
    }
}

#[macro_export]
macro_rules! token_validation_error {
    ($msg:expr) => {
        AppError::token_validation_error(anyhow::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        AppError::token_validation_error(anyhow::anyhow!($fmt, $($arg)*))
    }
}
