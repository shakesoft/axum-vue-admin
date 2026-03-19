use crate::entity::roles::Model as RoleModel;
use chrono::{DateTime, Utc};
use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

fn default_page() -> u64 {
    1
}

fn default_page_size() -> u64 {
    10
}

#[derive(Debug, Deserialize, IntoParams, Validate, Clone)]
#[allow(dead_code)]
pub struct QueryParams {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_page_size", alias = "pageSize")]
    pub page_size: u64,
    pub name: Option<String>,
    pub fields: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRoleDto {
    #[validate(length(min = 3, max = 100))]
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRoleDto {
    #[validate(length(min = 3, max = 100))]
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, FromQueryResult)]
pub struct RoleResponse {
    #[serde(skip_serializing_if = "Option::is_none", rename = "uuid")]
    pub role_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "name")]
    pub role_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

impl From<RoleModel> for RoleResponse {
    fn from(role: RoleModel) -> Self {
        Self {
            role_uuid: Some(role.role_uuid),
            created_at: Some(role.created_at),
            role_name: Some(role.role_name),
            description: role.description,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoleEntityInfo {
    pub role_uuid: String,
    pub role_name: String,
}