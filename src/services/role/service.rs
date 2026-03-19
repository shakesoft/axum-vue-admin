// 角色管理路由

use crate::config::state::AppState;
use crate::errors::app_error::AppError;
use crate::schemas::auth::Claims;
use crate::schemas::cedar_policy::CedarContext;
use crate::schemas::role::{CreateRoleDto, QueryParams, RoleResponse, UpdateRoleDto};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use super::repository;


#[derive(Debug, Clone)]
pub struct RoleEntityInfo {
    pub role_uuid: String,
    pub role_name: String,
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn list_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<Value>, u64), AppError>;

    async fn get_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<RoleResponse, AppError>;

    async fn create_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateRoleDto,
    ) -> Result<RoleResponse, AppError>;

    async fn update_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
        dto: UpdateRoleDto,
    ) -> Result<RoleResponse, AppError>;

    async fn delete_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<(), AppError>;
}

#[async_trait]
impl RoleRepository for repository::impl_seaorm::RoleService {
    async fn list_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<Value>, u64), AppError> {
        repository::impl_seaorm::RoleService::list_roles(self, current_user, context, params).await
    }

    async fn get_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<RoleResponse, AppError> {
        repository::impl_seaorm::RoleService::get_role(self, current_user, context, role_uuid).await
    }

    async fn create_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        repository::impl_seaorm::RoleService::create_role(self, current_user, context, dto).await
    }

    async fn update_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
        dto: UpdateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        repository::impl_seaorm::RoleService::update_role(
            self,
            current_user,
            context,
            role_uuid,
            dto,
        )
        .await
    }

    async fn delete_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<(), AppError> {
        repository::impl_seaorm::RoleService::delete_role(self, current_user, context, role_uuid)
            .await
    }
}

#[derive(Clone)]
pub struct RoleService {
    repo: Arc<dyn RoleRepository>,
}

impl RoleService {
    pub fn new(app_state: AppState) -> Self {
        Self {
            repo: Arc::new(repository::impl_seaorm::RoleService::new(app_state)),
        }
    }

    pub async fn list_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<Value>, u64), AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "role_service",
            action = "list_roles",
            operator = %operator,
            "role list requested"
        );
        self.repo
            .list_roles(current_user, context, params)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "role_service",
                    action = "list_roles",
                    operator = %operator,
                    error = %err,
                    "role list failed"
                );
                err
            })
    }

    pub async fn get_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<RoleResponse, AppError> {
        let operator = current_user.sub.clone();
        let resource = role_uuid.clone();
        tracing::info!(
            module = "role_service",
            action = "get_role",
            operator = %operator,
            role_uuid = %resource,
            "role detail requested"
        );
        self.repo
            .get_role(current_user, context, role_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "role_service",
                    action = "get_role",
                    operator = %operator,
                    role_uuid = %resource,
                    error = %err,
                    "role detail failed"
                );
                err
            })
    }

    pub async fn create_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "role_service",
            action = "create_role",
            operator = %operator,
            "role create requested"
        );
        self.repo
            .create_role(current_user, context, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "role_service",
                    action = "create_role",
                    operator = %operator,
                    error = %err,
                    "role create failed"
                );
                err
            })
    }

    pub async fn update_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
        dto: UpdateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        let operator = current_user.sub.clone();
        let resource = role_uuid.clone();
        tracing::info!(
            module = "role_service",
            action = "update_role",
            operator = %operator,
            role_uuid = %resource,
            "role update requested"
        );
        self.repo
            .update_role(current_user, context, role_uuid, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "role_service",
                    action = "update_role",
                    operator = %operator,
                    role_uuid = %resource,
                    error = %err,
                    "role update failed"
                );
                err
            })
    }

    pub async fn delete_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<(), AppError> {
        let operator = current_user.sub.clone();
        let resource = role_uuid.clone();
        tracing::info!(
            module = "role_service",
            action = "delete_role",
            operator = %operator,
            role_uuid = %resource,
            "role delete requested"
        );
        self.repo
            .delete_role(current_user, context, role_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "role_service",
                    action = "delete_role",
                    operator = %operator,
                    role_uuid = %resource,
                    error = %err,
                    "role delete failed"
                );
                err
            })
    }
}
