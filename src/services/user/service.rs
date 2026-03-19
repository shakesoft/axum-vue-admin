
use crate::config::state::AppState;
use crate::errors::app_error::AppError;
use crate::schemas::auth::Claims;
use crate::schemas::cedar_policy::CedarContext;
use crate::schemas::user::{
    AssignRoleDto, CreateUserDto, QueryParams, UpdateUserDto, UserResponse, UserRoleInfo,
};
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::sync::Arc;

use super::repository;


#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn list_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<JsonValue>, u64), AppError>;

    async fn get_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<UserResponse, AppError>;

    async fn create_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateUserDto,
    ) -> Result<UserResponse, AppError>;

    async fn update_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: UpdateUserDto,
    ) -> Result<UserResponse, AppError>;

    async fn delete_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<(), AppError>;

    async fn user_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<Vec<UserRoleInfo>, AppError>;

    async fn assign_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: AssignRoleDto,
    ) -> Result<(), AppError>;

    async fn revoke_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        role_uuid: String,
    ) -> Result<(), AppError>;
}

#[async_trait]
impl UserRepository for repository::impl_seaorm::UserService {
    async fn list_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<JsonValue>, u64), AppError> {
        repository::impl_seaorm::UserService::list_users(self, current_user, context, params).await
    }

    async fn get_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<UserResponse, AppError> {
        repository::impl_seaorm::UserService::get_user(self, current_user, context, user_uuid).await
    }

    async fn create_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateUserDto,
    ) -> Result<UserResponse, AppError> {
        repository::impl_seaorm::UserService::create_user(self, current_user, context, dto).await
    }

    async fn update_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: UpdateUserDto,
    ) -> Result<UserResponse, AppError> {
        repository::impl_seaorm::UserService::update_user(
            self,
            current_user,
            context,
            user_uuid,
            dto,
        )
        .await
    }

    async fn delete_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<(), AppError> {
        repository::impl_seaorm::UserService::delete_user(self, current_user, context, user_uuid)
            .await
    }

    async fn user_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<Vec<UserRoleInfo>, AppError> {
        repository::impl_seaorm::UserService::user_roles(self, current_user, context, user_uuid)
            .await
    }

    async fn assign_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: AssignRoleDto,
    ) -> Result<(), AppError> {
        repository::impl_seaorm::UserService::assign_roles(
            self,
            current_user,
            context,
            user_uuid,
            dto,
        )
        .await
    }

    async fn revoke_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        role_uuid: String,
    ) -> Result<(), AppError> {
        repository::impl_seaorm::UserService::revoke_roles(
            self,
            current_user,
            context,
            user_uuid,
            role_uuid,
        )
        .await
    }
}

#[derive(Clone)]
pub struct UserService {
    repo: Arc<dyn UserRepository>,
}

impl UserService {
    pub fn new(app_state: AppState) -> Self {
        Self {
            repo: Arc::new(repository::impl_seaorm::UserService::new(app_state)),
        }
    }

    pub async fn list_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<JsonValue>, u64), AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "user_service",
            action = "list_users",
            operator = %operator,
            "user list requested"
        );
        self.repo
            .list_users(current_user, context, params)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "list_users",
                    operator = %operator,
                    error = %err,
                    "user list failed"
                );
                err
            })
    }

    pub async fn get_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<UserResponse, AppError> {
        let operator = current_user.sub.clone();
        let resource = user_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "get_user",
            operator = %operator,
            user_uuid = %resource,
            "user detail requested"
        );
        self.repo
            .get_user(current_user, context, user_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "get_user",
                    operator = %operator,
                    user_uuid = %resource,
                    error = %err,
                    "user detail failed"
                );
                err
            })
    }

    pub async fn create_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateUserDto,
    ) -> Result<UserResponse, AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "user_service",
            action = "create_user",
            operator = %operator,
            "user create requested"
        );
        self.repo
            .create_user(current_user, context, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "create_user",
                    operator = %operator,
                    error = %err,
                    "user create failed"
                );
                err
            })
    }

    pub async fn update_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: UpdateUserDto,
    ) -> Result<UserResponse, AppError> {
        let operator = current_user.sub.clone();
        let resource = user_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "update_user",
            operator = %operator,
            user_uuid = %resource,
            "user update requested"
        );
        self.repo
            .update_user(current_user, context, user_uuid, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "update_user",
                    operator = %operator,
                    user_uuid = %resource,
                    error = %err,
                    "user update failed"
                );
                err
            })
    }

    pub async fn delete_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<(), AppError> {
        let operator = current_user.sub.clone();
        let resource = user_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "delete_user",
            operator = %operator,
            user_uuid = %resource,
            "user delete requested"
        );
        self.repo
            .delete_user(current_user, context, user_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "delete_user",
                    operator = %operator,
                    user_uuid = %resource,
                    error = %err,
                    "user delete failed"
                );
                err
            })
    }

    pub async fn user_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<Vec<UserRoleInfo>, AppError> {
        let operator = current_user.sub.clone();
        let resource = user_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "user_roles",
            operator = %operator,
            user_uuid = %resource,
            "user roles requested"
        );
        self.repo
            .user_roles(current_user, context, user_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "user_roles",
                    operator = %operator,
                    user_uuid = %resource,
                    error = %err,
                    "user roles query failed"
                );
                err
            })
    }

    pub async fn assign_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: AssignRoleDto,
    ) -> Result<(), AppError> {
        let operator = current_user.sub.clone();
        let resource = user_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "assign_roles",
            operator = %operator,
            user_uuid = %resource,
            "assign user roles requested"
        );
        self.repo
            .assign_roles(current_user, context, user_uuid, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "assign_roles",
                    operator = %operator,
                    user_uuid = %resource,
                    error = %err,
                    "assign user roles failed"
                );
                err
            })
    }

    pub async fn revoke_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        role_uuid: String,
    ) -> Result<(), AppError> {
        let operator = current_user.sub.clone();
        let user_resource = user_uuid.clone();
        let role_resource = role_uuid.clone();
        tracing::info!(
            module = "user_service",
            action = "revoke_roles",
            operator = %operator,
            user_uuid = %user_resource,
            role_uuid = %role_resource,
            "revoke user role requested"
        );
        self.repo
            .revoke_roles(current_user, context, user_uuid, role_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "user_service",
                    action = "revoke_roles",
                    operator = %operator,
                    user_uuid = %user_resource,
                    role_uuid = %role_resource,
                    error = %err,
                    "revoke user role failed"
                );
                err
            })
    }
}
