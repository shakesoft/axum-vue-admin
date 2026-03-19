use crate::config::state::AppState;
use crate::errors::app_error::AppError;
use crate::schemas::auth::Claims;
use crate::schemas::cedar_policy::CedarContext;
use crate::schemas::department::{CreateDepartmentDto, DepartmentResponse, DeptTreeNode};
use crate::schemas::user::UserResponse;
use async_trait::async_trait;
use std::sync::Arc;
use super::repository;

#[async_trait]
pub trait DepartmentRepository: Send + Sync {
    async fn list_departments(
        &self,
        current_user: Claims,
        context: CedarContext,
    ) -> Result<Vec<DeptTreeNode>, AppError>;

    async fn create_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError>;

    async fn update_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError>;

    async fn delete_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<(), AppError>;

    async fn department_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<Vec<UserResponse>, AppError>;
}

#[async_trait]
impl DepartmentRepository for repository::impl_seaorm::DepartmentService {
    async fn list_departments(
        &self,
        current_user: Claims,
        context: CedarContext,
    ) -> Result<Vec<DeptTreeNode>, AppError> {
        repository::impl_seaorm::DepartmentService::list_departments(self, current_user, context)
            .await
    }

    async fn create_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError> {
        repository::impl_seaorm::DepartmentService::create_department(
            self,
            current_user,
            context,
            dto,
        )
        .await
    }

    async fn update_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError> {
        repository::impl_seaorm::DepartmentService::update_department(
            self,
            current_user,
            context,
            dept_uuid,
            dto,
        )
        .await
    }

    async fn delete_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<(), AppError> {
        repository::impl_seaorm::DepartmentService::delete_department(
            self,
            current_user,
            context,
            dept_uuid,
        )
        .await
    }

    async fn department_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<Vec<UserResponse>, AppError> {
        repository::impl_seaorm::DepartmentService::department_users(
            self,
            current_user,
            context,
            dept_uuid,
        )
        .await
    }
}

#[derive(Clone)]
pub struct DepartmentService {
    repo: Arc<dyn DepartmentRepository>,
}

impl DepartmentService {
    pub fn new(app_state: AppState) -> Self {
        Self {
            repo: Arc::new(repository::impl_seaorm::DepartmentService::new(app_state)),
        }
    }

    pub async fn list_departments(
        &self,
        current_user: Claims,
        context: CedarContext,
    ) -> Result<Vec<DeptTreeNode>, AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "department_service",
            action = "list_departments",
            operator = %operator,
            "department tree requested"
        );
        self.repo
            .list_departments(current_user, context)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "department_service",
                    action = "list_departments",
                    operator = %operator,
                    error = %err,
                    "department tree failed"
                );
                err
            })
    }

    pub async fn create_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError> {
        let operator = current_user.sub.clone();
        tracing::info!(
            module = "department_service",
            action = "create_department",
            operator = %operator,
            "department create requested"
        );
        self.repo
            .create_department(current_user, context, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "department_service",
                    action = "create_department",
                    operator = %operator,
                    error = %err,
                    "department create failed"
                );
                err
            })
    }

    pub async fn update_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
        dto: CreateDepartmentDto,
    ) -> Result<DepartmentResponse, AppError> {
        let operator = current_user.sub.clone();
        let resource = dept_uuid.clone();
        tracing::info!(
            module = "department_service",
            action = "update_department",
            operator = %operator,
            dept_uuid = %resource,
            "department update requested"
        );
        self.repo
            .update_department(current_user, context, dept_uuid, dto)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "department_service",
                    action = "update_department",
                    operator = %operator,
                    dept_uuid = %resource,
                    error = %err,
                    "department update failed"
                );
                err
            })
    }

    pub async fn delete_department(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<(), AppError> {
        let operator = current_user.sub.clone();
        let resource = dept_uuid.clone();
        tracing::info!(
            module = "department_service",
            action = "delete_department",
            operator = %operator,
            dept_uuid = %resource,
            "department delete requested"
        );
        self.repo
            .delete_department(current_user, context, dept_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "department_service",
                    action = "delete_department",
                    operator = %operator,
                    dept_uuid = %resource,
                    error = %err,
                    "department delete failed"
                );
                err
            })
    }

    pub async fn department_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        dept_uuid: String,
    ) -> Result<Vec<UserResponse>, AppError> {
        let operator = current_user.sub.clone();
        let resource = dept_uuid.clone();
        tracing::info!(
            module = "department_service",
            action = "department_users",
            operator = %operator,
            dept_uuid = %resource,
            "department users requested"
        );
        self.repo
            .department_users(current_user, context, dept_uuid)
            .await
            .map_err(|err| {
                tracing::error!(
                    module = "department_service",
                    action = "department_users",
                    operator = %operator,
                    dept_uuid = %resource,
                    error = %err,
                    "department users query failed"
                );
                err
            })
    }
}
