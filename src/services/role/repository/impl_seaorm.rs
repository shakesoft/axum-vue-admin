use crate::common::cedar_utils::{AuthAction, ResourceType};
use crate::common::entities::{get_role_entities};
use crate::config::state::AppState;
use crate::entity::{group_roles, roles, user_group_members, user_roles, users};
use crate::errors::app_error::AppError;
use crate::schemas::auth::Claims;
use crate::schemas::cedar_policy::CedarContext;
use crate::schemas::role::{
    CreateRoleDto, QueryParams, RoleEntityInfo, RoleResponse, UpdateRoleDto,
};
use crate::schemas::user::UserUUID;
use crate::{bad_request, conflict, not_found};
use cedar_policy::{
    Entities, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression, Schema,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QuerySelect, QueryTrait, Select, Set, TransactionTrait,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use tracing::debug;
use uuid::Uuid;

#[derive(Clone)]
pub struct RoleService {
    app_state: AppState,
}

impl RoleService {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }

    pub async fn list_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<Value>, u64), AppError> {
        self.app_state
            .auth_service
            .check_permission(
                &current_user.sub,
                context,
                AuthAction::ViewRole,
                ResourceType::Role(None),
            )
            .await?;

        let requested_fields: HashSet<String> = params
            .fields
            .map(|f| f.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| {
                ["role_uuid", "role_name", "description", "created_at"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });
        debug!("requested_fields: {:?}", requested_fields);
        // 构建基础查询
        let mut select = roles::Entity::find().select_only();

        // 应用通用过滤条件
        if let Some(role_name) = &params.name {
            select = select.filter(roles::Column::RoleName.contains(role_name));
        }

        // 动态添加字段
        for field in &requested_fields {
            select = match field.as_str() {
                "id" => select.column(roles::Column::RoleUuid),
                "uuid" => select.column(roles::Column::RoleUuid),
                "role_uuid" => select.column(roles::Column::RoleUuid),
                "name" => select.column(roles::Column::RoleName),
                "role_name" => select.column(roles::Column::RoleName),
                "description" => select.column(roles::Column::Description),
                "created_at" => select.column(roles::Column::CreatedAt),
                _ => select, // 忽略未知字段
            };
        }

        let paginator = select
            .into_model::<RoleResponse>()
            .paginate(self.app_state.db.as_ref(), params.page_size);

        let total = paginator.num_items().await?;
        let results = paginator.fetch_page(params.page - 1).await?;

        // 安全的序列化
        let response = results
            .into_iter()
            .map(|role| serde_json::to_value(role))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((response, total))
    }

    pub async fn get_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<RoleResponse, AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let es = get_role_entities(
            self.app_state.db.as_ref(),
            self.app_state.cache_service.as_ref(),
            &vec![role_uuid.clone()],
            &schema,
        )
        .await?;

        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::ViewRole,
                ResourceType::Role(Some(role_uuid.clone())),
                es,
            )
            .await?;

        let role = roles::Entity::find()
            .column_as(roles::Column::RoleUuid, "id")
            .column_as(roles::Column::RoleName, "name")
            .column(roles::Column::Description)
            .column(roles::Column::CreatedAt)
            .filter(roles::Column::RoleUuid.eq(role_uuid))
            .into_model::<RoleResponse>()
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("Role Not Found".to_string()))?;
        Ok(role)
    }

    pub async fn create_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        self.app_state
            .auth_service
            .check_permission(
                &current_user.sub,
                context,
                AuthAction::CreateRole,
                ResourceType::Role(None),
            )
            .await?;

        if roles::Entity::find()
            .filter(roles::Column::RoleName.eq(&dto.name))
            .one(self.app_state.db.as_ref())
            .await?
            .is_some()
        {
            return Err(conflict!("Role already exists".to_string()));
        }

        let role = roles::ActiveModel {
            role_uuid: Set(Uuid::new_v4().to_string()),
            role_name: Set(dto.name),
            description: Set(Some(dto.description)),
            ..Default::default()
        };

        let role = role.insert(self.app_state.db.as_ref()).await?;
        Ok(RoleResponse::from(role))
    }

    pub async fn update_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
        dto: UpdateRoleDto,
    ) -> Result<RoleResponse, AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let es = get_role_entities(
            self.app_state.db.as_ref(),
            self.app_state.cache_service.as_ref(),
            &vec![role_uuid.clone()],
            &schema,
        )
        .await?;
        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::UpdateRole,
                ResourceType::Role(Some(role_uuid.clone())),
                es,
            )
            .await?;

        let mut role: roles::ActiveModel = roles::Entity::find()
            .filter(roles::Column::RoleUuid.eq(&role_uuid))
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("Role Not Found".to_string()))?
            .into();

        if let Some(name) = dto.name {
            role.role_name = Set(name);
        }

        if let Some(description) = dto.description {
            role.description = Set(Some(description));
        }

        let role = role.update(self.app_state.db.as_ref()).await?;
        Ok(RoleResponse::from(role))
    }

    pub async fn delete_role(
        &self,
        current_user: Claims,
        context: CedarContext,
        role_uuid: String,
    ) -> Result<(), AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let es = get_role_entities(
            self.app_state.db.as_ref(),
            self.app_state.cache_service.as_ref(),
            &vec![role_uuid.clone()],
            &schema,
        )
        .await?;

        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::DeleteRole,
                ResourceType::Role(Some(role_uuid.clone())),
                es,
            )
            .await?;

        roles::Entity::delete_many()
            .filter(roles::Column::RoleUuid.eq(role_uuid))
            .exec(self.app_state.db.as_ref())
            .await?;

        Ok(())
    }
}
