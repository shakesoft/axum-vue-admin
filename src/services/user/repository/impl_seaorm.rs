use crate::common::cedar_utils::{
    AuthAction, ResourceType
    ,
};
use crate::common::crypto::hash_password;
use crate::config::state::AppState;
use crate::entity::{
    departments, group_roles, roles, user_group_members, user_groups, user_roles, users,
};
use crate::errors::app_error::AppError;
use crate::schemas::auth::Claims;
use crate::schemas::cedar_policy::CedarContext;
use crate::schemas::user::{
    AssignRoleDto, CreateUserDto, DeptResponse, DirectRole, GroupResponse, GroupRole, QueryParams,
    UpdateUserDto, UserResponse, UserRoleInfo, UserUUID,
};
use crate::{conflict, not_found};
use cedar_policy::Entities;
use sea_orm::sea_query::Query;
use sea_orm::JoinType::InnerJoin;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, JoinType,
    ModelTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait
    , Set, TransactionTrait,
};
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use crate::common::entities::{get_dept_entities, get_group_entities, get_role_entities, get_user_entities};

const ROLE_SOURCE_DIRECT: &str = "direct";
const ROLE_SOURCE_GROUP: &str = "group";

#[derive(Clone)]
pub struct UserService {
    app_state: AppState,
}

impl UserService {
    pub fn new(app_state: AppState) -> Self {
        Self {
            app_state: app_state.clone(),
        }
    }

    pub async fn list_users(
        &self,
        current_user: Claims,
        context: CedarContext,
        params: QueryParams,
    ) -> Result<(Vec<JsonValue>, u64), AppError> {
        self.app_state
            .auth_service
            .check_permission(
                &current_user.sub,
                context,
                AuthAction::ViewUser,
                ResourceType::User(None),
            )
            .await?;

        let db = self.app_state.db.as_ref();

        // 如果 fields 参数为空，默认返回所有核心字段。
        let requested_fields: HashSet<String> = params
            .fields
            .map(|f| f.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| {
                // 定义默认返回的字段
                [
                    "user_uuid",
                    "username",
                    "alias",
                    "email",
                    "phone",
                    "is_active",
                    "dept",
                    "groups",
                    "avatar",
                    "last_login",
                ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });

        let mut query = users::Entity::find();

        // 应用其他过滤条件
        if let Some(username) = params.username {
            query = query.filter(users::Column::Username.contains(username));
        }
        if let Some(email) = params.email {
            query = query.filter(users::Column::Email.contains(email));
        }
        if let Some(dept_uuid) = params.dept_uuid {
            let dept_id = departments::Entity::find()
                .select_only()
                .column(departments::Column::DeptId)
                .filter(departments::Column::DeptUuid.eq(dept_uuid))
                .into_tuple::<i32>()
                .one(self.app_state.db.as_ref())
                .await?
                .ok_or(not_found!("department not found"))?;
            query = query.filter(users::Column::DeptId.eq(dept_id));
        }

        // 根据请求的字段动态选择列
        let mut select_query = query.select_only();
        let mut needs_dept_join = false;

        select_query = select_query
            .column(users::Column::UserId)
            .column_as(users::Column::UserUuid, "uuid");

        for field in &requested_fields {
            select_query = match field.as_str() {
                "uuid" | "user_id" => select_query,
                "username" => select_query.column(users::Column::Username),
                "alias" => select_query.column(users::Column::Alias),
                "email" => select_query.column(users::Column::Email),
                "phone" => select_query.column(users::Column::Phone),
                "is_active" => select_query.column(users::Column::IsActive),
                "avatar" => select_query.column(users::Column::Avatar),
                "last_login" => select_query.column(users::Column::LastLogin),
                "dept" => {
                    needs_dept_join = true;
                    select_query
                        .column_as(departments::Column::DeptUuid, "dept_uuid")
                        .column_as(departments::Column::Name, "dept_name")
                }
                "groups" => select_query, // groups 需要单独查询，这里先忽略
                _ => select_query,        // 忽略不认识的字段
            };
        }

        // 如果需要部门信息，才添加 JOIN
        if needs_dept_join {
            select_query =
                select_query.join(JoinType::LeftJoin, users::Relation::Departments.def());
        }
        select_query = select_query.order_by_desc(users::Column::LastLogin);
        // 执行分页查询，并将结果转换为 JSON
        let paginator = select_query.into_json().paginate(db, params.page_size);
        let total = paginator.num_items().await?;
        let page_index = if params.page > 0 { params.page - 1 } else { 0 };
        let mut users_json: Vec<JsonValue> = paginator.fetch_page(page_index).await?;

        // 按需获取关联的 `groups` 数据
        let mut user_groups_map: HashMap<String, JsonValue> = HashMap::new();

        if requested_fields.contains("groups") && !users_json.is_empty() {
            let user_ids: Vec<i32> = users_json
                .iter()
                .filter_map(|u| {
                    u.get("user_id")
                        .and_then(|id| id.as_i64())
                        .map(|id| id as i32)
                })
                .collect();

            if !user_ids.is_empty() {
                let user_group_relations = user_group_members::Entity::find()
                    .find_also_related(user_groups::Entity)
                    .filter(user_group_members::Column::UserId.is_in(user_ids.clone()))
                    .all(db)
                    .await?;

                let id_to_uuid_map: HashMap<i32, String> = users::Entity::find()
                    .select_only()
                    .columns([users::Column::UserId, users::Column::UserUuid])
                    .filter(users::Column::UserId.is_in(user_ids))
                    .into_tuple::<(i32, String)>()
                    .all(db)
                    .await?
                    .into_iter()
                    .collect();

                let mut grouped_by_uuid: HashMap<String, Vec<JsonValue>> = HashMap::new();
                for (relation, group_opt) in user_group_relations {
                    if let (Some(group), Some(uuid)) =
                        (group_opt, id_to_uuid_map.get(&relation.user_id))
                    {
                        grouped_by_uuid
                            .entry(uuid.clone())
                            .or_default()
                            .push(json!({
                                "uuid": group.user_group_uuid,
                                "name": group.name,
                            }));
                    }
                }
                // 将 Vec<JsonValue> 转换为单个 JsonValue::Array
                for (uuid, groups) in grouped_by_uuid {
                    user_groups_map.insert(uuid, JsonValue::Array(groups));
                }
            }
        }

        // 遍历查询结果，构建 dept 对象，并合并 groups 信息
        for user_val in users_json.iter_mut() {
            if let Some(user_obj) = user_val.as_object_mut() {
                if !requested_fields.contains("user_id") {
                    user_obj.remove("user_id");
                }
                // 组装 dept 对象
                if needs_dept_join {
                    let dept_uuid = user_obj.remove("dept_uuid");
                    let dept_name = user_obj.remove("dept_name");

                    let dept_json = match (dept_uuid, dept_name) {
                        (Some(id), Some(name)) if !id.is_null() => {
                            json!({"uuid": id, "name": name})
                        }
                        _ => JsonValue::Null,
                    };
                    user_obj.insert("dept".to_string(), dept_json);
                }

                // 合并 groups 信息
                if requested_fields.contains("groups") {
                    let user_uuid = user_obj
                        .get("uuid")
                        .and_then(|u| u.as_str())
                        .map(|s| s.to_string());

                    if let Some(uuid) = user_uuid {
                        let groups_json = user_groups_map.get(&uuid).cloned().unwrap_or(json!([]));
                        user_obj.insert("groups".to_string(), groups_json);
                    }
                }

                // 坑爹的MYSQL, BOOL要单独处理
                if requested_fields.contains("is_active") {
                    if let Some(is_active_val) = user_obj.get_mut("is_active") {
                        if let Some(num) = is_active_val.as_i64() {
                            *is_active_val = json!(num != 0);
                        }
                    }
                }
            }
        }

        Ok((users_json, total))
    }

    pub async fn get_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<UserResponse, AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let es = get_user_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            user_uuid.clone(), 
            &schema).await?;
        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::ViewUser,
                ResourceType::User(Some(user_uuid.clone())),
                es,
            )
            .await?;

        // 查询用户及其部门信息
        let user_with_dept = users::Entity::find()
            .filter(users::Column::UserUuid.eq(user_uuid))
            .find_also_related(departments::Entity)
            .one(self.app_state.db.as_ref())
            .await?;

        if let Some((user, dept)) = user_with_dept {
            // 查询该用户的所有用户组
            let user_groups = user_groups::Entity::find()
                .join(InnerJoin, user_groups::Relation::UserGroupMembers.def())
                .filter(user_group_members::Column::UserId.eq(user.user_id))
                .all(self.app_state.db.as_ref())
                .await?;

            let user_response = UserResponse {
                uuid: user.user_uuid,
                username: user.username,
                alias: user.alias,
                email: user.email,
                phone: user.phone,
                is_active: user.is_active,
                dept: dept.map(|d| DeptResponse {
                    uuid: d.dept_uuid,
                    name: d.name,
                }),
                groups: user_groups
                    .into_iter()
                    .map(|g| GroupResponse {
                        user_group_uuid: g.user_group_uuid,
                        name: g.name,
                    })
                    .collect(),
                avatar: user.avatar,
                last_login: user.last_login,
            };

            Ok(user_response)
        } else {
            Err(not_found!("User not found".to_string()))
        }
    }

    pub async fn create_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        dto: CreateUserDto,
    ) -> Result<UserResponse, AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let dept_es = get_dept_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            &dto.dept, 
            &schema).await?;
        let group_es = get_group_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            &dto.groups, 
            &schema
        ).await?;
        let merged_es = dept_es.add_entities(group_es.clone(), Some(&schema))?;
        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context.clone(),
                AuthAction::CreateUser,
                ResourceType::User(None),
                merged_es.clone(),
            )
            .await?;

        for group_id in dto.groups.clone() {
            self.app_state
                .auth_service
                .check_permission_with_entities(
                    &current_user.sub,
                    context.clone(),
                    AuthAction::CreateUser,
                    ResourceType::Group(Some(group_id)),
                    group_es.clone(),
                )
                .await?;
        }

        let txn = self.app_state.db.begin().await?;

        if users::Entity::find()
            .filter(users::Column::Email.eq(&dto.email))
            .one(&txn)
            .await?
            .is_some()
        {
            return Err(conflict!("Username or email already exists".to_string(),));
        }

        let hashed_password = hash_password(&dto.password)?;

        let dept_id = departments::Entity::find()
            .select_only()
            .column(departments::Column::DeptId)
            .filter(departments::Column::DeptUuid.eq(dto.dept))
            .into_tuple::<i32>()
            .one(&txn)
            .await?
            .ok_or(not_found!("No dept"))?;

        let user = users::ActiveModel {
            user_uuid: Set(Uuid::new_v4().to_string()),
            username: Set(dto.username),
            email: Set(dto.email),
            password: Set(hashed_password),
            dept_id: Set(dept_id),
            alias: Set(dto.alias),
            phone: Set(dto.phone),
            is_active: Set(dto.is_active),
            ..Default::default()
        };

        let user = user.insert(&txn).await?;

        let user_group_ids = user_groups::Entity::find()
            .select_only()
            .column(user_groups::Column::UserGroupId)
            .filter(user_groups::Column::UserGroupUuid.is_in(dto.groups))
            .into_tuple::<i32>()
            .all(&txn)
            .await?;

        let user_groups = user_group_ids
            .into_iter()
            .map(|group_id| user_group_members::ActiveModel {
                user_id: Set(user.user_id),
                group_id: Set(group_id),
                ..Default::default()
            })
            .collect::<Vec<_>>();

        user_group_members::Entity::insert_many(user_groups)
            .exec(&txn)
            .await?;

        txn.commit().await?;

        Ok(UserResponse::from(user))
    }

    pub async fn update_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: UpdateUserDto,
    ) -> Result<UserResponse, AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;

        let mut entities = Entities::empty();
        let user_es = get_user_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            user_uuid.clone(), 
            &schema
        ).await?;
        entities = entities.add_entities(user_es, Some(&schema))?;

        let mut target_dept_id: Option<i32> = None;
        if let Some(dept_uuid) = dto.dept.clone() {
            let dept_es = get_dept_entities(
                self.app_state.db.as_ref(),
                self.app_state.cache_service.as_ref(),
                &dept_uuid, 
                &schema
            ).await?;
            entities = entities.add_entities(dept_es, Some(&schema))?;

            let dept_id = departments::Entity::find()
                .select_only()
                .column(departments::Column::DeptId)
                .filter(departments::Column::DeptUuid.eq(dept_uuid))
                .into_tuple::<i32>()
                .one(self.app_state.db.as_ref())
                .await?
                .ok_or(not_found!("Department not found"))?;
            target_dept_id = Some(dept_id);
        }

        let mut target_group_ids: Option<Vec<i32>> = None;
        if let Some(group_uuids) = &dto.groups {
            if group_uuids.is_empty() {
                target_group_ids = Some(vec![]);
            } else {
                let group_es = get_group_entities(
                    self.app_state.db.as_ref(),
                    self.app_state.cache_service.as_ref(),
                    group_uuids, 
                    &schema
                ).await?;
                entities = entities.add_entities(group_es, Some(&schema))?;

                let group_ids = user_groups::Entity::find()
                    .select_only()
                    .column(user_groups::Column::UserGroupId)
                    .filter(user_groups::Column::UserGroupUuid.is_in(group_uuids))
                    .into_tuple::<i32>()
                    .all(self.app_state.db.as_ref())
                    .await?;

                if group_ids.len() != group_uuids.len() {
                    return Err(not_found!("One or more user group are invalid"));
                }
                target_group_ids = Some(group_ids);
            }
        }

        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context.clone(),
                AuthAction::UpdateUser,
                ResourceType::User(Some(user_uuid.clone())),
                entities.clone(),
            )
            .await?;

        if let Some(dept_uuid) = &dto.dept {
            self.app_state
                .auth_service
                .check_permission_with_entities(
                    &current_user.sub,
                    context.clone(),
                    AuthAction::UpdateUser,
                    ResourceType::Department(Some(dept_uuid.clone())),
                    entities.clone(),
                )
                .await?;
        }

        if let Some(group_uuids) = &dto.groups {
            for group_uuid in group_uuids {
                self.app_state
                    .auth_service
                    .check_permission_with_entities(
                        &current_user.sub,
                        context.clone(),
                        AuthAction::UpdateUser,
                        ResourceType::Group(Some(group_uuid.clone())),
                        entities.clone(),
                    )
                    .await?;
            }
        }

        let txn = self.app_state.db.begin().await?;

        let mut user: users::ActiveModel = users::Entity::find()
            .filter(users::Column::UserUuid.eq(&user_uuid))
            .one(&txn)
            .await?
            .ok_or_else(|| not_found!("User not found"))?
            .into();

        if let Some(email) = dto.email {
            user.email = Set(email);
        }
        if let Some(username) = dto.username {
            user.username = Set(username);
        }
        if let Some(alias) = dto.alias {
            user.alias = Set(Some(alias));
        }
        if let Some(phone) = dto.phone {
            user.phone = Set(Some(phone));
        }
        if let Some(is_active) = dto.is_active {
            user.is_active = Set(is_active);
        }

        if let Some(dept_id) = target_dept_id {
            user.dept_id = Set(dept_id);
        }

        let user = user.update(&txn).await?;

        if let Some(group_ids) = target_group_ids {
            user_group_members::Entity::delete_many()
                .filter(user_group_members::Column::UserId.eq(user.user_id))
                .exec(&txn)
                .await?;

            if !group_ids.is_empty() {
                let new_members: Vec<user_group_members::ActiveModel> = group_ids
                    .into_iter()
                    .map(|group_id| user_group_members::ActiveModel {
                        user_id: Set(user.user_id),
                        group_id: Set(group_id),
                        ..Default::default()
                    })
                    .collect();
                user_group_members::Entity::insert_many(new_members)
                    .exec(&txn)
                    .await?;
            }
        }

        txn.commit().await?;

        Ok(UserResponse::from(user))
    }

    pub async fn delete_user(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<(), AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let user_es = get_user_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            user_uuid.clone(), 
            &schema
        ).await?;
        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::DeleteUser,
                ResourceType::User(Some(user_uuid.clone())),
                user_es,
            )
            .await?;

        // 用户不删除 只是禁用
        users::Entity::update_many()
            .filter(users::Column::UserUuid.eq(user_uuid))
            .set(users::ActiveModel {
                is_active: Set(false),
                ..Default::default()
            })
            .exec(self.app_state.db.as_ref())
            .await?;

        Ok(())
    }

    pub async fn user_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
    ) -> Result<Vec<UserRoleInfo>, AppError> {
        self.app_state
            .auth_service
            .check_permission(
                &current_user.sub,
                context,
                AuthAction::ViewRole,
                ResourceType::User(None),
            )
            .await?;

        let mut all_roles = Vec::new();

        let user_id = users::Entity::find()
            .select_only()
            .column(users::Column::UserId)
            .filter(users::Column::UserUuid.eq(&user_uuid))
            .into_tuple::<i32>()
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("User not found"))?;

        // 获取直接角色
        let direct_roles = self.get_user_direct_roles(user_id).await?;
        for direct_role in direct_roles {
            all_roles.push(UserRoleInfo {
                uuid: Some(direct_role.uuid),
                role_name: direct_role.role_name,
                source: ROLE_SOURCE_DIRECT.to_string(),
                group_name: None,
            });
        }

        // 获取组角色
        let group_roles = self.get_user_group_roles(user_id).await?;
        for group_role in group_roles {
            all_roles.push(UserRoleInfo {
                uuid: Some(group_role.uuid),
                role_name: group_role.role_name,
                source: ROLE_SOURCE_GROUP.to_string(),
                group_name: Some(group_role.group_name),
            });
        }

        Ok(all_roles)
    }

    // 获取用户直接分配的角色
    async fn get_user_direct_roles(&self, user_id: i32) -> Result<Vec<DirectRole>, AppError> {
        let roles = roles::Entity::find()
            .select_only()
            .column(roles::Column::RoleUuid)
            .column(roles::Column::RoleName)
            .join(JoinType::InnerJoin, roles::Relation::UserRoles.def())
            .filter(user_roles::Column::UserId.eq(user_id))
            .into_tuple::<(String, String)>()
            .all(self.app_state.db.as_ref())
            .await?
            .into_iter()
            .map(|(uuid, name)| DirectRole {
                uuid,
                role_name: name,
            })
            .collect();

        Ok(roles)
    }

    // 获取用户通过组获得的角色（包含组信息）
    async fn get_user_group_roles(&self, user_id: i32) -> Result<Vec<GroupRole>, AppError> {
        let roles = roles::Entity::find()
            .select_only()
            .columns([roles::Column::RoleUuid, roles::Column::RoleName])
            .column_as(user_groups::Column::Name, "group_name")
            .join(InnerJoin, roles::Relation::GroupRoles.def())
            .join(InnerJoin, group_roles::Relation::UserGroups.def())
            .join(InnerJoin, user_groups::Relation::UserGroupMembers.def())
            .filter(user_group_members::Column::UserId.eq(user_id))
            .into_tuple::<(String, String, String)>()
            .all(self.app_state.db.as_ref())
            .await?;

        let group_roles = roles
            .into_iter()
            .map(|(role_uuid, role_name, group_name)| GroupRole {
                uuid: role_uuid,
                role_name,
                group_name,
            })
            .collect();

        Ok(group_roles)
    }

    pub async fn assign_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: String,
        dto: AssignRoleDto,
    ) -> Result<(), AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;

        let target_user_id = users::Entity::find()
            .select_only()
            .column(users::Column::UserId)
            .filter(users::Column::UserUuid.eq(user_uuid.clone()))
            .into_tuple::<i32>()
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or_else(|| not_found!(format!("not found user[{}]", user_uuid)))?;

        let user_es = get_user_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            user_uuid.clone(), 
            &schema
        ).await?;
        let role_es = get_role_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            &dto.role_uuids, 
            &schema
        ).await?;
        let merged_es = role_es.add_entities(user_es, Some(&schema))?;

        let mut target_role_ids = Vec::new();

        for role_uuid in &dto.role_uuids {
            self.app_state
                .auth_service
                .check_permission_with_entities(
                    &current_user.sub,
                    context.clone(), // <--- 关键点：克隆 Context
                    AuthAction::AssignRole,
                    ResourceType::Role(Some(role_uuid.to_string())),
                    merged_es.clone(), // <--- 关键点：克隆 Entities
                )
                .await?;

            let role_id = roles::Entity::find()
                .select_only()
                .column(roles::Column::RoleId)
                .filter(roles::Column::RoleUuid.eq(role_uuid))
                .into_tuple::<i32>()
                .one(self.app_state.db.as_ref())
                .await?
                .ok_or_else(|| not_found!(format!("not found role[{}]", role_uuid)))?;

            target_role_ids.push(role_id);
        }

        let txn = self.app_state.db.begin().await?;

        user_roles::Entity::delete_many()
            .filter(user_roles::Column::UserId.eq(target_user_id))
            .exec(&txn)
            .await?;

        if !target_role_ids.is_empty() {
            let new_relations: Vec<user_roles::ActiveModel> = target_role_ids
                .into_iter()
                .map(|role_id| user_roles::ActiveModel {
                    user_id: Set(target_user_id),
                    role_id: Set(role_id),
                    ..Default::default()
                })
                .collect();

            user_roles::Entity::insert_many(new_relations)
                .exec(&txn)
                .await?;
        }

        txn.commit().await?;

        Ok(())
    }

    pub async fn revoke_roles(
        &self,
        current_user: Claims,
        context: CedarContext,
        user_uuid: UserUUID,
        role_uuid: String,
    ) -> Result<(), AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let role_es = get_role_entities(
            self.app_state.db.as_ref(),
            self.app_state.cache_service.as_ref(),
            &vec![role_uuid.clone()], 
            &schema
        ).await?;
        let user_es = get_user_entities(
            self.app_state.db.as_ref(), 
            self.app_state.cache_service.as_ref(),
            user_uuid.clone(), 
            &schema
        ).await?;
        let merged_es = role_es.add_entities(user_es, None)?;

        self.app_state
            .auth_service
            .check_permission_with_entities(
                &current_user.sub,
                context,
                AuthAction::RevokeRole,
                ResourceType::User(Some(user_uuid.clone())),
                merged_es,
            )
            .await?;

        user_roles::Entity::delete_many()
            .filter(
                user_roles::Column::UserId.in_subquery(
                    Query::select()
                        .column(users::Column::UserId)
                        .from(users::Entity)
                        .and_where(users::Column::UserUuid.eq(user_uuid))
                        .to_owned(),
                ),
            )
            .filter(
                user_roles::Column::RoleId.in_subquery(
                    Query::select()
                        .column(roles::Column::RoleId)
                        .from(roles::Entity)
                        .and_where(roles::Column::RoleUuid.eq(role_uuid))
                        .to_owned(),
                ),
            )
            .exec(self.app_state.db.as_ref())
            .await?;

        Ok(())
    }
}
