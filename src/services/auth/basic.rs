use crate::common::entities::get_user_entities;
// 认证相关路由（登录、SSO等）
use crate::common::jwt::{create_refresh_token, verify_refresh_token};
use crate::common::{
    crypto::verify_password, jwt::create_access_token,
};
use crate::config::app::BLACK_LIST_JTI;
use crate::config::auth::{ACCESS_TOKEN_EXPIRATION, REFRESH_TOKEN_EXPIRATION};
use crate::config::state::AppState;
use crate::entity::{
    departments,
    roles::{Column as RoleColumn, Entity as RoleEntity, Relation as RoleRelation},
    user_roles::Column as UserRoleColumn,
    users::{ActiveModel as UserActiveModel, Column as UserColumn, Entity as UserEntity},
};
use crate::errors::app_error::AppError;
use crate::schemas::auth::{
    Claims, Credentials, LogoutCommand, SessionContext, TokenPair, TokenType,
};
use crate::schemas::user::UserUUID;
use crate::{bad_request, not_found};
use chrono::{Duration, Utc};
use redis::{AsyncCommands, RedisResult};
use sea_orm::JoinType::InnerJoin;
use sea_orm::{
    ActiveModelTrait, ColIdx, ColumnTrait, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter,
    QuerySelect, RelationTrait, Set,
};

#[derive(Clone)]
pub struct BasicAuthService {
    app_state: AppState,
}

impl BasicAuthService {
    pub fn new(app_state: AppState) -> Self {
        Self {
            app_state: app_state.clone(),
        }
    }

    pub async fn authenticate(&self, dto: Credentials) -> Result<TokenPair, AppError> {
        // 验证用户名和密码
        // 生成 JWT
        // 返回 JWT
        let user = UserEntity::find()
            .filter(UserColumn::Username.eq(&dto.username))
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("User Not found".to_string()))?;

        let verified = verify_password(&dto.password, user.password.as_str())?;
        if !verified {
            return Err(bad_request!("Invalid credentials".to_string()));
        }

        if !user.is_active {
            return Err(bad_request!("User is inactive".to_string()));
        }

        let is_super_admin = RoleEntity::find()
            .join(InnerJoin, RoleRelation::UserRoles.def())
            .filter(UserRoleColumn::UserId.eq(user.user_id))
            .filter(RoleColumn::RoleName.eq("SuperAdmin"))
            .count(self.app_state.db.as_ref())
            .await?;
        let is_super_admin = is_super_admin > 0;

        let dept_uuid = departments::Entity::find_by_id(user.dept_id)
            .select_only()
            .column(departments::Column::DeptUuid)
            .into_tuple::<String>()
            .one(self.app_state.db.as_ref())
            .await?
            .ok_or(not_found!("Not joined the department".to_string()))?;

        let expires = Utc::now() + Duration::seconds(ACCESS_TOKEN_EXPIRATION);
        let payload = Claims {
            sub: user.user_uuid.clone(),
            jti: uuid::Uuid::new_v4(),
            iat: Utc::now().timestamp() as u64,
            exp: expires.timestamp() as u64,
            name: user.username.clone(),
            email: user.email.clone(),
            dept_uuid: dept_uuid.clone(),
            token_type: TokenType::Access,
            is_super_admin,
        };
        let access_token = create_access_token(payload)?;

        let expires = Utc::now() + Duration::seconds(REFRESH_TOKEN_EXPIRATION);
        let payload = Claims {
            sub: user.user_uuid.clone(),
            jti: uuid::Uuid::new_v4(),
            iat: Utc::now().timestamp() as u64,
            exp: expires.timestamp() as u64,
            name: user.username.clone(),
            email: user.email.clone(),
            dept_uuid,
            token_type: TokenType::Refresh,
            is_super_admin,
        };

        let refresh_token = create_refresh_token(payload)?;

        let _ = &self.cache_user_entities(user.user_uuid.clone()).await?;

        // 更新用户最后登录时间
        let user = UserActiveModel {
            user_id: Set(user.user_id),
            last_login: Set(Some(Utc::now().naive_local())),
            ..Default::default()
        };

        user.update(self.app_state.db.as_ref()).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            username: dto.username,
        })
    }

    // 刷新 JWT
    pub async fn refresh(&self, session: SessionContext) -> Result<TokenPair, AppError> {
        let refresh_claims = verify_refresh_token(session.refresh_token.as_str())?;

        if refresh_claims.token_type != TokenType::Refresh {
            return Err(bad_request!("Invalid refresh token".to_string()));
        }
        // 检查这个Refresh Token是否在黑名单中
        let mut redis_conn = self
            .app_state
            .redis
            .get_multiplexed_async_connection()
            .await?;
        let is_blacklisted: bool = redis_conn
            .exists(format!("{}:{}", BLACK_LIST_JTI, refresh_claims.jti))
            .await?;
        if is_blacklisted {
            return Err(bad_request!("Refresh token is blacklisted".to_string(),));
        }

        // 签发新的JWT
        let expires = Utc::now() + Duration::seconds(ACCESS_TOKEN_EXPIRATION);
        let new_claims = Claims {
            sub: refresh_claims.sub.clone(),
            jti: uuid::Uuid::new_v4(),
            iat: Utc::now().timestamp() as u64,
            exp: expires.timestamp() as u64,
            name: refresh_claims.name.clone(),
            email: refresh_claims.email.clone(),
            dept_uuid: refresh_claims.dept_uuid.clone(),
            token_type: TokenType::Access,
            is_super_admin: refresh_claims.is_super_admin,
        };
        let new_access_token = create_access_token(new_claims)?;

        let access_ttl = refresh_claims.exp - Utc::now().timestamp() as u64;
        // 将旧Refresh Token 添加黑名单
        let _: RedisResult<()> = redis_conn
            .set_ex(
                format!("{}:{}", BLACK_LIST_JTI, refresh_claims.jti),
                true,
                access_ttl,
            )
            .await;

        let expires = Utc::now() + Duration::seconds(REFRESH_TOKEN_EXPIRATION);
        let new_claims = Claims {
            sub: refresh_claims.sub,
            jti: uuid::Uuid::new_v4(),
            iat: Utc::now().timestamp() as u64,
            exp: expires.timestamp() as u64,
            name: refresh_claims.name.clone(),
            email: refresh_claims.email.clone(),
            dept_uuid: refresh_claims.dept_uuid,
            token_type: TokenType::Refresh,
            is_super_admin: refresh_claims.is_super_admin,
        };
        let new_refresh_token = create_refresh_token(new_claims)?;

        Ok(TokenPair {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            username: refresh_claims.name,
        })
    }

    pub async fn logout(&self, cmd: LogoutCommand) -> Result<(), AppError> {
        let mut redis_conn = self
            .app_state
            .redis
            .get_multiplexed_async_connection()
            .await?;

        // 设置 Access Token 过期
        let ttl = cmd
            .auth_user
            .exp
            .saturating_sub(Utc::now().timestamp() as u64);

        let _: RedisResult<()> = redis_conn
            .set_ex(
                format!("{}:{}", BLACK_LIST_JTI, cmd.auth_user.jti),
                true,
                ttl,
            )
            .await;

        // 设置 Refresh Token 过期
        if let Some(session) = cmd.session {
            let claims = verify_refresh_token(session.refresh_token.as_str())?;
            let ttl = claims.exp.saturating_sub(Utc::now().timestamp() as u64);
            if ttl > 0 {
                let _: RedisResult<()> = redis_conn
                    .set_ex(format!("{}:{}", BLACK_LIST_JTI, claims.jti), true, ttl)
                    .await;
            }
        }

        Ok(())
    }

    // 当前用户的 Entities 不应该过期; 不然速度太慢了.
    async fn cache_user_entities(&self, user_id: UserUUID) -> Result<(), AppError> {
        let schema = self.app_state.auth_service.get_schema_copy().await;
        let _ = get_user_entities(
            self.app_state.db.as_ref(),
            self.app_state.cache_service.as_ref(),
            user_id,
            &schema
        ).await?;

        Ok(())
    }
}
