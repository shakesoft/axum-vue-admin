use std::collections::{HashSet, HashMap};
use std::str::FromStr;
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use crate::errors::app_error::AppError;

pub trait ToCedarEntity {
    /// 返回 Cedar 中的类型名称 (如 "User")
    fn entity_type() -> &'static str;

    /// 返回实体的唯一 ID (通常是 UUID)
    fn entity_id(&self) -> String;

    /// 返回实体的属性集合
    fn attributes(&self) -> HashMap<String, RestrictedExpression>;

    /// 返回父实体的 UID 集合 (默认空)
    fn parents(&self) -> HashSet<EntityUid> {
        HashSet::new()
    }

    /// 核心转换逻辑：构造 cedar_policy::Entity
    fn to_cedar_entity(&self) -> Result<Entity, AppError> {
        let uid = self.get_uid()?;
        Ok(Entity::new(uid, self.attributes(), self.parents())?)
    }

    /// 快捷获取该实体的 EntityUid
    fn get_uid(&self) -> Result<EntityUid, AppError> {
        let type_name = EntityTypeName::from_str(Self::entity_type())?;
        let id = EntityId::from_str(&self.entity_id())?;
        Ok(EntityUid::from_type_name_and_id(type_name, id))
    }
}