mod constants;
mod trait_def;
mod mapping;
mod loader;

// 导出所有常量供外部使用 (如 ENTITY_TYPE_USER)
pub use constants::*;
// 导出 Trait
pub use trait_def::ToCedarEntity;
// 导出业务加载函数
pub use loader::{
    get_user_entities,
    get_role_entities,
    get_group_entities,
    get_dept_entities,
    get_policy_entities,
    find_descendants_entities,
    get_role_models_by_user_uuid
};