// 实体类型名称
pub const ENTITY_TYPE_USER: &str = "User";
pub const ENTITY_TYPE_ROLE: &str = "Role";
pub const ENTITY_TYPE_GROUP: &str = "Group";
pub const ENTITY_TYPE_DEPARTMENT: &str = "Department";
pub const ENTITY_TYPE_POLICY: &str = "Policy";

// 属性名称
// Cedar 使用的常量
const  APPLICATION_ENTITY_UID: &str = r#"Application::"VueAxumAdmin""#;

pub const  ENTITY_TYPE_ROBOT: &str = "Robot";
pub const  ENTITY_TYPE_ROBOT_ACCOUNT: &str = "RobotAccount";

pub const  ENTITY_ATTR_NAME: &str = "name";
pub const ENTITY_ATTR_OWNERS: &str = "owners";

// 缓存前缀
pub const USER_ENTITIES_CACHE_PREFIX: &str = "authz:user_entities";
pub const ROLE_ENTITIES_CACHE_PREFIX: &str = "authz:role_entities";

pub const DEPT_ENTITIES_CACHE_PREFIX: &str = "authz:dept_entities";

pub const GROUP_ENTITIES_CACHE_PREFIX: &str = "authz:group_entities";

pub const POLICY_ENTITIES_CACHE_PREFIX: &str = "authz:policy_entities";
pub const POLICIES_AND_TEMPLATES_CACHE_KEY: &str = "authz:policies_and_templates";
pub const TEMPLATE_LINKS_CACHE_KEY: &str = "authz:template_links";
