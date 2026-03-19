use crate::config::state::AppState;
use crate::handlers::cedar_policy;
use crate::services::cedar_policy::CedarPolicyService;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub fn protected_routes(app_state: AppState) -> OpenApiRouter {
    let service = CedarPolicyService::new(app_state);
    OpenApiRouter::new()
        .routes(routes!(
            cedar_policy::list_policies,
            cedar_policy::create_policy
        ))
        .routes(routes!(
            cedar_policy::get_policy,
            cedar_policy::update_policy,
            cedar_policy::delete_policy
        ))
        .routes(routes!(cedar_policy::update_policies_cache))
        .with_state(service)
}
