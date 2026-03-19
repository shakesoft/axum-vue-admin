use crate::services::user::service::UserService;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::config::state::AppState;
use crate::handlers::user;

pub fn protected_routes(app_state: AppState) -> OpenApiRouter {
    let service = UserService::new(app_state);

    OpenApiRouter::new()
        .routes(routes!(user::list_users, user::create_user))
        .routes(routes!(
            user::get_user,
            user::delete_user,
            user::update_user
        ))
        .routes(routes!(
            user::user_roles,
            user::assign_roles,
            user::revoke_roles
        ))
        .with_state(service)
}
