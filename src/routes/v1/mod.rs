// 路由模块入口

use crate::config::state::AppState;
use crate::middlewares::auth_guard::auth_guard_middleware;
use axum::middleware;
use utoipa_axum::router::OpenApiRouter;

mod audit_log;
mod cedar_policy;
mod cedar_schema;
mod department;
mod group;
mod health;
mod me;
mod password;
mod role;
mod sse;
mod user;
mod auth;

pub fn public_router(app_state: AppState) -> OpenApiRouter {
    let routes = OpenApiRouter::new()
        .nest("/auth/basic", auth::basic::public_routes(app_state.clone()))
        .nest(
            "/password-resets",
            password::public_routes(app_state.clone()),
        );

    routes
}

pub fn protected_router(app_state: AppState) -> OpenApiRouter {
    let routes = OpenApiRouter::new()
        .nest(
            "/auth/basic",
            auth::basic::protected_routes(app_state.clone()),
        )
        .nest("/users", user::protected_routes(app_state.clone()))
        .nest("/roles", role::protected_routes(app_state.clone()))
        .nest(
            "/departments",
            department::protected_routes(app_state.clone()),
        )
        .nest("/groups", group::protected_routes(app_state.clone()))
        .nest("/me", me::protected_routes(app_state.clone()))
        .nest(
            "/cedar_policies",
            cedar_policy::protected_routes(app_state.clone()),
        )
        .nest(
            "/cedar_schema",
            cedar_schema::protected_routes(app_state.clone()),
        )
        .nest("/event", sse::protected_routes(app_state.clone()))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_guard_middleware,
        ));

    routes
}
