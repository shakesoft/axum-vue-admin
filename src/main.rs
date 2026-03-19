use clap::Parser;
use core::str::FromStr;
use std::path::PathBuf;
use std::{env, fs};
use tower_http::trace::TraceLayer;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::AppConfig;
use common::logging::init_logging;
use config::state;
use axum_vue_admin::common;
use axum_vue_admin::config;
use axum_vue_admin::routes;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::{debug, info};
use utoipa::OpenApi;

use crate::common::function::subscribe_to_policy_updates;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    generate_config: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if cli.generate_config {
        let config_content = AppConfig::get_default_config();
        match fs::write("config.toml", config_content.trim()) {
            Ok(_) => println!("✅ 默认的“config.toml”已成功生成。"),
            Err(e) => eprintln!("❌ 生成配置文件时出错: {}", e),
        }
        return;
    }
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("config.toml"));

    println!("尝试从以下位置加载配置：{:?}", config_path);

    let config = match AppConfig::load_config(&config_path) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("❌ 无法读取配置文件 {:?}. {}", config_path, err);
            eprintln!("💡 您可以通过使用“-g”标志运行来生成默认配置文件。");
            return;
        }
    };

    // 这个 `_guard` 变量必须存在于 main 函数的整个生命周期中。
    let _guard = init_logging(&config.log);

    // debug!("http_proxy Env: {}", env::var("http_proxy").unwrap_or("No http_proxy".to_string()));
    // debug!("https_proxy Env: {}", env::var("https_proxy").unwrap_or("No https_proxy".to_string()));

    let app_state = state::AppState::new(&config)
        .await
        .expect("Failed to initialize state");

    // 启动后台任务，监听访问策略更新
    let state_for_subscriber = app_state.clone();
    tokio::spawn(async move {
        subscribe_to_policy_updates(state_for_subscriber).await;
    });

    
    let (router, api) = OpenApiRouter::with_openapi(config::openapi::ApiDoc::openapi())
        .nest("/api", routes::api_router(app_state.clone()))
        .layer(TraceLayer::new_for_http())
        // .layer(middleware::from_fn_with_state(state.clone(), handle_audit_log_middleware))
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/swagger-ui").url("/apidoc/openapi.json", api));

    let ipaddr = Ipv4Addr::from_str(&config.server.host.as_str());
    let ipaddr = match ipaddr {
        Ok(ipaddr) => ipaddr,
        Err(_) => {
            eprintln!("错误的监听IP地址");
            return;
        }
    };
    let addr = SocketAddr::new(IpAddr::V4(ipaddr), config.server.port);
    info!("正在监听 {}", addr);
    // Run server
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
