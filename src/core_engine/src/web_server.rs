//! # Web Sunucusu Modülü
//! 
//! Bu modül axum framework kullanarak HTTP panel sunucusunu başlatır.
//! Endpoint'ler:
//! - `GET /` — Ana panel sayfası
//! - `GET /analyze?url=...` — Header analizi
//! - `GET /health` — Sağlık kontrolü
use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::http_header_analyzer::analyze_headers;

/// Web sunucusunu başlatır.
pub async fn start_server() {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/analyze", get(analyze_handler))
        .route("/health", get(health_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🌐 Panel açık: http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}

/// Ana sayfa handler'ı
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// URL parametresi
#[derive(Deserialize)]
struct AnalyzeParams {
    url: String,
}

/// Analiz endpoint'i
async fn analyze_handler(
    Query(params): Query<AnalyzeParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match analyze_headers(&params.url).await {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

/// Sağlık kontrolü endpoint'i
async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": "0.1.0",
        "service": "ISU-SecOps-Engine"
    }))
}
