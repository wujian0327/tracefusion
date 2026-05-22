use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use reqwest::Client;
use serde_json::{json, Map, Value};
use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const FORWARDED_HEADERS: &[&str] = &[
    "x-request-id",
    "x-ot-span-context",
    "x-datadog-trace-id",
    "x-datadog-parent-id",
    "x-datadog-sampling-priority",
    "traceparent",
    "tracestate",
    "x-cloud-trace-context",
    "grpc-trace-bin",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-flags",
    "sw8",
    "end-user",
    "x-mark",
    "user-agent",
    "cookie",
    "authorization",
    "jwt",
];

#[derive(Clone)]
struct AppState {
    role: String,
    book_count: i64,
    details_base_url: String,
    reviews_base_url: String,
    ratings_base_url: String,
    ratings_enabled: bool,
    star_color: String,
    hostname: String,
    client: Client,
    user_ratings: Arc<Mutex<HashMap<i64, Value>>>,
}

#[tokio::main]
async fn main() {
    let port = env_string("SERVER_PORT", "9080");
    let state = AppState {
        role: env_string("SERVICE_ROLE", "productpage"),
        book_count: env_i64("BOOK_COUNT", 100).max(1),
        details_base_url: format!(
            "http://{}:{}/details",
            env_string("DETAILS_HOSTNAME", "details"),
            env_string("DETAILS_SERVICE_PORT", "9080")
        ),
        reviews_base_url: format!(
            "http://{}:{}/reviews",
            env_string("REVIEWS_HOSTNAME", "reviews"),
            env_string("REVIEWS_SERVICE_PORT", "9080")
        ),
        ratings_base_url: format!(
            "http://{}:{}/ratings",
            env_string("RATINGS_HOSTNAME", "ratings"),
            env_string("RATINGS_SERVICE_PORT", "9080")
        ),
        ratings_enabled: env_bool("ENABLE_RATINGS", true),
        star_color: env_string("STAR_COLOR", "black"),
        hostname: env::var("HOSTNAME").unwrap_or_default(),
        client: Client::builder()
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(128)
            .build()
            .expect("failed to build HTTP client"),
        user_ratings: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/productpage", get(product_page))
        .route("/api/v1/products", get(products))
        .route("/api/v1/products/:product_id", get(product_route))
        .route("/api/v1/products/:product_id/reviews", get(reviews_route))
        .route("/api/v1/products/:product_id/ratings", get(ratings_route))
        .route("/details/:product_id", get(details))
        .route("/reviews/:product_id", get(reviews))
        .route("/ratings/:product_id", get(ratings).post(put_ratings))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .expect("invalid listen address");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");
    println!("starting bookinfo-rust on {addr}");
    axum::serve(listener, app).await.expect("server failed");
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({"status": format!("{} is healthy", capitalize(&state.role))}))
}

async fn product_page(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let product_id = parse_id(params.get("id"));
    let outbound_headers = forward_headers(&headers);
    let product_data = product(&state, product_id);
    let details_data = get_json(
        &state,
        &format!("{}/{}", state.details_base_url, product_id),
        &outbound_headers,
        fallback("details unavailable"),
    )
    .await;
    let reviews_data = get_reviews_with_retry(&state, product_id, &outbound_headers).await;

    let html = format!(
        r#"<!doctype html>
<html>
  <head><title>Bookinfo Rust</title></head>
  <body>
    <h1>{}</h1>
    <h2>Details</h2>
    <pre>{}</pre>
    <h2>Reviews</h2>
    <pre>{}</pre>
  </body>
</html>
"#,
        escape_html(product_data["title"].as_str().unwrap_or("")),
        escape_html(&compact_json(&details_data)),
        escape_html(&compact_json(&reviews_data)),
    );
    Html(html)
}

async fn products(State(state): State<AppState>) -> impl IntoResponse {
    let items: Vec<Value> = (0..state.book_count)
        .map(|product_id| product(&state, product_id))
        .collect();
    Json(items)
}

async fn product_route(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let item_id = parse_id(Some(&product_id));
    let result = get_json(
        &state,
        &format!("{}/{}", state.details_base_url, item_id),
        &forward_headers(&headers),
        fallback("details unavailable"),
    )
    .await;
    Json(result)
}

async fn reviews_route(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let result = get_reviews_with_retry(
        &state,
        parse_id(Some(&product_id)),
        &forward_headers(&headers),
    )
    .await;
    Json(result)
}

async fn ratings_route(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let item_id = parse_id(Some(&product_id));
    let result = get_json(
        &state,
        &format!("{}/{}", state.ratings_base_url, item_id),
        &forward_headers(&headers),
        fallback("ratings unavailable"),
    )
    .await;
    Json(result)
}

async fn details(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
) -> impl IntoResponse {
    let item_id = normalize(&state, parse_id(Some(&product_id)));
    let genres = [
        "distributed systems",
        "database internals",
        "observability",
        "networking",
        "cloud architecture",
        "debugging",
        "operating systems",
        "performance engineering",
    ];

    Json(json!({
        "id": item_id,
        "author": format!("Author {:02}", item_id % 17),
        "year": 2000 + (item_id % 24),
        "type": "paperback",
        "pages": 120 + ((item_id * 7) % 420),
        "publisher": format!("Publisher{:02}", item_id % 9),
        "language": "English",
        "genre": genres[(item_id as usize) % genres.len()],
        "ISBN-10": format!("{:010}", 1234567890_i64 + item_id),
        "ISBN-13": format!("978-1-4028-{item_id:04}-{}", item_id % 10),
    }))
}

async fn reviews(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let item_id = parse_id(Some(&product_id));
    let mut stars_reviewer_1 = -1;
    let mut stars_reviewer_2 = -1;

    if state.ratings_enabled {
        let mut url = format!("{}/{}", state.ratings_base_url, item_id);
        if let Some(rid) = params.get("rid") {
            if !rid.is_empty() {
                url = format!("{url}?rid={rid}");
            }
        }
        let ratings_data = get_json(&state, &url, &forward_headers(&headers), json!({})).await;
        if let Some(ratings) = ratings_data.get("ratings").and_then(Value::as_object) {
            stars_reviewer_1 = int_value(ratings.get("Reviewer1"), -1);
            stars_reviewer_2 = int_value(ratings.get("Reviewer2"), -1);
        }
    }

    Json(reviews_response(
        &state,
        item_id,
        stars_reviewer_1,
        stars_reviewer_2,
    ))
}

async fn ratings(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
) -> impl IntoResponse {
    Json(get_local_ratings(&state, parse_id(Some(&product_id))))
}

async fn put_ratings(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let item_id = normalize(&state, parse_id(Some(&product_id)));
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "please provide valid ratings JSON"})),
        );
    }
    let result = json!({"id": item_id, "ratings": body});
    state
        .user_ratings
        .lock()
        .expect("ratings lock poisoned")
        .insert(item_id, result.clone());
    (StatusCode::OK, Json(result))
}

fn product(state: &AppState, product_id: i64) -> Value {
    let item_id = normalize(state, product_id);
    json!({
        "id": item_id,
        "title": format!("Microservice Field Notes {item_id:03}"),
        "descriptionHtml": format!("Synthetic Bookinfo record {item_id:03} for trace and lineage experiments."),
    })
}

async fn get_reviews_with_retry(state: &AppState, product_id: i64, headers: &HeaderMap) -> Value {
    let default = fallback("reviews unavailable");
    let mut result = default.clone();
    for _ in 0..2 {
        result = get_json(
            state,
            &format!("{}/{}", state.reviews_base_url, product_id),
            headers,
            default.clone(),
        )
        .await;
        if result.get("error").is_none() {
            return result;
        }
    }
    result
}

async fn get_json(state: &AppState, url: &str, headers: &HeaderMap, default: Value) -> Value {
    let mut request = state.client.get(url);
    for (name, value) in headers.iter() {
        request = request.header(name, value);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => match response.json::<Value>().await {
            Ok(value) if value.is_object() => value,
            _ => default,
        },
        _ => default,
    }
}

fn reviews_response(
    state: &AppState,
    product_id: i64,
    stars_reviewer_1: i64,
    stars_reviewer_2: i64,
) -> Value {
    json!({
        "id": product_id.to_string(),
        "podname": state.hostname,
        "clustername": env::var("CLUSTER_NAME").unwrap_or_default(),
        "reviews": [
            review(state, "Reviewer1", "An extremely entertaining play by Shakespeare. The slapstick humour is refreshing!", stars_reviewer_1),
            review(state, "Reviewer2", "Absolutely fun and entertaining. The play lacks thematic depth when compared to other plays by Shakespeare.", stars_reviewer_2),
        ],
    })
}

fn review(state: &AppState, reviewer: &str, text: &str, stars: i64) -> Value {
    let mut item = Map::new();
    item.insert("reviewer".to_string(), json!(reviewer));
    item.insert("text".to_string(), json!(text));
    if state.ratings_enabled {
        if stars >= 0 {
            item.insert(
                "rating".to_string(),
                json!({"stars": stars, "color": state.star_color}),
            );
        } else {
            item.insert(
                "rating".to_string(),
                json!({"error": "Ratings service is currently unavailable"}),
            );
        }
    }
    Value::Object(item)
}

fn get_local_ratings(state: &AppState, product_id: i64) -> Value {
    let item_id = normalize(state, product_id);
    if let Some(value) = state
        .user_ratings
        .lock()
        .expect("ratings lock poisoned")
        .get(&item_id)
        .cloned()
    {
        return value;
    }
    json!({
        "id": item_id,
        "ratings": {
            "Reviewer1": 1 + (item_id % 5),
            "Reviewer2": 1 + ((item_id + 3) % 5),
        },
    })
}

fn forward_headers(headers: &HeaderMap) -> HeaderMap {
    let allowed: HashSet<&str> = FORWARDED_HEADERS.iter().copied().collect();
    let mut result = HeaderMap::new();
    for (name, value) in headers.iter() {
        if allowed.contains(name.as_str()) {
            result.append(
                HeaderName::from_bytes(name.as_str().as_bytes()).expect("valid header name"),
                HeaderValue::from_bytes(value.as_bytes()).expect("valid header value"),
            );
        }
    }
    result
}

fn fallback(message: &str) -> Value {
    json!({"error": message})
}

fn parse_id(raw: Option<&String>) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok()).unwrap_or(0)
}

fn normalize(state: &AppState, product_id: i64) -> i64 {
    ((product_id % state.book_count) + state.book_count) % state.book_count
}

fn int_value(value: Option<&Value>, fallback: i64) -> i64 {
    match value {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(fallback),
        Some(Value::String(text)) => text.parse::<i64>().unwrap_or(fallback),
        _ => fallback,
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_i64(name: &str, default: i64) -> i64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(default)
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Service".to_string(),
    }
}
