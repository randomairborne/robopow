use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use deadpool_redis::{Config, Runtime};
use rand::{distributions::Alphanumeric, Rng};
use redis::AsyncCommands;
use sha2::{digest::FixedOutput, Digest};
use tokio::select;

#[tokio::main]
async fn main() {
    let redis_url = std::env::var("REDIS_URL").expect("Expected REDIS_URL in env");
    let zeros: usize = std::env::var("ZEROS")
        .expect("Expected ZEROS in env")
        .parse()
        .expect("Invalid ZEROS");
    let challenges: usize = std::env::var("CHALLENGES")
        .expect("Expected CHALLENGES in env")
        .parse()
        .expect("Invalid CHALLENGES");
    let timeout: usize = std::env::var("TIMEOUT")
        .expect("Expected TIMEOUT in env")
        .parse()
        .expect("Invalid TIMEOUT");

    let redis_cfg = Config::from_url(redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
    redis.get().await.expect("Failed to connect to redis");
    let state = Arc::new(InnerAppState {
        redis,
        zeros,
        challenges,
        timeout,
    });
    let app = router(state);
    axum::Server::bind(&([0, 0, 0, 0], 8080).into())
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn router(state: AppState) -> Router {
    let v0 = Router::new()
        .route("/challenge", get(challenge))
        .route("/verify", post(verify))
        .route("/client.js", get(js))
        .with_state(state.clone());
    let api = Router::new()
        .nest_service("/v0", v0)
        .with_state(state.clone());
    Router::new().nest_service("/api", api).with_state(state)
}

pub type AppState = Arc<InnerAppState>;

pub struct InnerAppState {
    redis: deadpool_redis::Pool,
    zeros: usize,
    challenges: usize,
    timeout: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Redis pool error: {0}")]
    DeadpoolRedis(#[from] deadpool_redis::PoolError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

#[derive(serde::Serialize)]
pub struct Challenge {
    token: String,
    zeros: usize,
}

#[derive(serde::Deserialize)]
pub struct CompletedChallenge {
    token: String,
    nonce: usize,
}

async fn challenge(State(state): State<AppState>) -> Result<Json<Vec<Challenge>>, Error> {
    let mut challenges = Vec::with_capacity(8);
    for _ in 0..state.challenges {
        let token: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        state
            .redis
            .get()
            .await?
            .set_ex(&token, "", state.timeout)
            .await?;
        challenges.push(Challenge {
            token,
            zeros: state.zeros,
        })
    }
    Ok(Json(challenges))
}

async fn verify(
    State(state): State<AppState>,
    Json(form): Json<Vec<CompletedChallenge>>,
) -> Result<Json<Vec<bool>>, Error> {
    let mut responses = Vec::with_capacity(form.len());
    'challenges: for CompletedChallenge { token, nonce } in form {
        let redis_token: Option<String> = state.redis.get().await?.get_del(&token).await?;
        if redis_token.is_none() {
            responses.push(false);
            continue 'challenges;
        }
        let bytes = format!("{nonce}{token}");
        let mut sha = sha2::Sha512::default();
        sha.update(bytes);
        let mut bits = 0;
        let data: Vec<u8> = sha.finalize_fixed().into_iter().collect();
        for item in data {
            for shift in 0..8 {
                let and_target = 0b10000000u8 >> shift;
                if (item & and_target) != 0 {
                    responses.push(false);
                    continue 'challenges;
                }
                bits += 1;
                if bits >= state.zeros {
                    responses.push(true);
                    continue 'challenges;
                }
            }
        }
    }
    Ok(Json(responses))
}

async fn js() -> ([(&'static str, &'static str); 2], &'static [u8]) {
    (
        [
            ("cache-control", "max-age=86400"),
            ("content-type", "application/json;charset=utf-8"),
        ],
        (include_bytes!("robopow.js")),
    )
}

async fn shutdown_signal() {
    #[cfg(target_family = "unix")]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt()).expect("Failed to listen to sigint");
        let mut quit = signal(SignalKind::quit()).expect("Failed to listen to sigquit");
        let mut terminate = signal(SignalKind::terminate()).expect("Failed to listen to sigterm");

        select! {
            _ = interrupt.recv() => {},
            _ = quit.recv() => {},
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(target_family = "unix"))]
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen to ctrl+c");
}
