use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use deadpool_redis::{Config, Runtime};
use rand::{distributions::Alphanumeric, Rng};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{digest::FixedOutput, Digest};
use tokio::select;

#[tokio::main]
async fn main() {
    let redis_url = std::env::var("REDIS_URL").expect("Expected REDIS_URL in env");

    let redis_cfg = Config::from_url(redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
    redis.get().await.expect("Failed to connect to redis");
    let state = Arc::new(InnerAppState { redis });
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
        .route("/verify/:id", post(verify))
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
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Redis pool error: {0}")]
    DeadpoolRedis(#[from] deadpool_redis::PoolError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Configuration out of bounds")]
    ParamsOutOfBounds,
    #[error("Token not found")]
    TokenNotFound,
    #[error("Wrong number of challenge responses sent for token!")]
    WrongNumberOfChallenges,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, self.to_string()).into_response()
    }
}

impl Error {
    fn status(&self) -> StatusCode {
        match self {
            Error::Redis(_) | Error::DeadpoolRedis(_) | Error::SerdeJson(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Error::ParamsOutOfBounds | Error::WrongNumberOfChallenges => StatusCode::BAD_REQUEST,
            Error::TokenNotFound => StatusCode::NOT_FOUND,
        }
    }
}

#[derive(Serialize)]
pub struct ChallengeSet {
    params: ChallengeParams,
    token: String,
    challenges: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RedisChallengeSet {
    params: ChallengeParams,
    challenges: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeVerification {
    params: ChallengeParams,
    valid: bool,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeParams {
    #[serde(default = "default_zeros")]
    zeros: usize,
    #[serde(default = "default_challenges")]
    challenges: usize,
    #[serde(default = "default_timeout")]
    timeout: usize,
}

fn default_zeros() -> usize {
    14
}

fn default_challenges() -> usize {
    8
}

fn default_timeout() -> usize {
    10
}

fn get_token() -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

async fn challenge(
    State(state): State<AppState>,
    Query(params): Query<ChallengeParams>,
) -> Result<Json<ChallengeSet>, Error> {
    let mut challenges = Vec::with_capacity(8);
    if params.zeros > 32 || params.challenges > 128 || params.timeout > 3600 {
        return Err(Error::ParamsOutOfBounds);
    }

    let token = get_token();

    for _ in 0..params.challenges {
        let challenge = get_token();
        challenges.push(challenge)
    }

    let redis_challenge = RedisChallengeSet {
        params,
        challenges: challenges.clone(),
    };
    state
        .redis
        .get()
        .await?
        .set_ex(
            &token,
            serde_json::to_string(&redis_challenge)?,
            params.timeout,
        )
        .await?;

    Ok(Json(ChallengeSet {
        token,
        params,
        challenges,
    }))
}

async fn verify(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(form): Json<Vec<usize>>,
) -> Result<Json<ChallengeVerification>, Error> {
    let maybe_token_meta: Option<String> = state.redis.get().await?.get_del(&token).await?;
    let Some(token_meta_string) = maybe_token_meta else {
        return Err(Error::TokenNotFound);
    };
    let challenge_set: RedisChallengeSet = serde_json::from_str(&token_meta_string)?;
    if form.len() != challenge_set.params.challenges {
        return Err(Error::WrongNumberOfChallenges);
    }
    for (nonce, challenge) in form.into_iter().zip(challenge_set.challenges) {
        if !check_token(nonce, &token, &challenge, challenge_set.params.zeros) {
            return Ok(Json(ChallengeVerification {
                params: challenge_set.params,
                valid: false,
            }));
        }
        tokio::task::yield_now().await;
    }
    Ok(Json(ChallengeVerification {
        params: challenge_set.params,
        valid: true,
    }))
}

fn check_token(nonce: usize, token: &str, challenge: &str, zeros: usize) -> bool {
    let mut sha = sha2::Sha512::default();
    sha.update(nonce.to_string());
    sha.update(token);
    sha.update(challenge);
    let mut bits = 0;
    let data: Vec<u8> = sha.finalize_fixed().into_iter().collect();
    for item in data {
        for shift in 0..8 {
            let and_target = 0b10000000u8 >> shift;
            if (item & and_target) != 0 {
                return false;
            }
            bits += 1;
            if bits >= zeros {
                return true;
            }
        }
    }
    false
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
