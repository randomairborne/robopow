use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use deadpool_redis::{Config, Runtime};
use rand::{distributions::Alphanumeric, Rng};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{digest::FixedOutput, Digest};
use tokio::net::TcpListener;

const GITHUB_URL: &str = "https://github.com/randomairborne/robopow";

#[tokio::main]
async fn main() {
    let redis_url = std::env::var("REDIS_URL").expect("Expected REDIS_URL in env");

    let redis_cfg = Config::from_url(redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
    redis.get().await.expect("Failed to connect to redis");

    let state = Arc::new(InnerAppState { redis });
    let app = router(state);
    let bind_address = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on port http://0.0.0.0:8080!");
    let tcp = TcpListener::bind(bind_address).await.unwrap();
    axum::serve(tcp, app)
        .with_graceful_shutdown(vss::shutdown_signal())
        .await
        .unwrap();
}

fn router(state: AppState) -> Router {
    let v0 = Router::new()
        .route("/challenge", get(challenge))
        .route("/verify/:id", post(verify))
        .route("/client.js", get(js))
        .with_state(state.clone());
    let api = Router::new().nest("/v0", v0).with_state(state.clone());
    Router::new()
        .route("/", get(Redirect::to(GITHUB_URL)))
        .nest("/api", api)
        .with_state(state)
}

pub type AppState = Arc<InnerAppState>;

pub struct InnerAppState {
    redis: deadpool_redis::Pool,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Redis error")]
    Redis(#[from] redis::RedisError),
    #[error("Redis pool error")]
    DeadpoolRedis(#[from] deadpool_redis::PoolError),
    #[error("serde_json error")]
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
        let code = self.code();
        let message = self.to_string();
        let json = serde_json::json!({
            "code": code,
            "message": message,
            "error": true
        });
        (status, Json(json)).into_response()
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
    fn code(&self) -> u64 {
        match self {
            Error::Redis(_) => 1,
            Error::DeadpoolRedis(_) => 2,
            Error::SerdeJson(_) => 3,
            Error::ParamsOutOfBounds => 4,
            Error::TokenNotFound => 5,
            Error::WrongNumberOfChallenges => 6,
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
    timeout: u64,
}

fn default_zeros() -> usize {
    12
}

fn default_challenges() -> usize {
    32
}

fn default_timeout() -> u64 {
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
    if params.zeros > 256 || params.challenges > 1024 || params.timeout > 3600 {
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
            ("content-type", "text/javascript;charset=utf-8"),
        ],
        include_bytes!("robopow.js"),
    )
}
