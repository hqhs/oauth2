use std::sync::Arc;

use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{Html, Response},
    routing::{get, Router},
};
use serde_json::Value;
use slog::trace;
use uuid::Uuid;

use crate::{AppError, ServerState, StateTy};

const SESSION_ID_COOKIE: &str = "session-id";
type SessionID = Uuid;

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route("/login", get(login_options))
        .route("/login/discord", get(login_with_discord_page))
        .with_state(state)
}

pub async fn check_user_session<B>(
    State(_state): StateTy,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError>
{
    Ok(next.run(req).await)
}

struct Session {}

async fn login_options(State(state): StateTy)
    -> Result<Html<String>, AppError>
{
    trace! {state.log, "received request"; "page" => "profile"};
    let page = state.render("login_options.jinja2", Value::Null)?;
    let r: Result<_, AppError> = Ok(Html(page));
    r
}

/*
 * SECTION: DISCORD AUTH
 */

async fn login_with_discord_page() -> Result<Html<String>, AppError>
{
    let r = "<html><p>Hello world</p></html>".to_owned();
    Ok(Html(r))
}
