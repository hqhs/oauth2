use std::sync::Arc;

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::{Html, Response},
    routing::{get, Router},
    Extension,
};
use serde_json::Value;
use slog::{error, trace};
use uuid::Uuid;

use crate::{
    common_request_context_middleware, AppError, RequestContext, ServerState,
    StateTy,
};

const SESSION_ID_COOKIE: &str = "session-id";
type SessionID = Uuid;

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route("/login", get(login_options))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            common_request_context_middleware,
        ))
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

async fn login_options(
    Extension(cx): Extension<RequestContext>,
) -> Result<Html<String>, AppError>
{
    let template = "login_options.jinja2";
    let page = cx.server.render(&cx, template, Value::Null)?;
    let r: Result<_, AppError> = Ok(Html(page));
    r
}

/*
 * SECTION: DISCORD AUTH
 */
