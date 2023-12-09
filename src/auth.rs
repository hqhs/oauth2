use std::sync::Arc;

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, Router},
    Extension,
};
use axum_extra::extract::CookieJar;
use serde_json::Value;
use slog::{error, trace};
use uuid::Uuid;

use crate::{
    common_request_context_middleware, AppError, RequestContext, ServerState,
    StateTy,
};

const SESSION_ID_COOKIE: &str = "session-id";
const LOGIN_PAGE: &str = "/login";

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route(LOGIN_PAGE, get(login_options))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            common_request_context_middleware,
        ))
        .with_state(state)
}

pub async fn fetch_session_from_cookies(
    jar: &CookieJar,
    server: &ServerState,
) -> Result<Session, AppError>
{
    // let session_id =
    //     jar.get(SESSION_ID_COOKIE).ok_or(AuthError::MissingSessionID)?;
    // let session_id = Uuid::try_parse(session_id.value())
    //     .map_err(|_| AuthError::InvalidSessionID)?;
    unimplemented!("implement me");
}

pub async fn redirect_unauthorized_middleware<B>(
    State(_state): StateTy,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError>
{
    // NOTE: unwrap here is safe since request context is not optional,
    // it's expected to be set for each request in `common_request_context_middleware`
    // if it's missing, it's a bug
    let cx = req.extensions().get::<RequestContext>().unwrap();
    if cx.session.is_none()
    {
        let redirect = Redirect::to(LOGIN_PAGE);
        return Ok(redirect.into_response());
    }
    Ok(next.run(req).await)
}

type SessionID = Uuid;

#[derive(Clone)]
pub struct Session
{
    session_id: SessionID,
}

type UserID = Uuid;

pub struct User
{
    user_id: UserID,
}

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
