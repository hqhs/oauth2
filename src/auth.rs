use std::sync::Arc;

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::{Html, Response},
    routing::{get, Router},
};

use crate::{AppError, ServerState};

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route("/discord", get(login_with_discord_page))
        .with_state(state)
}

pub async fn check_user_session<B>(
    State(_state): State<Arc<ServerState>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError>
{
    Ok(next.run(req).await)
}

/*
 * SECTION: DISCORD AUTH
 */

async fn login_with_discord_page() -> Result<Html<String>, AppError>
{
    let r = "<html><p>Hello world</p></html>".to_owned();
    Ok(Html(r))
}
