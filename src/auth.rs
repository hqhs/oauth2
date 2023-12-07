use std::sync::Arc;

use axum::response::Html;
use axum::routing::{get, Router};

use crate::{AppError, ServerState};

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route("/discord", get(login_with_discord_page))
        .with_state(state)
}

/*
 * SECTION: DISCORD AUTH
 */

async fn login_with_discord_page() -> Result<Html<String>, AppError>
{
    let r = "<html><p>Hello world</p></html>".to_owned();
    Ok(Html(r))
}
