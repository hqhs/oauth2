use std::env;
use std::path::Path;
use std::sync::Arc;

use anyhow;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, Router};
use dotenvy::dotenv;
use hyper::StatusCode;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};
use tera::Tera;

const TEMPLATES_DIR: &str = "templates";

pub struct ServerState
{
    db: Pool<Sqlite>,
    templates: Tera,
}

type StateTy = State<Arc<ServerState>>;

fn print_type_of<T>(_: &T)
{
    println!("{}", std::any::type_name::<T>())
}

#[derive(sqlx::FromRow)]
struct Card
{
    card_id: i64,
    title: String,
    text: String,
}

pub async fn run_server() -> anyhow::Result<()>
{
    let state = setup_server_state().await?;
    let card = Card { card_id: 0, title: "Hello".into(), text: "where".into() };
    sqlx::query!(
        "insert into cards (title, text) values ($1, $2)",
        card.title,
        card.text
    )
    .execute(&state.db)
    .await?;
    let app = setup_router(state.into());
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

pub async fn setup_server_state() -> anyhow::Result<ServerState>
{
    dotenv().ok();
    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let templates = {
        if !Path::new(TEMPLATES_DIR).is_dir()
        {
            anyhow::bail!("{} directory does not exist", TEMPLATES_DIR);
        }
        let glob = format!("{}/**/*.jinja2", TEMPLATES_DIR);
        let mut templates = Tera::new(&glob)?;
        templates.autoescape_on(vec![".jinja2"]);
        templates
    };
    Ok(ServerState { db: pool, templates })
}

pub fn setup_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route("/cards", get(list_cards))
        .fallback(handler_404)
        .with_state(state)
}

async fn list_cards(State(state): StateTy) -> Result<(), AppError>
{
    let cards: Vec<Card> = sqlx::query_as!(
        Card,
        "
select
    card_id, title, text
from
    cards
limit 20"
    )
    .fetch_all(&state.db)
    .await?;

    for card in cards
    {
        println!("{} {}; {}", card.card_id, card.title, card.text);
    }
    Ok(())
}

async fn handler_404() -> impl IntoResponse
{
    (StatusCode::NOT_FOUND, "404! Nothing to see here!")
}

// Make our own error that wraps `anyhow::Error`.
struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError
{
    fn into_response(self) -> Response
    {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self
    {
        Self(err.into())
    }
}
