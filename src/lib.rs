use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use auth::build_auth_router;
use axum::extract::State;
use axum::middleware::{self};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, Router};
use dotenvy::dotenv;
use hyper::StatusCode;
use serde::Serialize;
use serde_json::{self, Value};
use slog::{debug, info, o, trace, Drain};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};
use tera::Tera;
use tower_http::services::ServeDir;

mod auth;

const TEMPLATES_DIR: &str = "templates";
const STATIC_DIR: &str = "static";
const ROOT_DIR: &str = env!("CARGO_MANIFEST_DIR"); // NOTE(hqhs): won't compile on systems with non-utf8 paths, but project is not expected to run everywhere

#[derive(Serialize)]
struct Common
{
    dev_mode: bool,

    #[serde(flatten)]
    other: serde_json::Value,
}

pub struct ServerState
{
    db: Pool<Sqlite>,
    log: slog::Logger,
    templates: RwLock<Tera>,
}

impl ServerState
{
    fn render(
        &self,
        template: &str,
        other: serde_json::Value,
    ) -> Result<String, AppError>
    {
        let dev_mode = true;
        let params = Common { dev_mode, other };
        let cx = tera::Context::from_serialize(params)?;
        let unlocked = self.templates.read().unwrap();
        let page = unlocked.render(template, &cx)?;
        Ok(page)
    }

    fn reload_templates(&self) -> tera::Result<()>
    {
        info!(self.log, "template reload requested");
        let mut unlocked = self.templates.write().unwrap();
        unlocked.full_reload()
    }
}

type StateTy = State<Arc<ServerState>>;

pub async fn run_server() -> anyhow::Result<()>
{
    let state = Arc::new(setup_server_state().await?);
    let app = setup_router(state.clone())?;
    let address = "0.0.0.0:3000";
    info!(state.log, "serving requests on {address}");
    axum::Server::bind(&address.parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

pub async fn setup_server_state() -> anyhow::Result<ServerState>
{
    dotenv().ok();
    let log = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, o!())
    };
    debug!(log, "hello where, general kenobi");
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
        RwLock::new(templates)
    };
    Ok(ServerState { db: pool, log, templates })
}

pub fn setup_router(state: Arc<ServerState>) -> anyhow::Result<Router>
{
    let auth = build_auth_router(state.clone());
    let static_files: Router = {
        let path: PathBuf = [ROOT_DIR, STATIC_DIR].iter().collect();
        if !path.is_dir()
        {
            anyhow::bail!(
                "{} directory does not exist",
                path.to_string_lossy()
            );
        }
        Router::new().nest_service("/static", ServeDir::new(path))
    };

    let public = Router::new()
        .route("/", get(home_page))
        .route("/reload", post(reload_templates))
        .with_state(state.clone());

    let authorized_only = Router::new()
        .route("/profile", get(profile))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::check_user_session,
        ))
        .with_state(state.clone());

    let r = Router::new()
        .merge(public)
        .merge(authorized_only)
        .merge(auth)
        .merge(static_files)
        .fallback(handler_404);
    Ok(r)
}

async fn reload_templates(State(state): StateTy) -> impl IntoResponse
{
    trace! { state.log, "received request"; "page" => "reload_templates" };
    state.reload_templates()?;
    let r: Result<_, AppError> = Ok(StatusCode::OK);
    r
}

async fn profile(State(state): StateTy) -> impl IntoResponse
{
    trace! {state.log, "received request"; "page" => "profile"};
    let page = state.render("base.jinja2", Value::Null)?;
    let r: Result<_, AppError> = Ok(Html(page));
    r
}

async fn home_page(State(state): StateTy) -> impl IntoResponse
{
    trace! {state.log, "received request"; "page" => "home"};
    Redirect::to("/profile")
}

async fn handler_404() -> impl IntoResponse
{
    (StatusCode::NOT_FOUND, "404! Nothing to see here!")
}

// Make our own error that wraps `anyhow::Error`.
pub struct AppError(anyhow::Error);

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
