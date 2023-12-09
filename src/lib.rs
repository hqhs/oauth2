use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use auth::build_auth_router;
use axum::middleware::{self};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, Router};
use axum::Extension;
use axum::{extract::State, http::Request, middleware::Next};
use dotenvy::dotenv;
use hyper::StatusCode;
use serde::Serialize;
use serde_json::{self, Value};
use slog::{debug, error, info, o, trace, Drain};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};
use tera::Tera;
use thiserror;
use tower_http::services::ServeDir;
use uuid::Uuid;

mod auth;

const TEMPLATES_DIR: &str = "templates";
const STATIC_DIR: &str = "static";
const ROOT_DIR: &str = env!("CARGO_MANIFEST_DIR"); // NOTE(hqhs): won't compile on systems with non-utf8 paths, but project is not expected to run everywhere

#[derive(Serialize)]
struct Common
{
    dev_mode: bool,
    request_id: String, // NOTE: one less allocation if it's &str

    #[serde(flatten)]
    other: serde_json::Value,
}

pub struct ServerState
{
    templates: RwLock<Tera>,
    db: Pool<Sqlite>,
    root: slog::Logger,
}

impl ServerState
{
    fn render(
        &self,
        cx: &RequestContext,
        template: &str,
        other: serde_json::Value,
    ) -> Result<String, AppError>
    {
        let dev_mode = true;
        let request_id = cx.request_id.clone();
        let params = Common { dev_mode, request_id, other };
        let template_cx = tera::Context::from_serialize(params)?;
        let unlocked = self.templates.read().unwrap();
        let maybe_page = unlocked.render(template, &template_cx);
        if let Err(ref err) = maybe_page
        {
            // NOTE: it's fine to log error internally since templates
            // are expected to always work, and all rendering happens threw
            // this method
            error!(cx.log, "failed to render {template}: {err}");
        }
        let page = maybe_page?;
        Ok(page)
    }

    fn reload_templates(&self) -> tera::Result<()>
    {
        info!(self.root, "template reload requested");
        let mut unlocked = self.templates.write().unwrap();
        unlocked.full_reload()
    }
}

#[derive(Clone)]
pub struct RequestContext
{
    pub server: Arc<ServerState>,
    pub request_id: String,
    pub log: slog::Logger,
}

type StateTy = State<Arc<ServerState>>;

pub async fn run_server() -> anyhow::Result<()>
{
    let state = Arc::new(setup_server_state().await?);
    let app = setup_router(state.clone())?;
    let address = "0.0.0.0:3000";
    info!(state.root, "serving requests on {address}");
    axum::Server::bind(&address.parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

pub async fn common_request_context_middleware<B>(
    State(state): StateTy,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError>
{
    let request_id = Uuid::new_v4().to_string();
    let log = state.root.new(o!(
        "request_id" => request_id.clone(),
        "uri" => req.uri().to_string(),
        "method" => req.method().as_str().to_owned(),
    ));
    let cx = RequestContext { server: state.clone(), request_id, log };
    trace!(
        cx.log,
        "request";
    );
    req.extensions_mut().insert(cx);
    Ok(next.run(req).await)
}

pub async fn setup_server_state() -> anyhow::Result<ServerState>
{
    dotenv().ok();
    let root = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, o!())
    };
    debug!(root, "hello where, general kenobi");
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
    Ok(ServerState { db: pool, root, templates })
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

    let commont_cx_middleware = middleware::from_fn_with_state(
        state.clone(),
        common_request_context_middleware,
    );

    let public = Router::new()
        .route("/", get(home_page))
        .route("/reload", post(reload_templates))
        .route_layer(commont_cx_middleware.clone());

    let authorized_only = Router::new()
        .route("/profile", get(profile))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::check_user_session,
        ))
        .route_layer(commont_cx_middleware);

    let r = Router::new()
        .merge(public)
        .merge(auth)
        .merge(authorized_only)
        .merge(static_files)
        .fallback(handler_404);
    Ok(r)
}

async fn reload_templates(
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    cx.server.reload_templates()?;
    let r: Result<_, AppError> = Ok(StatusCode::OK);
    r
}

async fn profile(Extension(cx): Extension<RequestContext>)
    -> impl IntoResponse
{
    let page = cx.server.render(&cx, "base.jinja2", Value::Null)?;
    let r: Result<_, AppError> = Ok(Html(page));
    r
}

async fn home_page(
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    trace! {cx.log, "received request"; "page" => "home"};
    Redirect::to("/profile")
}

async fn handler_404() -> impl IntoResponse
{
    (StatusCode::NOT_FOUND, "404! Nothing to see here!")
}

// Make our own error that wraps `anyhow::Error`.
#[derive(thiserror::Error, Debug)]
pub enum AppError
{
    #[error("failed to render template: `{0}`")]
    Template(#[from] tera::Error),
    #[error("something unexpected happened: `{0}`")]
    Opaque(#[from] anyhow::Error),
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError
{
    fn into_response(self) -> Response
    {
        let code = match self
        {
            AppError::Opaque(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Template(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        code.into_response()
    }
}
