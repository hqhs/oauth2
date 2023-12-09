use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::Request,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    Extension,
};
use axum_extra::extract::CookieJar;
use hyper::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
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
        .route(DISCORD_CALLBACK, get(discord_callback))
        .route(GOOGLE_CALLBACK, get(google_callback))
        .route(MICROSOFT_CALLBACK, get(microsoft_callback))
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

#[derive(Serialize)]
struct LoginOptionsPayload
{
    google_auth_url: String,
    google_csrf_token: String,

    discord_auth_url: String,
    discord_csrf_token: String,
}

async fn login_options(
    Extension(cx): Extension<RequestContext>,
) -> Result<Html<String>, AppError>
{
    const TEMPLATE: &str = "login_options.jinja2";

    let (pkce_challenge, pkce_verifier) =
        PkceCodeChallenge::new_random_sha256();
    let (google_auth_url, google_csrf_token) = cx
        .server
        .google_auth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_owned()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    let (pkce_challenge, pkce_verifier) =
        PkceCodeChallenge::new_random_sha256();
    let (discord_auth_url, discord_csrf_token) = cx
        .server
        .discord_auth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_owned()))
        .add_scope(Scope::new("email".to_owned()))
        // .set_pkce_challenge(pkce_challenge)
        .url();
    let payload = LoginOptionsPayload {
        google_auth_url: google_auth_url.to_string(),
        google_csrf_token: google_csrf_token.secret().to_string(),

        discord_auth_url: discord_auth_url.to_string(),
        discord_csrf_token: discord_csrf_token.secret().to_string(),
    };
    let as_value = serde_json::to_value(payload).unwrap(); // FIXME: unwrap
    let page = cx.server.render(&cx, TEMPLATE, as_value)?;
    let r: Result<_, AppError> = Ok(Html(page));
    r
}

/*
 * SECTION: DISCORD AUTH
 */

pub const DISCORD_CALLBACK: &str = "/login/discord_callback";

#[derive(Deserialize)]
struct OauthCallbackPayload
{
    code: String,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscordUser
{
    id: String,
    username: String,
    global_name: Option<String>,
    avatar: Option<String>,
    locale: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscordMe
{
    user: Option<DiscordUser>,
}

async fn discord_callback(
    query: Query<OauthCallbackPayload>,
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    let token = match cx
        .server
        .discord_auth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .add_extra_param("grant_type", "authorization_code")
        .request_async(async_http_client)
        .await
    {
        Ok(res) => res,
        Err(e) =>
        {
            error!(cx.log, "An error occured while exchanging the code: {e}");
            dbg!(e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let client = reqwest::Client::new();
    let response = match client
        .get("https://discord.com/api/oauth2/@me")
        .bearer_auth(token.access_token().secret().to_owned())
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) =>
        {
            error!(cx.log, "An error occured while reqwesting user info: {e}");
            dbg!(e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let me = response.json::<DiscordMe>().await.unwrap();
    dbg!(me);
    // trace!(cx.log, "authorizatin OK"; "email" => me.user.unwrap().email.unwrap());
    Ok("not implemented")
}

#[derive(Default)]
pub struct Oauth2Builder
{
    redirect_url: String,
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
}

impl Oauth2Builder
{
    pub fn new(host: &str, callback: &str) -> Self
    {
        let redirect_url = format!("{host}{callback}");
        Oauth2Builder { redirect_url, ..Default::default() }
    }

    pub fn auth_url(mut self, auth_url: &str) -> Self
    {
        self.auth_url = auth_url.into();
        self
    }

    pub fn token_url(mut self, token_url: &str) -> Self
    {
        self.token_url = token_url.into();
        self
    }

    pub fn client_id(mut self, client_id: &str) -> Self
    {
        self.client_id = client_id.into();
        self
    }

    pub fn client_secret(mut self, client_secret: &str) -> Self
    {
        self.client_secret = client_secret.into();
        self
    }

    pub fn build(self) -> BasicClient
    {
        // NOTE: panics on errors, not supposed to be used
        // out of the initialization code
        let auth_url = AuthUrl::new(self.auth_url)
            .expect("invalid authorization endpoint URL");
        let token_url =
            TokenUrl::new(self.token_url).expect("invalid token endpoint URL");

        BasicClient::new(
            ClientId::new(self.client_id),
            Some(ClientSecret::new(self.client_secret)),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_url).unwrap())
    }
}

/*
 * SECTION: GOOGLE AUTH
 */

pub const GOOGLE_CALLBACK: &str = "/login/google_callback";

async fn google_callback() -> impl IntoResponse
{
    "not implemented"
}

/*
 * SECTION: MICROSOFT
 */

pub const MICROSOFT_CALLBACK: &str = "/login/microsoft_callback";

async fn microsoft_callback() -> impl IntoResponse
{
    "not implemented"
}
