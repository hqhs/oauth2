use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::Request,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    Extension,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use chrono;
use hyper::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slog::{error, info, trace};
use uuid::Uuid;

use crate::{
    common_request_context_middleware, AppError, RequestContext, ServerState,
    StateTy, PROFILE_PAGE,
};

pub const SESSION_ID_COOKIE: &str = "session-id";
const LOGIN_PAGE: &str = "/login";

pub fn build_auth_router(state: Arc<ServerState>) -> Router
{
    Router::new()
        .route(LOGIN_PAGE, get(login_options))
        .route(DISCORD_CALLBACK, get(discord_callback))
        .route(TWITCH_CALLBACK, get(twitch_callback))
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
    pub session_id: SessionID,
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

    discord_auth_url: String,

    twitch_auth_url: String,
}

async fn login_options(
    Extension(cx): Extension<RequestContext>,
) -> Result<Response, AppError>
{
    const TEMPLATE: &str = "login_options.jinja2";

    if let Some(ref session) = cx.session
    {
        return Ok(Redirect::to(PROFILE_PAGE).into_response());
    }

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
        .add_scope(Scope::new("email".to_owned()))
        // .set_pkce_challenge(pkce_challenge)
        .url();
    let (twitch_auth_url, twitch_csrf_token) = cx
        .server
        .twitch_auth_client
        .authorize_url(CsrfToken::new_random)
        // https://dev.twitch.tv/docs/authentication/scopes/
        .add_scope(Scope::new("user:read:email".to_owned()))
        // .set_pkce_challenge(pkce_challenge)
        .url();
    let payload = LoginOptionsPayload {
        google_auth_url: google_auth_url.to_string(),
        discord_auth_url: discord_auth_url.to_string(),
        twitch_auth_url: twitch_auth_url.to_string(),
    };
    {
        // NOTE: store tokens in database
        let google_token = google_csrf_token.secret().to_string();
        let discord_token = discord_csrf_token.secret().to_string();
        let twitch_token = twitch_csrf_token.secret().to_string();
        let _inserted = sqlx::query!(
            "
insert into
    pending_authorizations (google_token, discord_token, twitch_token)
values ($1, $2, $3)",
            google_token,
            discord_token,
            twitch_token
        )
        .execute(&cx.server.db)
        .await?;
    }
    let page = cx.server.render(&cx, TEMPLATE, payload)?;
    let r: Result<_, AppError> = Ok(Html(page).into_response());
    r
}

pub async fn logout(
    jar: CookieJar,
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    let session = cx.session.as_ref().unwrap(); // unwrap is safe because it's auth-only route
    let session_id_bytes = &session.session_id.as_bytes()[..];
    sqlx::query!(
        "
delete from sessions where session_id = $1
",
        session_id_bytes
    )
    .execute(&cx.server.db)
    .await?;
    let response: Result<_, AppError> =
        Ok((jar.remove(Cookie::named(SESSION_ID_COOKIE)), Redirect::to("/")));
    response
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
    discriminator: String,
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

async fn discord_callback_inner(
    query: &OauthCallbackPayload,
    cx: &RequestContext,
) -> Result<SessionID, AppError>
{
    let token = query.state.as_deref().ok_or(AppError::BadRequest)?;
    // NOTE: validate csrf first
    let result = sqlx::query!(
        "
delete from
    pending_authorizations
where
    discord_token = $1",
        token,
    )
    .execute(&cx.server.db)
    .await?;
    if result.rows_affected() != 1
    {
        return Err(AppError::BadRequest);
    }
    let token = cx
        .server
        .discord_auth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::Opaque(e.into()))?;
    let response = cx
        .server
        .client
        .get("https://discord.com/api/oauth2/@me")
        .bearer_auth(token.access_token().secret().to_owned())
        .send()
        .await?;
    let me = response.json::<DiscordMe>().await.unwrap();
    let me = me.user.unwrap(); // FIXME(hqhs): unwrap
    let mut tx = cx.server.db.begin().await?;
    let now = chrono::Utc::now();
    let session_id = Uuid::new_v4();
    let session_id_bytes: &[u8] = &session_id.as_bytes()[..];
    let user_id: Uuid = {
        let user_id = Uuid::new_v4();
        let user_id_bytes: &[u8] = &user_id.as_bytes()[..];
        let bytes: Option<Vec<u8>> = sqlx::query_scalar!(
            "
insert into
    users (user_id, handle, created_at, last_updated)
values ($1, $2, $3, $4)
on conflict(handle) do update set last_updated = $4
returning user_id",
            user_id_bytes,
            me.username,
            now,
            now,
        )
        .fetch_one(&mut *tx)
        .await?;
        if let Some(bytes) = bytes
        {
            Uuid::from_bytes(bytes.try_into().unwrap())
        }
        else
        {
            user_id
        }
    };
    let user_id_bytes = &user_id.as_bytes()[..];
    let _inserted = sqlx::query!(
        "
insert into
    discord_users (user_id, discord_id, username, avatar, locale, email)
values ($1, $2, $3, $4, $5, $6)
on conflict(discord_id) do nothing", // FIXME(hqhs): do nothing instead of updating correct fields
        user_id_bytes,
        me.id,
        me.username,
        me.avatar,
        me.locale,
        me.email,
    )
    .execute(&mut *tx)
    .await?;
    // TODO: limit amount of active sessions for single user
    let _inserted = sqlx::query!(
        "
insert into
    sessions (session_id, user_id, last_updated)
values ($1, $2, $3)",
        session_id_bytes,
        user_id_bytes,
        now,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(session_id)
}

async fn discord_callback(
    query: Query<OauthCallbackPayload>,
    jar: CookieJar,
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    let session_id = discord_callback_inner(&query, &cx)
        .await
        .map_err(|e| cx.log_error(e))?;
    info!(cx.log, "authorized user from discord; {session_id}");
    let cookie = Cookie::build(SESSION_ID_COOKIE, session_id.to_string())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax) // NOTE: SameSite::Strict doesn't work properly for some reason; also, since auth is stateful sessions, Lax is fine
        .path("/")
        // .max_age(Duration::from_secs(24)) // FIXME(hqhs): wtf is with the import
        .finish();
    let response: Result<_, AppError> =
        Ok((jar.add(cookie), Redirect::to(PROFILE_PAGE)));
    response
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

/*
 * SECTION: TWICH
 */

pub const TWITCH_CALLBACK: &str = "/login/twitch_callback";

async fn twitch_callback(
    query: Query<OauthCallbackPayload>,
    Extension(cx): Extension<RequestContext>,
) -> impl IntoResponse
{
    // NOTE: twitch sucks ass
    let params = [
        ("client_id", cx.server.config.twitch_client_id.clone()),
        ("client_secret", cx.server.config.twitch_client_secret.clone()),
        ("grant_type", "authorization_code".to_owned()),
        (
            "redirect_uri",
            "http://localhost:3000/login/twitch_callback".to_owned(),
        ),
        ("code", query.code.clone()),
    ];
    let response = match cx
        .server
        .client
        .post("https://id.twitch.tv/oauth2/token")
        .form(&params)
        .send()
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
    let text = response.text().await;
    dbg!(text);

    // NOTE: twitch REALLY sucks ass
    // let token = match cx
    //     .server
    //     .discord_auth_client
    //     .exchange_code(AuthorizationCode::new(query.code.clone()))
    //     .add_extra_param("client_id", &cx.server.config.twitch_client_id)
    //     .add_extra_param(
    //         "client_secret",
    //         &cx.server.config.twitch_client_secret,
    //     )
    //     .add_extra_param("grant_type", "authorization_code")
    //     .add_extra_param(
    //         "redirect_uri",
    //         "http://localhost:3000/login/twitch_callback",
    //     )
    //     .request_async(async_http_client)
    //     .await
    // {
    //     Ok(res) => res,
    //     Err(e) =>
    //     {
    //         error!(cx.log, "An error occured while exchanging the code: {e}");
    //         dbg!(e);
    //         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    //     }
    // };
    // trace!(cx.log, "twitch login successful";
    //        "token" => token.access_token().secret().to_owned());
    // let response = match cx
    //     .server
    //     .client
    //     .get("https://api.twitch.tv/helix/users")
    //     .bearer_auth(token.access_token().secret().to_owned())
    //     .send()
    //     .await
    // {
    //     Ok(res) => res,
    //     Err(e) =>
    //     {
    //         error!(cx.log, "An error occured while reqwesting user info: {e}");
    //         dbg!(e);
    //         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    //     }
    // };
    // let test = response.text().await.unwrap();
    // trace!(cx.log, "user info"; "response" => test);
    Ok("not implemented")
}
