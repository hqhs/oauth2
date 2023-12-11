use std::env;

use template::{run_server, Config};

use dotenvy::dotenv;

#[tokio::main]
async fn main() -> anyhow::Result<()>
{
    dotenv().ok();

    let cfg = Config {
        dev_mode: true,

        google_oauth_client_id: env::var("GOOGLE_CLIENT_ID")?,
        google_oauth_client_secret: env::var("GOOGLE_CLIENT_SECRET")?,

        discord_oauth_client_id: env::var("DISCORD_CLIENT_ID")?,
        discord_oauth_client_secret: env::var("DISCORD_CLIENT_SECRET")?,

        twitch_client_id: env::var("TWITCH_CLIENT_ID")?,
        twitch_client_secret: env::var("TWITCH_CLIENT_SECRET")?,
    };

    run_server(cfg).await
}
