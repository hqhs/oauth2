use template::{setup_router, setup_server_state, Config};

use axum_test::TestServer;

#[tokio::test]
async fn home_page_test() -> anyhow::Result<()>
{
    let cfg = Config::default();
    let state = setup_server_state(cfg).await?;
    let router = setup_router(state.into())?;
    let server = TestServer::new(router)?;
    {
        let response = server.get("/cards").await;

        response.assert_status_ok();
    }
    Ok(())
}
