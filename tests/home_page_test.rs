use anyhow;

use template::{setup_router, setup_server_state};

use axum_test::TestServer;

#[tokio::test]
async fn home_page_test() -> anyhow::Result<()>
{
    let state = setup_server_state().await?;
    let router = setup_router(state.into())?;
    let server = TestServer::new(router)?;
    {
        let response = server.get("/cards").await;

        response.assert_status_ok();
    }
    Ok(())
}
