use anyhow;
use utoipa::OpenApi;

use template::{login_options_json, LoginOptionsPayload};

fn main() -> anyhow::Result<()>
{
    #[derive(OpenApi)]
    #[openapi(
        paths(template::login_options_json,),
        components(schemas(LoginOptionsPayload),)
    )]
    struct ApiDoc;

    println!("{}", ApiDoc::openapi().to_pretty_json().unwrap());

    Ok(())
}
