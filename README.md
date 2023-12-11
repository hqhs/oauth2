# Oauth2 example implementation using [prototyping template](https://github.com/hqhs/template)


## development

to install tailwind, follow [the instructions](https://tailwindcss.com/blog/standalone-cli)

``` sh
tailwindcss -o static/tailwind.css # generate css files for jinja templates
```

## oauth2 providers 

[Wikipedia list of oauth2 providers](https://en.wikipedia.org/wiki/List_of_OAuth_providers)

implemented:
- [discord](https://discord.com/developers/docs/topics/oauth2)
- [twitch](https://dev.twitch.tv/docs/authentication/)

planned:
- [microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [google](https://developers.google.com/identity/protocols/oauth2)
- [facebook]()
- [apple]()

maybe someday:
- [twitter]()
- [twitch]()
- [reddit]()
- [github]()

## helpful links

[how to implement oauth in rust](https://www.shuttle.rs/blog/2023/08/30/using-oauth-with-axum)
