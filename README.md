# OIDC demonstration

A Symfony application that shows every feature of the OpenID Provider of [beffroi-auth/beffroi](https://github.com/beffroi-auth/beffroi) working. It is organised as a tree of those features: each one faces a client, shows the configuration of that client, runs it against the provider and ticks every step it took. It is also the reference client of the provider on the `oidc_login` authenticator of the Symfony core: whatever the provider emits must be consumable here without any patch of `oidc_login`. `castor demo` of the provider's repository plays it from the command line, one flag per thing demonstrated.

## The tree

The tree is on every page, grouped: sign in, client authentication, tokens, protecting an API, documents, sign out, the grants that need no browser, and FAPI 2.0. `/f/<feature>` shows one feature:

- the one line that says what its client does;
- the configuration of that client, the members that make the feature highlighted;
- **Run**, which runs the client against the provider;
- the proof: every step of the last run in this browser, ticked, with what travelled.

A square beside each feature says whether its client worked the last time it ran in this browser, failed, never ran, or is not offered by the provider (what the discovery document does not announce is not offered). A failure shows what the provider answered, in its words.

The catalogue is `src/Showcase/Catalogue.php`. A feature faces one of four kinds of client, each a class implementing `FeatureClientInterface`:

| Kind | What it is | Where |
|---|---|---|
| Reference client | The `main` firewall on `oidc_login`, configured and never coded; its configuration is read from `config/packages/security.yaml` | `src/Showcase/Reference/` |
| Forged client | A composition of the forge, registered at the provider the first time it runs (RFC 7591) and played by the `forge` firewall; its configuration is its preset, highlighted where it differs from "Code + PKCE" | `src/Forge/Presets.php`, `src/Showcase/Forged/` |
| API client | Swagger UI, or the page of a signed-in session, calling the API of `/api/v1`; the proof is the journal of the calls the API answered | `src/Showcase/Api/` |
| Grant without a browser | Client credentials, token exchange, device code, CIBA and JWT bearer, played by this application's server; the device code and CIBA wait while the user approves at the provider, and the page asks again at the interval the provider named | `src/Showcase/Grant/` |

The look follows the brand guidelines of Beffroi. The fonts (Chakra Petch, Archivo, Martian Mono) are under the SIL Open Font License, their licences beside them in `assets/fonts/`.

## The reference client

The `main` firewall on `oidc_login`: `/profile`, RP-Initiated and Back-Channel logout, and `/vault`, a route that requires an authentication context class rather than a role. A session opened with a password alone is sent back to the provider for a passkey (OpenID Connect EAP ACR Values 1.0), in three pieces under `src/Security/Acr/`:

- `AcrVoter` votes on the `REQUIRES_PHR` attribute of the `access_control` rule, reading the `acr` `oidc_login` recorded on the security token;
- `AcrReAuthenticationHandler`, the `access_denied_handler` of the firewall, starts the re-authentication, which `ExceptionListener` starts by itself only for the two attributes it holds;
- `AcrValuesListener` adds `acr_values` to that request, `prompt=login` and `id_token_hint` coming from `startReAuthentication()`.

The classes that answer for the route are the `app.acr.accepted_classes` parameter. Pull request [#66235](https://github.com/symfony/symfony/pull/66235) moves to the entry point the list of denials that start a re-authentication; once it is merged, the handler becomes a decorated entry point and the rest does not change.

## The API

API Platform under `/api/v1`: the invoices of whoever the token names, kept in the cache pool of the application (`src/ApiResource/`, `src/State/`, `src/Invoice/`). Each operation needs a scope, voted on by `OAUTH2_SCOPE` against the scopes the token was granted, and a token without it is refused with the `insufficient_scope` challenge of RFC 6750 section 3.1.

A token gets in one of two ways (`src/Api/AddressedHereOrDescribed.php`):

- **addressed to the API** (RFC 8707, its `aud` is `API_RESOURCE`): an `at+jwt` the API verifies itself against the keys of the provider (RFC 9068), asking nothing;
- **any other token**: described by the provider (RFC 7662), which describes a token only to the client it was issued to, so the API asks as each client whose secret this application holds (`src/Api/WhicheverClientKnowsTheToken.php`), and keeps the answer of an active token for `app.api.introspection_cache_ttl` seconds.

`/api/v1/docs` is Swagger UI. Its **Authorize** button runs the authorization code flow with PKCE as a public client the demonstration registers, asking for a token addressed to the API. The endpoints come from the discovery document (`src/Api/OpenApi/TheProviderOfTheFlow.php`) and the client identifier is written into the page when it is rendered (`templates/bundles/ApiPlatformBundle/SwaggerUi/index.html.twig`). The page asks for `openid` beside the scopes of the API, the provider refusing an authorization request without it, and leaves out of its token request the `X-Requested-With` header the provider does not allow across origins. Each operation declares its scope in the OpenAPI document. A token can also be pasted under `bearer`.

`/api-calls` calls the API from a page with the access token of the session. The six routes under `/api/me` and `/api/service` are the resource server of the reference client, one way of checking the same token each: introspection, signed introspection, `at+jwt` verified offline, two tokens bound by DPoP, and a token addressed elsewhere.

## The forge

`/forge` composes a client option by option out of what the provider announces, registers it on the spot (RFC 7591), signs in with it under `/c/<handle>/` and deletes it again (RFC 7592). The page of a built client says which gap of `oidc_login` its composition would hit (`src/Forge/WhatOidcLoginCannotServe.php`).

## What it runs on

Symfony 8.2 at its second beta, `v8.2.0-BETA2`: `minimum-stability: beta` with `prefer-stable: true` resolves it, and `composer update` takes 8.2.0 the day it is tagged. Every package comes from Packagist.

## Configuration

`.env` holds the identifiers and URIs; **no secret is committed**, the values a provider hands out live in `.env.local`, which git ignores.

| Variable | What it is |
|---|---|
| `OIDC_PROVIDER_URI`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | The provider and the reference client |
| `OIDC_INTROSPECTION_URI` | The introspection endpoint of the provider |
| `API_RESOURCE` | The identifier of the API (RFC 8707), `https://localhost:8002/api/v1` by default |
| `FORGE_INITIAL_ACCESS_TOKEN` | The initial access token every client of the tree is registered with (RFC 7591 section 1.2) |
| `EXCHANGE_INITIAL_ACCESS_TOKEN` | The one the gateway of the token exchange is registered with |
| `JWT_BEARER_ISSUER` | The issuer this demonstration plays for the JWT bearer grant |

The APIs a client may ask a token for and the token exchange are the initial access token's to grant, never the client's to register. On Beffroi:

```bash
# every client of the tree; the API as a resource they may ask a token for
bin/console beffroi:client:token:issue demo --registrations 60 --days 7 --resource https://localhost:8002/api/v1
# the gateway of the token exchange: a token granting the exchange gives it to every client it registers
bin/console beffroi:client:token:issue exchange --resource https://localhost:8002/api/v1 \
    --exchange-subject-token-type urn:ietf:params:oauth:token-type:access_token
```

CIBA names the user by the `sub` the provider issued, known once the user signed in with the reference client. The JWT bearer grant works once the tenant trusts the issuer this demonstration plays: its panel shows the entry of `BEFFROI_TRUSTED_ISSUERS` to set and the user to link.

## Running it

From the provider's repository, which points the demonstration at the development provider and starts it:

```bash
castor start
castor provision
castor demo --check
```

Each flag of `castor demo` plays one thing end to end; the `AGENTS.md` of the provider's repository describes them.

Against any provider, with its values in `.env.local`:

```bash
symfony server:start --port=8002 --daemon
```

The reference client is registered with `https://localhost:8002/oidc/callback`, `https://localhost:8002/` to come back to after a logout, and `https://localhost:8002/oidc/backchannel-logout`. A provider on the Internet cannot post a back-channel logout to a demonstration on `localhost`, and a provider behind a proxy that terminates TLS never sees the certificate of a client: those features need the demonstration published, or a provider that sees the connection.

## Published

The `Dockerfile` builds the demonstration as it is published: FrankenPHP serving `public/` over plain HTTP on port 8080, as `www-data`, behind a proxy that terminates TLS. The workflow `image.yml`, asked for by hand, publishes `ghcr.io/beffroi-auth/oidc-demo` from `main`, for amd64 and arm64.

A container reads its provider, its clients and its API from the environment, the variables above with `APP_SECRET`, and the proxy it trusts from `SYMFONY_TRUSTED_PROXIES`, `SYMFONY_TRUSTED_HEADERS` and `SYMFONY_TRUSTED_HOSTS`.
