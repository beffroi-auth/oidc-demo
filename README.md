# OIDC demonstration

A Symfony application that is the reference client of the OpenID Provider of [beffroi-auth/beffroi](https://github.com/beffroi-auth/beffroi), on the `oidc_login` authenticator of the Symfony core. It is played by `castor demo` of the provider's repository, one flag per thing demonstrated, and it is where what the provider emits is checked: whatever arrives here must be consumable without any patch of `oidc_login`.

It is four things at once:

- **The client.** The `main` firewall on `oidc_login`: login, `/profile`, `/api-calls` where the access token of the session is used against the API, `/vault` which requires an authentication context class, RP-Initiated and Back-Channel logout. The topbar lists those pages whether or not a session is open: following one of them when there is none is how a sign-in starts.
- **The resource server.** Six firewalls under `/api/`, on the access token the client obtained. Four differ only in how it is checked: by introspection (`/api/me`), by signed introspection (`/api/me/signed`), and twice with a token bound by DPoP, the binding read from the `at+jwt` (`/api/me/dpop`) or from the introspection response (`/api/me/dpop/introspected`). The other two demonstrate something else: `/api/me/offline` what an `at+jwt` verified offline keeps serving after the session ended, and `/api/service` the refusal of a token addressed elsewhere.
- **The API.** API Platform under `/api/v1`, behind one firewall of its own (beffroi-auth/beffroi#556): the access token a client sends is described by the provider at every request (RFC 7662), through the same introspection endpoint as `/api/me`, and the answer of an active token is kept the few seconds `config/services.yaml` names. What each operation needs is a scope, read from that answer: `invoices.read` for the collection and one invoice, `invoices.pay` for a payment, `invoices.write` for an invoice written, which the client registered and never asks for, so a write is refused with the `insufficient_scope` challenge of RFC 6750 section 3.1. The invoices of whoever the token names live in the cache pool of the application; there is no entity and no database. The resources are in `src/ApiResource/`, their state in `src/State/`, the book in `src/Invoice/`. `/api-calls` is where it is used from a browser: the page carries the access token of the session, declares the five calls (`src/Api/Console/`), and a Stimulus controller sends each one with that token and shows the answer as it came back, the challenge of a refusal included; the same call is written out as a command line for a browser that runs nothing. A token pasted in its place works too. The documentation at `/api/v1/docs` carries an `Authorize` button for the bearer token of RFC 6750 section 2.1, and each operation says which scope the token has to carry, read from the `security` expression that enforces it (`src/Api/ScopesOfTheOperation.php`). The token to paste is one a client this demonstration declares was issued, the one `/profile` shows for instance: the provider describes a token to the client it was issued to and to no other (RFC 7662 section 2.2), so the API asks it as each client whose secret this application holds (`src/Api/WhicheverClientKnowsTheToken.php`, the list in `config/services.yaml`). The token of a client the forge built is refused, that client being registered at runtime. No authorization code flow is offered in the page: it runs in a browser, so the client it signed in as would hold its secret there.
- **The forge of clients.** The home page, where a client is composed option by option out of what the discovery document of the provider announces, registered on the spot (RFC 7591), signed in with under `/c/<handle>/`, and deleted again (RFC 7592). Eight presets fill the form in one click (`src/Forge/Presets.php`), from the client that puts the whole authorization request in the URL of a browser to the FAPI 2.0 one that pushes it signed, reads a signed response, holds a bound token and opens an encrypted ID token. A client born at runtime cannot be a firewall of the configuration, so every one of them is played by the one `forge` firewall and its authenticator (`src/Security/Forge/`), and the page of a built client says which gap of `oidc_login` that composition would hit, if any (`src/Forge/WhatOidcLoginCannotServe.php`). On a provider whose registration asks for an initial access token (RFC 7591 section 1.2), the forge reads it from `FORGE_INITIAL_ACCESS_TOKEN`.

## What it runs on

Symfony 8.2 at its second beta, `v8.2.0-BETA2`: `minimum-stability: beta` with `prefer-stable: true` is what resolves it, and `composer update` takes 8.2.0 the day it is tagged, with no change of `composer.json`. Every package comes from Packagist: the back-channel logout of `oidc_login` ([#66196](https://github.com/symfony/symfony/pull/66196)), its binding of a token to a key ([#66239](https://github.com/symfony/symfony/pull/66239)) and the `dpop` option of the `access_token` authenticator are part of 8.2.

## The vault

`/vault` is the route that requires an authentication context class rather than a role: a session opened with a password alone is sent back to the provider for a passkey (OpenID Connect EAP ACR Values 1.0). It runs entirely on 8.2, in three pieces under `src/Security/Acr/`:

- `AcrVoter` votes on the `REQUIRES_PHR` attribute of the `access_control` rule, reading `oidc_acr`, the attribute of the security token where `oidc_login` records the `acr` claim of the ID token.
- `AcrReAuthenticationHandler` is the `access_denied_handler` of the firewall: it starts the re-authentication. `ExceptionListener` starts one by itself only for `IS_AUTHENTICATED_RECENTLY` and `IS_AUTHENTICATED_VERY_RECENTLY`, two names it holds itself, so an attribute belonging to an application is answered by that application.
- `AcrValuesListener` adds `acr_values` to the authorization request, and only on the re-authentication the handler started. The `prompt=login` and the `id_token_hint` come from `startReAuthentication()`.

The classes that answer for the route are the `app.acr.accepted_classes` parameter, in one place: the voter grants on them and the listener asks the provider for them, in that order.

Pull request [#66235](https://github.com/symfony/symfony/pull/66235) moves to the entry point the list of denials that start a re-authentication. The day it is merged, the handler becomes a decorated entry point answering for `REQUIRES_PHR`, and the rest does not change.

## Configuration

- `config/packages/security.yaml`: the `oidc` provider, the `main` firewall with `oidc_login` and `logout`, the `forge` firewall of the clients the forge builds, the six of the resource server and the one of the API, and the `access_control` where `^/vault` asks for `REQUIRES_PHR`.
- `config/routes/security.yaml`: the import of the `security.route_loader` service, which declares the logout routes, `/oidc/start`, `/oidc/callback` and the POST route of the back-channel logout.
- `.env`: the client identifiers and the URIs. **No secret is committed**: the values the provider generates live in `.env.local`, which `castor demo` writes and git ignores, as does the `php.ini` that trusts the certificate authority of its Caddy.

## Running it

From the provider's repository, which points the demonstration at the development OP and starts it:

```bash
castor start
castor provision
castor demo --check
```

Each flag of `castor demo` plays one thing end to end. Those that go through this application: `--check` a sign-in and a sign-out, `--rotate` a whole key rotation against the running application, `--passkey` the step-up to `acr=phr` through `/vault`, `--form-post` the response posted from another origin, `--logout-others` a second instance logged out by back channel, `--resource-server` the routes behind an access token, `--api` the API and `/api-calls`, `--dpop` a token bound to a key, `--forge` every preset of the forge built, signed in with and deleted. The `AGENTS.md` of the provider's repository describes them all, and the flags whose clients are programs of the lab rather than this application.

By hand, without the provider:

```bash
symfony server:start --port=8002 --daemon
symfony server:log
```

- `https://localhost:8002/`: the forge, whose built clients are served under `/c/<handle>/profile`.
- `https://localhost:8002/profile`: a protected page, which starts the flow; it shows the `OidcUser`, the UserInfo claims, and the ID token and access token decoded.
- `https://localhost:8002/vault`: the vault; it shows `acr`, `amr`, `auth_time`, `sid` and the proofs `oidc_login` recorded on the security token.
- `https://localhost:8002/login`: `login_path` and `failure_path`, which shows the authentication error.

## Published

The `Dockerfile` builds the demonstration as it is published: FrankenPHP serving `public/` over plain HTTP on port 8080, as `www-data`, behind a proxy that terminates TLS. The workflow `image.yml`, asked for by hand, publishes `ghcr.io/beffroi-auth/oidc-demo` from `main`, for amd64 and arm64.

A container reads its provider and its client from the environment: `APP_SECRET`, `OIDC_PROVIDER_URI`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_INTROSPECTION_URI`, and the proxy it trusts from `SYMFONY_TRUSTED_PROXIES`, `SYMFONY_TRUSTED_HEADERS` and `SYMFONY_TRUSTED_HOSTS`. Its client is registered with `https://<host>/oidc/callback`, `https://<host>/` to come back to after a logout, and `https://<host>/oidc/backchannel-logout`, where the provider posts its logout tokens.
