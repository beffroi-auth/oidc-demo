# OIDC demonstration

A Symfony application that is the reference client of the OpenID Provider of [beffroi-php/beffroi](https://github.com/beffroi-php/beffroi), on the `oidc_login` authenticator of the Symfony core. It is played by `castor demo` of the provider's repository, one flag per thing demonstrated, and it is where what the provider emits is checked: whatever arrives here must be consumable without any patch of `oidc_login`.

It is four things at once:

- **The client.** The `main` firewall on `oidc_login`: login, `/profile`, `/vault` which requires an authentication context class, RP-Initiated and Back-Channel logout.
- **The resource server.** Six firewalls under `/api/`, on the access token the client obtained. Four differ only in how it is checked: by introspection (`/api/me`), by signed introspection (`/api/me/signed`), and twice with a token bound by DPoP, the binding read from the `at+jwt` (`/api/me/dpop`) or from the introspection response (`/api/me/dpop/introspected`). The other two demonstrate something else: `/api/me/offline` what an `at+jwt` verified offline keeps serving after the session ended, and `/api/service` the refusal of a token addressed elsewhere.
- **The API.** API Platform under `/api/v1`, behind one firewall of its own (beffroi-php/beffroi#556): the access token a client sends is described by the provider at every request (RFC 7662), through the same introspection endpoint as `/api/me`, and the answer of an active token is kept the few seconds `config/services.yaml` names. What each operation needs is a scope, read from that answer: `invoices.read` for the collection and one invoice, `invoices.pay` for a payment, `invoices.write` for an invoice written, which the client registered and never asks for, so a write is refused with the `insufficient_scope` challenge of RFC 6750 section 3.1. The invoices of whoever the token names live in the cache pool of the application; there is no entity and no database. The resources are in `src/ApiResource/`, their state in `src/State/`, the book in `src/Invoice/`. The documentation at `/api/v1/docs` carries an `Authorize` button for the bearer token of RFC 6750 section 2.1, and each operation says which scope the token has to carry, read from the `security` expression that enforces it (`src/Api/ScopesOfTheOperation.php`). The token to paste is one the provider issued to the client this API introspects as: a token obtained for another client, a rung of the ladder for instance, is reported inactive here (RFC 7662 section 2.2) and refused. No authorization code flow is offered in the page, and none could be: a client the documentation signed in as would be a public client of its own, whose tokens this API cannot introspect.
- **The ladder of clients.** Six rungs under `/c/<rung>`, one client of the provider and one firewall each, from the one that puts the whole authorization request in the URL of a browser to the one that pushes it signed, reads a signed response, holds a bound token and opens an encrypted ID token. What each rung adds is in `src/Ladder/Rungs.php`. The last one is not an `oidc_login` firewall: what it asks for is what the authenticator cannot do yet, so it is a laboratory client of its own, under `src/Security/Fapi/`.

## What it runs on

Symfony 8.2, which is not tagged: `8.2.x-dev` is the only version of that branch, and `minimum-stability: dev` with `prefer-stable: true` is what resolves it.

Three security packages do not come from Packagist but from a local worktree, mounted as `path` repositories (symbolic links), because the demonstration relies on four commits that are not merged yet:

```
~/Projects/symfony-oidc-pending                branch oidc-demo-pending
vendor/symfony/security-core   -> ../../../symfony-oidc-pending/src/Symfony/Component/Security/Core
vendor/symfony/security-http   -> ../../../symfony-oidc-pending/src/Symfony/Component/Security/Http
vendor/symfony/security-bundle -> ../../../symfony-oidc-pending/src/Symfony/Bundle/SecurityBundle
```

| What 8.2 lacks | What the demonstration does with it | Where it is |
|---|---|---|
| The `backchannel_logout` option of the `oidc_login` firewall | The back-channel logout of the `main` firewall, played by `castor demo --logout-others` | [#66196](https://github.com/symfony/symfony/pull/66196) |
| The `dpop` option of `oidc_login`, and the type of the access token | The `fapi` rung of the ladder, which binds its token to a key it holds | [#66239](https://github.com/symfony/symfony/pull/66239), two commits |
| The `dpop` option of the `access_token` authenticator | The two `api_dpop*` firewalls, which accept a bound token only from whoever proves the key | branch `security-dpop-resource-server`, line `RS-05` of the status document, no pull request open |

Everything else comes from 8.2 as it stands, the `form_post` response and the reading of `acr` included.

Rebuilding the branch on a fresh 8.2:

```bash
cd ~/Projects/symfony
git fetch upstream 8.2 \
  refs/pull/66196/head:refs/remotes/upstream/pr-66196 \
  refs/pull/66239/head:refs/remotes/upstream/pr-66239 --force
cd ~/Projects/symfony-oidc-pending
git checkout -B oidc-demo-pending upstream/8.2
git cherry-pick upstream/pr-66196                       # the back-channel logout
git cherry-pick upstream/pr-66239~1 upstream/pr-66239   # DPoP on the client side
git cherry-pick security-dpop-resource-server           # DPoP at the resource server
cd ~/Projects/oidc-demo && php bin/console cache:clear
```

The only conflicts to expect are in the `CHANGELOG.md` files, where the entries add up to one another.

## The vault

`/vault` is the route that requires an authentication context class rather than a role: a session opened with a password alone is sent back to the provider for a passkey (OpenID Connect EAP ACR Values 1.0). It runs entirely on 8.2, in three pieces under `src/Security/Acr/`:

- `AcrVoter` votes on the `REQUIRES_PHR` attribute of the `access_control` rule, reading `oidc_acr`, the attribute of the security token where `oidc_login` records the `acr` claim of the ID token.
- `AcrReAuthenticationHandler` is the `access_denied_handler` of the firewall: it starts the re-authentication. `ExceptionListener` starts one by itself only for `IS_AUTHENTICATED_RECENTLY` and `IS_AUTHENTICATED_VERY_RECENTLY`, two names it holds itself, so an attribute belonging to an application is answered by that application.
- `AcrValuesListener` adds `acr_values` to the authorization request, and only on the re-authentication the handler started. The `prompt=login` and the `id_token_hint` come from `startReAuthentication()`.

The classes that answer for the route are the `app.acr.accepted_classes` parameter, in one place: the voter grants on them and the listener asks the provider for them, in that order.

Pull request [#66235](https://github.com/symfony/symfony/pull/66235) moves to the entry point the list of denials that start a re-authentication. The day it is merged, the handler becomes a decorated entry point answering for `REQUIRES_PHR`, and the rest does not change.

## Configuration

- `config/packages/security.yaml`: the `oidc` provider, the `main` firewall with `oidc_login` and `logout`, the six firewalls of the ladder, the six of the resource server, and the `access_control` where `^/vault` asks for `REQUIRES_PHR`.
- `config/routes/security.yaml`: the import of the `security.authenticator.oidc_login.route_loader` service, which declares `/oidc/callback` and the POST route of the back-channel logout.
- `.env`: the client identifiers and the URIs. **No secret is committed**: the values the provider generates live in `.env.local`, which `castor demo` writes and git ignores, as does the `php.ini` that trusts the certificate authority of its Caddy.

## Running it

From the provider's repository, which points the demonstration at the development OP and starts it:

```bash
castor start
castor provision
castor demo --check
```

Each flag of `castor demo` plays one thing end to end: `--check` a sign-in and a sign-out, `--passkey` the step-up to `acr=phr` through `/vault`, `--form-post` the response posted from another origin, `--logout-others` a second instance logged out by back channel, `--resource-server` the routes of the API, `--dpop` a token bound to a key, `--ladder` the six rungs one after the other.

By hand, without the provider:

```bash
symfony server:start --port=8002 --daemon
symfony server:log
```

- `https://localhost:8002/` lists the rungs of the ladder, each served under `/c/<rung>/profile`.
- `https://localhost:8002/profile`: a protected page, which starts the flow; it shows the `OidcUser`, the UserInfo claims, and the ID token and access token decoded.
- `https://localhost:8002/vault`: the vault; it shows `acr`, `amr`, `auth_time`, `sid` and the proofs `oidc_login` recorded on the security token.
- `https://localhost:8002/login`: `login_path` and `failure_path`, which shows the authentication error.
