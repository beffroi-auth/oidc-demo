# Démo OIDC login (symfony/symfony#64954)

Application Symfony qui exerce l'authenticator `oidc_login` (Authorization Code Flow) proposé par la PR [symfony/symfony#64954](https://github.com/symfony/symfony/pull/64954), branchée sur le realm Keycloak `spomky-labs`.

## Comment la PR est installée

Le code de la PR est monté en *worktree* git, et les trois paquets qu'elle modifie sont installés en `path` repository (liens symboliques) :

```
~/Projects/symfony-pr64954                     worktree sur upstream/pr-64954
vendor/symfony/security-core   -> ../../../symfony-pr64954/src/Symfony/Component/Security/Core
vendor/symfony/security-http   -> ../../../symfony-pr64954/src/Symfony/Component/Security/Http
vendor/symfony/security-bundle -> ../../../symfony-pr64954/src/Symfony/Bundle/SecurityBundle
```

L'application tourne donc sur le code de la PR : `git fetch` + reset du worktree suffit pour tester une nouvelle version.

Les paquets de la PR requièrent `symfony/security-core: ^8.2` et `symfony/config: ^8.2` : le reste de l'application a donc été passé de `8.1.*` à `8.2.*` (`minimum-stability: dev`, `prefer-stable: true`).

Rafraîchir le worktree :

```bash
cd ~/Projects/symfony
git fetch upstream refs/pull/64954/head:refs/remotes/upstream/pr-64954 --force
git -C ~/Projects/symfony-pr64954 reset --hard upstream/pr-64954
cd ~/Projects/oidc-demo && php bin/console cache:clear
```

## Configuration

- `config/packages/security.yaml` : provider `oidc`, firewall `main` avec `oidc_login` et `logout`, `access_control` sur `^/profile` (`ROLE_USER`) et sur `^/vault` (`IS_AUTHENTICATED_IN_CONTEXT:phr` : une session dont l'ID token ne porte pas `acr=phr` est renvoyée au provider avec `acr_values=phr` et `prompt=login` par le point d'entrée de ré-authentification de `oidc_login` ; branche `security-acr-on-route` du worktree jusqu'à la fusion de la PR Symfony).
- `config/routes/security.yaml` : import du route loader `security.authenticator.oidc_login.route_loader`, qui déclare `/oidc/callback`.
- `.env` : `OIDC_PROVIDER_URI`, `OIDC_CLIENT_ID` ; le secret est dans `.env.local`.

Client Keycloak `demo` : `redirect_uris = ["https://localhost:8002/oidc/callback"]`, PKCE S256 imposé par le realm, authentification au token endpoint en `client_secret_post`.

## Lancer

```bash
symfony server:start --port=8002 --daemon
symfony server:log
```

- `https://localhost:8002/` : page publique, état de la session, rappel de la configuration.
- `https://localhost:8002/profile` : page protégée, déclenche le flow ; affiche l'`OidcUser`, les claims UserInfo, l'ID token et l'access token décodés.
- `https://localhost:8002/login` : `login_path` et `failure_path`, affiche l'erreur d'authentification.
- `https://localhost:8002/vault` : page protégée par une classe d'authentification ; affiche `acr`, `amr`, `auth_time`, `sid` et les preuves du token de sécurité que `oidc_login` a enregistrées.
