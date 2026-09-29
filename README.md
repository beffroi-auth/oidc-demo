# Démonstration OIDC

Application Symfony qui sert de client de référence à l'OpenID Provider de [beffroi-php/heidi](https://github.com/beffroi-php/heidi), sur l'authenticator `oidc_login` du cœur de Symfony. Elle est jouée par `castor demo` du dépôt du fournisseur, un drapeau par chose démontrée, et c'est là que se vérifie ce que le fournisseur émet : ce qui arrive ici doit être consommable sans aucun correctif de `oidc_login`.

Elle est trois choses à la fois :

- **Le client.** Le firewall `main` sur `oidc_login` : connexion, `/profile`, `/vault` qui exige une classe d'authentification, déconnexion RP-Initiated et Back-Channel.
- **Le serveur de ressources.** Six firewalls sous `/api/`, sur l'access token que le client a obtenu. Quatre ne diffèrent que par la façon de le vérifier : par introspection (`/api/me`), par introspection signée (`/api/me/signed`), et deux fois avec un jeton lié par DPoP, la liaison lue sur l'`at+jwt` (`/api/me/dpop`) ou dans la réponse d'introspection (`/api/me/dpop/introspected`). Les deux autres démontrent autre chose : `/api/me/offline` ce qu'un `at+jwt` vérifié hors ligne continue de servir après la fin de la session, et `/api/service` le refus d'un jeton adressé ailleurs.
- **L'échelle de clients.** Six barreaux sous `/c/<barreau>`, un client du fournisseur et un firewall chacun, de celui qui met toute la requête d'autorisation dans l'URL d'un navigateur à celui qui la pousse signée, lit une réponse signée, tient un jeton lié et ouvre un ID token chiffré. Ce que chaque barreau ajoute est dans `src/Ladder/Rungs.php`. Le dernier n'est pas un firewall `oidc_login` : ce qu'il demande est ce que l'authenticator ne sait pas encore faire, donc c'est un client de laboratoire à lui, sous `src/Security/Fapi/`.

## Sur quoi elle tourne

Symfony 8.2, qui n'est pas taguée : `8.2.x-dev` est la seule version de cette branche, et `minimum-stability: dev` avec `prefer-stable: true` est ce qui la résout.

Trois paquets de sécurité ne viennent pas de Packagist mais d'un worktree local, monté en `path` repository (liens symboliques), parce que la démonstration s'appuie sur quatre commits qui ne sont pas encore fusionnés :

```
~/Projects/symfony-oidc-pending                branche oidc-demo-pending
vendor/symfony/security-core   -> ../../../symfony-oidc-pending/src/Symfony/Component/Security/Core
vendor/symfony/security-http   -> ../../../symfony-oidc-pending/src/Symfony/Component/Security/Http
vendor/symfony/security-bundle -> ../../../symfony-oidc-pending/src/Symfony/Bundle/SecurityBundle
```

| Ce qui manque à 8.2 | Ce que la démonstration en fait | Où c'est |
|---|---|---|
| L'option `backchannel_logout` du firewall `oidc_login` | La déconnexion par canal arrière du firewall `main`, jouée par `castor demo --logout-others` | [#66196](https://github.com/symfony/symfony/pull/66196) |
| L'option `dpop` de `oidc_login`, et le type du jeton d'accès | Le barreau `fapi` de l'échelle, qui lie son jeton à une clé qu'il détient | [#66239](https://github.com/symfony/symfony/pull/66239), deux commits |
| L'option `dpop` de l'authenticator `access_token` | Les deux firewalls `api_dpop*`, qui n'acceptent un jeton lié que de qui prouve la clé | branche `security-dpop-resource-server`, ligne `RS-05` du document de statut, aucune pull request ouverte |

Tout le reste vient de 8.2 telle quelle, la réponse `form_post` et la lecture de `acr` comprises.

Reconstruire la branche sur une 8.2 fraîche :

```bash
cd ~/Projects/symfony
git fetch upstream 8.2 \
  refs/pull/66196/head:refs/remotes/upstream/pr-66196 \
  refs/pull/66239/head:refs/remotes/upstream/pr-66239 --force
cd ~/Projects/symfony-oidc-pending
git checkout -B oidc-demo-pending upstream/8.2
git cherry-pick upstream/pr-66196            # la déconnexion par canal arrière
git cherry-pick upstream/pr-66239~1 upstream/pr-66239   # DPoP côté client
git cherry-pick security-dpop-resource-server           # DPoP côté serveur de ressources
cd ~/Projects/oidc-demo && php bin/console cache:clear
```

Les seuls conflits attendus sont dans les `CHANGELOG.md`, où les entrées s'ajoutent les unes aux autres.

## Le coffre

`/vault` est la route qui exige une classe d'authentification et non un rôle : une session ouverte avec un mot de passe seul est renvoyée au fournisseur pour une passkey (OpenID Connect EAP ACR Values 1.0). Elle tourne entièrement sur 8.2, en trois pièces sous `src/Security/Acr/` :

- `AcrVoter` vote sur l'attribut `REQUIRES_PHR` de la règle `access_control`, en lisant `oidc_acr`, l'attribut du token de sécurité où `oidc_login` enregistre la revendication `acr` de l'ID token.
- `AcrReAuthenticationHandler` est l'`access_denied_handler` du firewall : il démarre la ré-authentification. `ExceptionListener` ne la démarre de lui-même que pour `IS_AUTHENTICATED_RECENTLY` et `IS_AUTHENTICATED_VERY_RECENTLY`, deux noms qu'il détient, donc l'attribut propre à une application est répondu par elle.
- `AcrValuesListener` ajoute `acr_values` à la requête d'autorisation, et seulement sur la ré-authentification que le handler a démarrée. Le `prompt=login` et l'`id_token_hint` viennent de `startReAuthentication()`.

Les classes qui répondent pour la route sont le paramètre `app.acr.accepted_classes`, en un seul endroit : le voter accorde sur elles et le listener les demande au fournisseur, dans cet ordre.

La pull request [#66235](https://github.com/symfony/symfony/pull/66235) déplace vers le point d'entrée la liste des refus qui démarrent une ré-authentification. Le jour où elle est fusionnée, le handler devient un point d'entrée décoré qui répond pour `REQUIRES_PHR`, et le reste ne change pas.

## Configuration

- `config/packages/security.yaml` : le provider `oidc`, le firewall `main` avec `oidc_login` et `logout`, les six firewalls de l'échelle, les cinq du serveur de ressources, et l'`access_control` où `^/vault` demande `REQUIRES_PHR`.
- `config/routes/security.yaml` : l'import du route loader `security.authenticator.oidc_login.route_loader`, qui déclare `/oidc/callback` et la route en POST de la déconnexion par canal arrière.
- `.env` : les identifiants de clients et les URI. **Aucun secret n'est committé** : les valeurs que le fournisseur engendre vivent dans `.env.local`, que `castor demo` écrit et que git ignore, comme le `php.ini` qui fait confiance à l'autorité de certification de son Caddy.

## Lancer

Depuis le dépôt du fournisseur, ce qui pointe la démonstration sur l'OP de développement et la démarre :

```bash
castor start
castor provision
castor demo --check
```

Chaque drapeau de `castor demo` joue une chose de bout en bout : `--check` une connexion et une déconnexion, `--passkey` le passage à `acr=phr` par `/vault`, `--form-post` la réponse postée depuis une autre origine, `--logout-others` une seconde instance déconnectée par canal arrière, `--resource-server` les cinq routes de l'API, `--dpop` un jeton lié à une clé, `--ladder` les six barreaux l'un après l'autre.

À la main, sans le fournisseur :

```bash
symfony server:start --port=8002 --daemon
symfony server:log
```

- `https://localhost:8002/` : page publique, état de la session, rappel de la configuration.
- `https://localhost:8002/profile` : page protégée, déclenche le flow ; affiche l'`OidcUser`, les claims UserInfo, l'ID token et l'access token décodés.
- `https://localhost:8002/vault` : le coffre ; affiche `acr`, `amr`, `auth_time`, `sid` et les preuves que `oidc_login` a enregistrées sur le token de sécurité.
- `https://localhost:8002/login` : `login_path` et `failure_path`, affiche l'erreur d'authentification.
- `https://localhost:8002/` liste les barreaux de l'échelle, chacun servi sous `/c/<barreau>/profile`.
