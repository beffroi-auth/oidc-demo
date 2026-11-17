# syntax=docker/dockerfile:1
ARG PHP_VERSION=8.5

# The demonstration as it is published: the main client of the provider and what it serves, behind a proxy that
# terminates TLS. Everything a deployment differs by comes from the environment of the container.
FROM dunglas/frankenphp:1-php${PHP_VERSION}

WORKDIR /app

RUN install-php-extensions \
    @composer \
    apcu \
    gmp \
    intl \
    opcache \
    sodium \
    zip

ENV APP_ENV=prod \
    COMPOSER_ALLOW_SUPERUSER=1 \
    SERVER_NAME=:8080

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY --link frankenphp/Caddyfile /etc/frankenphp/Caddyfile

# the dependencies first, so that a change of the code does not download them again
COPY --link composer.json composer.lock symfony.lock ./
RUN composer install --no-cache --prefer-dist --no-dev --no-autoloader --no-scripts --no-progress

COPY --link . ./

RUN set -eux; \
    composer dump-autoload --classmap-authoritative --no-dev; \
    composer dump-env prod; \
    composer run-script --no-dev post-install-cmd; \
    bin/console asset-map:compile; \
    mkdir -p var/log; \
    chown -R www-data:www-data var /data/caddy /config/caddy

USER www-data

HEALTHCHECK --start-period=30s CMD curl -fsS -o /dev/null http://localhost:2019/config/ || exit 1
