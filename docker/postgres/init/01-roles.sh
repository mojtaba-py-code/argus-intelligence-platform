#!/bin/sh
# Runs once, as the PostgreSQL superuser, when the data volume is first initialised.
# Creates the two application roles that mirror production:
#   argus_owner - owns the schema; used only by `argus db migrate`
#   argus_app   - runtime role: no DDL, no BYPASSRLS, no superuser
# Passwords arrive as environment variables and are bound as psql variables (:'name'), so a quote
# in a password can never break out of the SQL literal.
set -eu

: "${POSTGRES_OWNER_PASSWORD:?POSTGRES_OWNER_PASSWORD must be set}"
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_pw="$POSTGRES_OWNER_PASSWORD" -v app_pw="$POSTGRES_APP_PASSWORD" <<'EOSQL'
CREATE ROLE argus_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE argus_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE argus OWNER argus_owner;
REVOKE ALL ON DATABASE argus FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE argus TO argus_app;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname argus <<'EOSQL'
CREATE EXTENSION IF NOT EXISTS vector;
EOSQL
