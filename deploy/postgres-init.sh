#!/bin/sh
# Premier démarrage seulement : rôle dédié à cocon-api, sans privilèges
# ailleurs, propriétaire de sa base.
set -eu
psql -v ON_ERROR_STOP=1 -U postgres <<SQL
CREATE ROLE cocon_api LOGIN PASSWORD '$COCON_DB_PASSWORD';
CREATE DATABASE cocon_api OWNER cocon_api;
REVOKE ALL ON DATABASE cocon_api FROM PUBLIC;
SQL
