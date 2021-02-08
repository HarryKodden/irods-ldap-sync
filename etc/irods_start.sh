#!/bin/bash

source .env

etc/irods_stop.sh 2>&1 >/dev/null

# Start iRODS server

docker run \
  --name my-irods \
  --publish "${IRDDS_PORT:-1247}":1247 \
  --rm \
  --detach \
  irods/icat:4.0.3 "${IRDDS_PASS:-password}"
