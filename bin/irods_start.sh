#!/bin/bash

if test -f ".env"; then
  source .env
else
  source .test.env
fi

bin/irods_stop.sh 2>&1 >/dev/null

# Start iRODS server

VER="4.0.3"

docker run \
  --name my-irods-icat \
  --publish "${IRDDS_PORT:-1247}":1247 \
  --rm \
  --detach \
  irods/icat:$VER "${IRDDS_PASS:-password}"

icat=$(docker inspect my-irods-icat | grep IPAddress | grep -v null | cut -d '"' -f 4 | head -1)

docker run \
  --name my-irods-icommands \
  --rm \
  --detach \
  --publish "${SSH_PORT:-2222}":22 \
  --add-host icat:${icat} \
  --entrypoint /opt/icommands-start.sh \
  --env IRODS_HOST=icat \
  --env IRODS_PORT=${IRDDS_PORT:-1247} \
  --env IRODS_USER=${IRODS_USER:-rods} \
  --env IRODS_ZONE=${IRODS_ZONE:-tempZone} \
  -v $(pwd)/bin/icommands-start.sh:/opt/icommands-start.sh \
  -v ~/.ssh/id_rsa.pub:/tmp/authorized_keys \
  irods/icommands:$VER

#  --network host \
