#!/bin/bash

# Kill previous server

docker stop my-irods-icat || true
docker stop my-irods-icommands || true
