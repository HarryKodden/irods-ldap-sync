#!/bin/bash

(cd etc/irods; docker build -t irods_4.2.8 -f Dockerfile.centos .)

docker tag irods_4.2.8:latest harrykodden/irods_4.2.8:latest
