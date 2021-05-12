#!/bin/bash

(cd etc/irods; docker build -t irods_4.2.8 -f Dockerfile.centos .)
