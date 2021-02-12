#!/bin/bash

source .env

# Display result...
docker exec my-ldap ldapsearch -x -H ldap://localhost -b "${LDAP_BASE_DN:-dc=example,dc=org}"
