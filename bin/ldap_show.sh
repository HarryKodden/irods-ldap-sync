#!/bin/bash

if test -f ".env"; then
  source .env
else
  source .test.env
fi

# Display result...
docker exec my-ldap ldapsearch -x -H ldap://localhost -b "${LDAP_BASE_DN:-dc=example,dc=org}"
