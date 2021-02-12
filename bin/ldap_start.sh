#!/bin/bash

source .env

bin/ldap_stop.sh 2>&1 >/dev/null

# Start LDAP server
docker run \
  --name my-ldap \
  --env LDAP_DOMAIN="${LDAP_DOMAIN:-example.org}" \
  --env LDAP_BASE_DN="${LDAP_BASE_DN:-dc=example,dc=org}" \
  --env LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-changeme}" \
  --env LDAP_CONFIG_PASSWORD="${LDAP_CONFIG_PASSWORD:-changeme}" \
  --env LDAP_TLS=true \
  --publish 389:389 \
  --rm \
  --detach \
  osixia/openldap:latest --loglevel debug --copy-service

# copy LDIF files into running container...
docker cp etc/ldif my-ldap:/tmp

sleep 5

# Add schemas
docker exec my-ldap ldapadd -H ldap://localhost -D cn=admin,cn=config -w "${LDAP_CONFIG_PASSWORD:-changeme}" -f /tmp/ldif/access.ldif
docker exec my-ldap ldapadd -H ldap://localhost -D cn=admin,cn=config -w "${LDAP_CONFIG_PASSWORD:-changeme}" -f /tmp/ldif/eduPerson.ldif
docker exec my-ldap ldapadd -H ldap://localhost -D cn=admin,cn=config -w  "${LDAP_CONFIG_PASSWORD:-changeme}" -f /tmp/ldif/voPerson.ldif
docker exec my-ldap ldapadd -H ldap://localhost -D cn=admin,cn=config -w  "${LDAP_CONFIG_PASSWORD:-changeme}" -f /tmp/ldif/groupOfMembers.ldif

# Add service...
docker exec my-ldap ldapadd -H ldap://localhost -D "${LDAP_BIND_DN:-cn=admin,dc=example,dc=org}" -w  "${LDAP_ADMIN_PASSWORD:-changeme}" -f /tmp/ldif/service.ldif
