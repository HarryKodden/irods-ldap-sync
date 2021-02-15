FROM gitpod/workspace-full

RUN sudo apt-get update && sudo apt-get install -y libsasl2-dev libldap2-dev ldap-utils
RUN ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''

RUN cat > .env <<EOF
IRODS_PORT=1247
IRODS_USER=rods
IRODS_PASS=password
IRODS_ZONE=tempZone

SSH_USER=rods
SSH_HOST=localhost
SSH_PORT=2222

LDAP_HOST=ldap://localhost:1389
LDAP_ADMIN_PASSWORD=secret
LDAP_CONFIG_PASSWORD=config
LDAP_BASE_DN=dc=example,dc=org
LDAP_BIND_DN=cn=admin,dc=example,dc=org
EOF  
