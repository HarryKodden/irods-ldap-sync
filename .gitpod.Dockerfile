FROM gitpod/workspace-full

RUN sudo apt-get update && sudo apt-get install -y libsasl2-dev libldap2-dev ldap-utils
RUN ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''

RUN echo $'\
IRODS_PORT=1247\n\
IRODS_USER=rods\n\
IRODS_PASS=password\n\
IRODS_ZONE=tempZone\n\
\n\
SSH_USER=rods\n\
SSH_HOST=localhost\n\
SSH_PORT=2222\n\
\n\
LDAP_HOST=ldap://localhost:1389\n\
LDAP_ADMIN_PASSWORD=secret\n\
LDAP_CONFIG_PASSWORD=config\n\
LDAP_BASE_DN=dc=example,dc=org\n\
LDAP_BIND_DN=cn=admin,dc=example,dc=org\n\
'>> .env
