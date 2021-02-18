FROM gitpod/workspace-full

RUN sudo apt-get update && sudo apt-get install -y libsasl2-dev libldap2-dev ldap-utils
RUN ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''
