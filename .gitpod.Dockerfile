FROM gitpod/workspace-full

# Install custom tools, runtimes, etc.
# For example "bastet", a command-line tetris clone:
# RUN brew install bastet
#
# More information: https://www.gitpod.io/docs/config-docker/

RUN apt-get update && sudo apt-get install -y libsasl2-dev libldap2-dev ldap-utils
RUN ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''
