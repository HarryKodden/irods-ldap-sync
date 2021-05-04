FROM ubuntu:18.04

ARG IRODS_VERSION=4.2.8
ARG IRODS_USER=rods

ENV TERM xterm-256color
ENV DEBIAN_FRONTEND=noninteractive
ENV IRODS_VERSION=$IRODS_VERSION

# INSTALL GENERIC...
RUN apt-get clean
RUN apt-get update 
RUN apt-get install -y apt-transport-https sudo wget git gnupg2 jq libxml2 moreutils vim lsb-release locales openssh-server

RUN locale-gen en_US.UTF-8
RUN update-locale

# PREPARE IRODS
RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - \
    && echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/renci-irods.list \
    && apt-get update && apt-get install -y \
    irods-database-plugin-postgres=$IRODS_VERSION \
    irods-runtime=$IRODS_VERSION  \
    irods-icommands=$IRODS_VERSION  \
    irods-server=$IRODS_VERSION \
    irods-dev=$IRODS_VERSION

# PREPARE SSHD
RUN mkdir /var/run/sshd \
    && sed -ie 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/g' /etc/ssh/sshd_config \
    && sed -ie 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config \
    && echo "sshd: ALL" >> /etc/hosts.allow \
    && useradd -m ${IRODS_USER} --shell /bin/bash \
    && usermod -aG sudo ${IRODS_USER} \
    && echo "${IRODS_USER} ALL=NOPASSWD: ALL" >> /etc/sudoers \
    && su - ${IRODS_USER} -c "ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''" \
    && su - ${IRODS_USER} -c "touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys" \
    && su - ${IRODS_USER} -c "mkdir .irods; sudo ln -s /usr/local/etc/irods/irods_environment.json .irods/irods_environment.json"

# PREPARE IRODS PLUGIN: PAM_INTERACTIVE
RUN apt-get install -y cmake gcc g++ python-pam libssl-dev libpam-dev
RUN cd /opt && git clone https://github.com/HarryKodden/irods_auth_plugin_pam_interactive && \
    cd /opt/irods_auth_plugin_pam_interactive && \
    cmake . && make && make install

CMD ["/usr/sbin/sshd", "-D"]
