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
    irods-server=$IRODS_VERSION

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

RUN apt-get install -y clang-6.0 cmake python-pam libssl-dev libpam-dev
ENV CXX=export CXX=/usr/bin/clang++-6.0

RUN cd /opt && git clone https://github.com/irods/irods.git --branch $IRODS_VERSION && git clone https://github.com/stefan-wolfsheimer/irods_auth_plugin_pam_interactive.git
RUN \
    cp /opt/irods/lib/core/include/irods_version.h.in /opt/irods/lib/core/include/irods_version.h && \
    sed -i "s/@IRODS_VERSION_MAJOR@/`echo $IRODS_VERSION | cut -d. -f1`/"  /opt/irods/lib/core/include/irods_version.h && \
    sed -i "s/@IRODS_VERSION_MINOR@/`echo $IRODS_VERSION | cut -d. -f2`/"  /opt/irods/lib/core/include/irods_version.h && \
    sed -i "s/@IRODS_VERSION_PATCH@/`echo $IRODS_VERSION | cut -d. -f3`/"  /opt/irods/lib/core/include/irods_version.h && \
    cp /opt/irods/lib/core/include/rodsVersion.h.in /opt/irods/lib/core/include/rodsVersion.h && \
    sed -i "s/@IRODS_VERSION@/${IRODS_VERSION}/"  /opt/irods/lib/core/include/irods_version.h

ADD CMakeLists.txt /opt/irods_auth_plugin_pam_interactive
# TO DO: Need to finish this !
# RUN cd /opt/irods_auth_plugin_pam_interactive && \
#    cmake CMakeLists.txt && make && make install

CMD ["/usr/sbin/sshd", "-D"]
