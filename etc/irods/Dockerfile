FROM ubuntu:18.04

ARG IRODS_VERSION=4.2.8

ENV TERM xterm-256color
ENV DEBIAN_FRONTEND=noninteractive

# INSTALL GENERIC...
RUN apt-get clean
RUN apt-get update 
RUN apt-get install -y apt-transport-https sudo wget git gnupg2 jq libxml2 moreutils vim lsb-release locales

RUN locale-gen en_US.UTF-8
RUN update-locale

# INSTALL IRODS
RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - \
    && echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/renci-irods.list \
    && apt-get update && apt-get install -y \
    irods-database-plugin-postgres=$IRODS_VERSION \
    irods-runtime=$IRODS_VERSION  \
    irods-icommands=$IRODS_VERSION  \
    irods-server=$IRODS_VERSION

CMD ["/bin/bash", "sleep", "infinity"]
