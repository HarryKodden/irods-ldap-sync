#!/bin/bash

echo "Running..."
apt-get update -y
apt-get install -y openssh-server
mkdir /var/run/sshd
sed -ie 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/g' /etc/ssh/sshd_config
sed -ie 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config
echo "sshd: ALL" >> /etc/hosts.allow
useradd -m ${IRODS_USER}
usermod -aG sudo ${IRODS_USER}
echo "rods ALL=NOPASSWD: ALL" >> /etc/sudoers
su - ${IRODS_USER} -c "ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ''"
su - ${IRODS_USER} -c "cat /tmp/authorized_keys > ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys"
su - ${IRODS_USER} -c "mkdir -p .irods; echo -e \"\nirodsHost ${IRODS_HOST}\nirodsPort ${IRODS_PORT}\nirodsUserName ${IRODS_USER}\nirodsZone ${IRODS_ZONE}\n\" > .irods/.irodsEnv"
/usr/sbin/sshd -D
