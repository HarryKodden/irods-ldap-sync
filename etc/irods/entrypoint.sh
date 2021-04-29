#!/bin/bash

# Check postgres at startup
until PGPASSWORD=$IRODS_DB_PASS psql -h $IRODS_DB_HOST -U $IRODS_DB_USER $IRODS_DB_NAME -c "\d" 1> /dev/null 2> /dev/null;
do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

# setup SSL keys...
mkdir /etc/irods/ssl 2>/dev/null
cd /etc/irods/ssl

if [ ! -f irods.key ]; then
  openssl genrsa -out irods.key
fi

if [ ! -f irods.crt ]; then
  openssl req -new -key irods.key -x509 -days 365 -out irods.crt -config <( \
  echo '[req]'; \
  echo 'distinguished_name = req_distinguished_name'; \
  echo 'x509_extensions = v3_req'; \
  echo 'prompt = no'; \
  echo '[req_distinguished_name]'; \
  echo 'OU = PKI'; \
  echo 'CN = '$IRODS_HOST; \
  echo '[v3_req]'; \
  echo 'basicConstraints = CA:TRUE'; \
  echo 'extendedKeyUsage = serverAuth'; \
  echo 'subjectAltName = @alt_names'; \
  echo '[alt_names]'; \
  echo 'DNS.1 = '$IRODS_HOST; \
  echo 'DNS.2 = localhost'; \
  echo 'IP.1 = 127.0.0.1')  
fi

if [ ! -f dhparams.pem ]; then
  openssl dhparam -2 -out dhparams.pem 2048
fi

# Is it init time?
checkirods=$(ls /etc/irods/core.re)
if [ "$checkirods" == "" ]; then
    MYDATA="/tmp/answers"
    sudo -E /bin/bash /usr/local/bin/genresp.sh $MYDATA

    # Launch the installation
    sudo python /var/lib/irods/scripts/setup_irods.py < $MYDATA

    # Verify how it went
    if [ "$?" == "0" ]; then
        echo ""
        echo "iRODS INSTALLED!"
    else
        echo "Failed to install irods..."
        exit 1
    fi
 
    # Adjust core.re to enforce SSL handshake
    sed -i 's/CS_NEG_DONT_CARE/CS_NEG_REQUIRE/' /etc/irods/core.re

    # Adjust default environment to enforce SSL handshake
    sed -i 's/CS_NEG_DONT_CARE/CS_NEG_REQUIRE/' /var/lib/irods/.irods/irods_environment.json
    sed -i 's/CS_NEG_REFUSE/CS_NEG_REQUIRE/'    /var/lib/irods/.irods/irods_environment.json

    # Adjust default environment.json to make use of SSL cert...
    sed -i '2i    "irods_ssl_certificate_chain_file": "/etc/irods/ssl/irods.crt", ' /var/lib/irods/.irods/irods_environment.json
    sed -i '3i    "irods_ssl_certificate_key_file": "/etc/irods/ssl/irods.key", '   /var/lib/irods/.irods/irods_environment.json
    sed -i '4i    "irods_ssl_ca_certificate_file": "/etc/irods/ssl/irods.crt", '    /var/lib/irods/.irods/irods_environment.json
    sed -i '5i    "irods_ssl_dh_params_file": "/etc/irods/ssl/dhparams.pem", '      /var/lib/irods/.irods/irods_environment.json
    sed -i '6i    "irods_ssl_verify_server": "none", '                              /var/lib/irods/.irods/irods_environment.json
#   sed -i '7i    "irods_authentication_scheme": "PAM", '                           /var/lib/irods/.irods/irods_environment.json

    service irods restart
else
    echo "Already installed. Launching..."
    sudo service irods start
fi

cat <<EOF > /usr/local/etc/irods/irods_environment.json
{
    "irods_host": "${IRODS_HOST}",
    "irods_port": ${IRODS_SERVICE_PORT},
    "irods_user_name": "${IRODS_USER}",
    "irods_zone_name": "${IRODS_ZONE}",
    "irods_client_server_negotiation": "request_server_negotiation",
    "irods_client_server_policy": "CS_NEG_REQUIRE",
    "irods_encryption_algorithm": "AES-256-CBC",
    "irods_encryption_key_size": 32,
    "irods_encryption_num_hash_rounds": 16,
    "irods_encryption_salt_size": 8,
    "irods_ssl_ca_certificate_file": "/usr/local/etc/irods/irods.crt"
}
EOF
cp /etc/irods/ssl/irods.crt /usr/local/etc/irods    

echo "iRODS is ready"

/usr/sbin/sshd -D