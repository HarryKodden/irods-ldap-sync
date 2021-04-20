#!/bin/bash

if test -f ".env"; then
  source .env
else
  source .test.env
fi

# Prepare iCAT server...

docker exec my-irods-icat sed -i 's/CS_NEG_DONT_CARE/CS_NEG_REQUIRE/' /etc/irods/core.re

ssl=$(cat <<EOF
mkdir /etc/irods/ssl;
cd /etc/irods/ssl;
openssl dhparam -2 -out dhparams.pem 2048;
openssl genrsa -out irods.key;
chmod 600 irods.key
openssl req -new -key irods.key -subj '/OU=Domain Control Validated/OU=PositiveSSL/CN=icat' -x509 -days 365 -out irods.crt
EOF
)

docker exec my-irods-icat su - irods -c "$ssl"
docker exec my-irods-icat cp /etc/irods/ssl/irods.crt /etc/ssl/certs 

server_env=$(cat <<EOF
export irodsSSLCertificateChainFile=/etc/ssl/certs/irods.crt;
export irodsSSLCertificateKeyFile=/etc/irods/ssl/irods.key;
export irodsSSLDHParamsFile=/etc/irods/ssl/dhparams.pem;
EOF
)

client_env=$(cat <<EOF
export irodsDefaultHashScheme=SHA256;
export irodsClientServerPolicy=CS_NEG_REQUIRE;
export irodsClientServerNegotiation=request_server_negotiation;
export irodsEncryptionAlgorithm=AES-256-CBC;
export irodsEncryptionKeySize=32;
export irodsEncryptionNumHashRounds=16;
export irodsEncryptionSaltSize=8;
export irodsSSLCACertificateFile=/etc/ssl/certs/irods.crt;
export irodsSSLVerifyServer=cert;
EOF
)

docker exec my-irods-icat su - irods -c "sed -i 's/CS_NEG_REFUSE/CS_NEG_REQUIRE/' ~/.irods/.irodsEnv"
docker exec my-irods-icat su - irods -c "echo -e \"$server_env\n$client_env\" > ~/.profile"
docker exec my-irods-icat su - irods -c "iRODS/irodsctl restart"

# Prepare iCommand Client...

docker cp my-irods-icat:/etc/ssl/certs/irods.crt ./etc/irods/irods.crt
docker cp ./etc/irods/irods.crt my-irods-icommands:/etc/ssl/certs/irods.crt

docker exec my-irods-icommands  bash -c "echo \"$client_env\" > /etc/profile.d/irods.sh"

# Done !