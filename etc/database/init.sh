#!/bin/bash

conf='/var/lib/postgresql/data/pg_hba.conf'
net="0.0.0.0/0"

## http://www.postgresql.org/docs/9.1/static/auth-pg-hba-conf.html

echo "Changing access"
echo "" > $conf

# Enable to allow health checks
echo "hostnossl  $POSTGRES_USER all $net    md5" >> $conf
echo "host       all            all $net    md5">> $conf
echo "host       all            all ::1/128 md5" >> $conf
echo "hostnossl  all            postgres 127.0.0.1/32 trust" >> $conf

echo "hba_file = '$conf'" >> /var/lib/postgresql/data/postgresql.conf

# Setup DB
echo "Enabling DB $db"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" << EOSQL
    CREATE DATABASE "$MY_DB";
    CREATE USER $MY_USER WITH PASSWORD '$MY_PASSWORD';
    GRANT ALL PRIVILEGES ON DATABASE "$MY_DB" TO $MY_USER;
EOSQL

echo "DONE"
