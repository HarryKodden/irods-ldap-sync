#!/bin/bash

# genresp.sh
# Generates responses for iRODS' setup_irods.sh script.
# Zone SID, agent key, database admin, and admin password are all randomized.

OUTFILE=$1

echo "${IRODS_SERVICE_NAME}" > $OUTFILE
echo "${IRODS_SERVICE_GROUP}" >> $OUTFILE
echo "1" >> $OUTFILE # 1. provider, 2. consumer
echo "1" >> $OUTFILE # 1. PostgreSQL ANSI, 2. PostgreSQL Unicode
echo "${IRODS_DB_HOST}" >> $OUTFILE
echo "${IRODS_DB_PORT}" >> $OUTFILE
echo "${IRODS_DB_NAME}" >> $OUTFILE
echo "${IRODS_DB_USER}" >> $OUTFILE
echo "yes" >> $OUTFILE # confirm database settings
echo "${IRODS_DB_PASS}" >> $OUTFILE
echo "${IRODS_DB_PASS}" >> $OUTFILE # database salt
echo "${IRODS_ZONE}" >> $OUTFILE
echo "${IRODS_SERVICE_PORT}" >> $OUTFILE
echo "${IRODS_RANGE_FROM}" >> $OUTFILE
echo "${IRODS_RANGE_TILL}" >> $OUTFILE
echo "${IRODS_CONTROL_PORT}" >> $OUTFILE
echo "" >> $OUTFILE # Schema Validation URI [ default ]
echo "${IRODS_USER}" >> $OUTFILE
echo "yes" >> $OUTFILE # conform irods settings
(openssl rand -base64 16 2>/dev/null | sed 's,/,S,g' | sed 's,+,_,g' | cut -c 1-16  | tr -d '\n' ; echo "")  >> $OUTFILE # zone key
(openssl rand -base64 32 2>/dev/null | sed 's,/,S,g' | sed 's,+,_,g' | cut -c 1-32) >> $OUTFILE # negotation key
(openssl rand -base64 32 2>/dev/null | sed 's,/,S,g' | sed 's,+,_,g' | cut -c 1-32) >> $OUTFILE # control plane key
echo "${IRODS_PASS}" >> $OUTFILE
echo "" >> $OUTFILE # Vault [ default location ]
