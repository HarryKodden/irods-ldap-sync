![example workflow name](https://github.com/HarryKodden/irods-ldap-sync/workflows/CI/badge.svg)

# irods-ldap-sync

This repository demonstrates the synchronization of LDAP object into iRODS cataloque.

Features:
* LDAP people objects are translated to iRODS users
* LDAP group objects arre translated to iRODS groups
* LDAP group memberships are translated to iRODS group memberships
* LDAP attributes are translated to iRODS metadata
* For each user identity created, a user is also created on a SSH server
* When the LDAP user object contains a **sshPublicKey** attribute, also an **~/.ssh/authorized_keys** entry is created containing that key.

Please look in the **.github/workflows/ci.yml** for configuration details

## Running

You have multiple run options:
1. Run locally with LDAP and iRODS docker containers.
2. Connect to existing LDAP and/or iRODS instances
### Run on localhost

Running on localhost: (docker is required !)
1. start local LDAP container, (data is loaded during start as well)
```
./etc/ldap_start.sh
```
2. start local iRODS container
```
./etc/irods_start.sh
```

### Connect to existing LDAP / iRODS

For connecting to existing instances, make sure you have administrator credentials and provide the credential in the **.env** file (see below)

### Execute !
For a single pass execution you can either execute:

```
pytest
```
or
```
dotenv run python src/sync.py 
```

## Configuration

You can create a **.env** file that can contain values for following configuration keys.

key | Sample |Description
--- | --- | ---
LDAP_HOST |ldap://localhost:389|The LDAP to connect to
LDAP_ADMIN_PASSWORD |secret|The LDAP Admin Password
LDAP_CONFIG_PASSWORD|config|The LDAP Config Password
LDAP_DOMAIN|"example.org"|LDAP Domain
LDAP_BASE_DN|"dc=example,dc=org"|LDAP Base DN
LDAP_BIND_DN|"cn=admin,dc=example,dc=org"|LDAP Bind DN
IRODS_HOST|localhost|The iRODS host to connect to
IRDDS_PORT|1247|The iRODS service port to connect to
IRODS_USER|rods|iRODS administrator user
IRODS_PASS|password|iRODS administrator user
IRODS_ZONE|tempZone|The iRODS zone
LOG_LEVEL|INFO|Loglevel can be **NONE**, **DEBUG**, **INFO**, **WARN**, **ERROR**
DRY_RUN|False|Either **True** or **False**, when True No updates are performed to iRODS.


