[![Gitpod ready-to-code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/HarryKodden/irods-ldap-sync) ![example workflow name](https://github.com/HarryKodden/irods-ldap-sync/workflows/CI/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/HarryKodden/irods-ldap-sync/badge.svg?branch=main&kill_cache=1)](https://coveralls.io/github/HarryKodden/irods-ldap-sync?branch=main) [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/HarryKodden/irods-ldap-sync/HEAD)

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

All required services are defined in the docker-compose.yml file in etc directory.
These services can easily be started by:

```
(cd etc; docker-compose up -d)
```
## Gitpod

This repository is fully prepared to operate on GitPod. You can launch the workspace on GitPod. During initialization of the workspace, docker is prepared as well. Both LDAP and iRODS containers are instantiated.
When workspace is opened, you may directly execute command 'pytest' to see that everythings works as expected.

### Connect to existing LDAP / iRODS

For connecting to existing instances, make sure you have administrator credentials and provide the credential in the **.env** file (see below)

### Execute !
For a single pass execution you can execute:

```
pytest
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
IRODS_VERSION |The requested iRODS version, default: 4.2.8
IRODS_JSON |The **irods_environment.json** file
IRODS_CERT |The irods CA Certificate for SSL interaction
IRODS_HOST|localhost|The iRODS host to connect to
IRDDS_PORT|1247|The iRODS service port to connect to
IRODS_USER|rods|iRODS administrator user
IRODS_PASS|password|iRODS administrator password
IRODS_ZONE|tempZone|The iRODS zone
LOG_LEVEL|INFO|Loglevel can be **NONE**, **DEBUG**, **INFO**, **WARN**, **ERROR**
DRY_RUN|False|Either **True** or **False**, when True No updates are performed to iRODS.


