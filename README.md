![example workflow name](https://github.com/HarryKodden/irods-ldap-sync/workflows/CI/badge.svg)

# irods-ldap-sync

This repository demonstrates the synchronization of LDAP object into iRODS cataloque.

Features:
* LDAP people objects are translated to iRODS users
* LDAP group objects arre translated to iRODS groups
* LDAP group memberships are translated to iRODS group memberships
* LDAP attributes are translated ot iRODS metadata
* For each user a user is created on a SSH server.
* When the LDAP user object contains a sshPublicKey attribute, also an ~/.ssh/authorized_keys entry is created containing that key.

Please lookin the **.github/workflows/ci.yml** for configuration details

Running on localhost: (docker is required !)
1. start local local LDAP container, (also data is loaded)
```
./etc/ldap_start.sh
```
2. start local iRODS container
```
./etc/irods_start.sh
```
3. Either:
```
pytest
```
4. alternative, run with loacl contiguration in **.env** file:
```
dotenv run python src/sync.py 
```