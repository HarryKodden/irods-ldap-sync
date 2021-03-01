# sync process

## Read LDAP - People

```
Every occurence of people in the LDAP is added to an internal dictionary with key uid of object. The
LDAP attributes of this user are stored as attributes in this dictionary associated this this key.
```

## Read LDAP - Groups

```
Every occurrence of groups in the LDAP is added to an internal dictionary with key cn of object. The
LDAP attributes of this group are stored as attributes in this dictionary associated this this key.
```

## Read iRODS - users

```
Every occurrence of user in iRODS database is added to an internal dictionary with key username of
object. The iRODS metatdata attributes of this user are stored as attributes in this dictionary associated
this this key.
```

## Read iRODS - groups

```
Every occurrence of group in iRODS database is added to an internal dictionary with key groupname of
object. The iRODS metatdata attributes of this user are stored as attributes in this dictionary associated
this this key.
```

## Provisioning - general

```
Every LDAP user not found in iRODS is created
Every LDAP group not found in iRODS is created
Every member of LDAP group not in member list of iRODS is added to iRODS group memberlist
Every iRODS group member not found in LDAP group member list, is removed from iRODS group
member list
For each iRODS user the meta attributes are updated to the LDAP attributes found in LDAP People
object
for each iRODS group the the meta attributes are updated to the LDAP attributes found in LDAP
group object
```
```
Objective:
```
```
Make sure that all data in iRODS is owned by a iRODS Group (not on individual iRODS users !)
Make sure that exitsing iRODS groups are not deleted based on the removal of LDAP grooup.
Make sure there is always 'ownership' of at least 1 owner of the iRODS group, even if the last lDAP
member of that group is deleted.
```

## What If - About to delete last iRODS group member?

```
Happens when:
```

```
LDAP has group
LDAP has no members (anymore)
the Group was having member at least 1 member in the past.
during sync, the process is about to remove last iRODS member
```
```
Proposal:
```
```
Add irods administrator as member of this group
```
## What If - About to delete iRODS group

```
Happens when:
```
```
LDAP group does not exits (anymore)
iRODS group was having 1 least 1 member (either irods adminstrator of regular member)
during sync, the process is about to remove last iRODS group
```
```
Proposal:
```
```
Remove any regular user as member of this group
Add irods administrator as member of this group
keep iRODS group (do not delete !)
```
## What If - About to create iRODS group - no LDAP members

```
Happens when:
```
```
LDAP has group
LDAP group has no members
iRODS group exists with 1 member being irods Administrator
```
```
Proposal:
```
```
leave as is (no change !)
```

## What If - About to create iRODS group - with LDAP members

```
Happens when:
```
```
LDAP has group
LDAP group has at least 1 member
iRODS group exists with irods adminstrator as member
```
```
Proposal:
```
```
Add regular LDAP member as member of this iRODS group
Remove irods administrator as member of this iRODS group
```