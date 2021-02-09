#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import ldap
import json
import argparse
import logging
import random
import re
import signal
import time
from datetime import datetime
from enum import Enum

from irods.session import iRODSSession
from irods.column import Criterion
from irods.exception import iRODSException, UserDoesNotExist, UserGroupDoesNotExist, \
    CAT_INVALID_GROUP, CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME
from irods.models import User, UserGroup
from irods.user import iRODSUser, iRODSUserGroup

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(level=logging.getLevelName(log_level), format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('root')

IRODS_ZONE = os.environ.get('IRODS_ZONE', 'tempZone')
IRODS_HOST = os.environ.get('IRODS_HOST', 'localhost')
IRODS_PORT = os.environ.get('IRODS_PORT', 1247)
IRODS_USER = os.environ.get('IRODS_USER', '')
IRODS_PASS = os.environ.get('IRODS_PASS', '')

SSH_HOST = os.environ.get('SSH_HOST', 'localhost')
SSH_PORT = os.environ.get('SSH_PORT', 2222)

DRY_RUN = (os.environ.get('DRY_RUN','FALSE').upper() == 'TRUE')

from pty import fork
from os import waitpid, execv
class ssh():
    def __init__(self, command, host=SSH_HOST, port=SSH_PORT, user='root'):
        self.command = command
        self.host = host
        self.port = port
        self.user = user
        self.run()

    def run(self):
        command = [
                '/usr/bin/ssh',
                '-p', '{}'.format(self.port),
                '-o', 'StrictHostKeyChecking=accept-new',
                self.user+'@'+self.host,
                self.command
        ]

        logger.info("Executing command: {} on {}".format(command, self.host))

        pid, _ = fork()

        if not pid:
            execv(command[0], command)
            
        waitpid(pid, 0)

class Ldap(object):

    def __init__(self):
        # Establish connection with LDAP...
        try:  
            self.session = ldap.initialize(os.environ['LDAP_HOST'])
            self.session.simple_bind_s(os.environ['LDAP_BIND_DN'], os.environ['LDAP_ADMIN_PASSWORD'])

            self.people = {}
            self.groups = {}

        except Exception as e:
            logger.error("Problem connecting to LDAP {} error: {}".format(os.environ['LDAP_HOST'], str(e)))
            exit(1)

    def __exit__(self):
        try:
            self.session.unbind_s()
        except:
            pass

    def search(self, dn, searchScope = ldap.SCOPE_SUBTREE, searchFilter = "(objectclass=*)", retrieveAttributes = []):

        result = None
        try:
            result_set = []

            ldap_result_id = self.session.search(dn, searchScope, searchFilter, retrieveAttributes)
            while 1:
                result_type, result_data = self.session.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                elif result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

            result = result_set

        except ldap.LDAPError as e:
            result = None
            logger.error("[IRODS] REQUEST: %s\n" % str(e))

        return result

    def show_people(self):
        logger.debug("LDAP People: %s\n" % json.dumps(self.people, sort_keys=True, indent=4))


    def show_groups(self):
        logger.debug("LDAP_Groups: %s" % json.dumps(self.groups, sort_keys=True, indent=4))

    @staticmethod
    def get_attributes(x):
        attributes = {} 
    
        for a in x.keys():
                attributes[a] = []
                for v in x[a]:
                    attributes[a].append(v.decode())

        return attributes

    def get_people(self):
        ldap_user_key = os.environ.get('LDAP_USER_KEY', 'uid')

        for i in self.search(
            os.environ['LDAP_BASE_DN'],
            searchFilter = "(&(objectClass=inetOrgPerson)({}=*))".format(ldap_user_key),
            retrieveAttributes = []):

            attributes = self.get_attributes(i[0][1])

            if ldap_user_key not in attributes:
                logger.error("Missing '{}' attribute in LDAP USER Object !", ldap_user_key)
                continue

            if len(attributes[ldap_user_key]) > 1:
                logger.error("LDAP User key '{}' must be 1 value !".format(ldap_user_key))
                continue

            key = attributes[ldap_user_key][0]

            self.people[key] = { 'attributes': attributes }
        
    def get_groups(self):
        ldap_group_key = os.environ.get('LDAP_GROUP_KEY', 'cn')

        for i in self.search(
            os.environ['LDAP_BASE_DN'],
            searchFilter = "({})".format(os.environ.get('LDAP_FILTER', "objectClass=groupOfMembers")),
            retrieveAttributes = []): 

            attributes = self.get_attributes(i[0][1])

            if ldap_group_key not in attributes:
                logger.error("Missing '{}' attribute in LDAP GROUP Object !".format(ldap_group_key))
                continue

            if len(attributes[ldap_group_key]) > 1:
                logger.error("LDAP Group key '{}' must be 1 value !".format(ldap_group_key))
                continue

            key = attributes[ldap_group_key][0]

            members = []

            if 'member' in attributes:

                for member in attributes['member']:

                    m = member.split(',')[0].split('=')[1]

                    if m not in self.people:
                        logger.error("Member {} not in LDAP People !".format(m))
                        continue

                    members.append(m)

            attributes['member'] = members

            self.groups[key] = { 'attributes': attributes }



class iRODS(object):

    def __init__(self):
        try:
            self.session = iRODSSession(host=IRODS_HOST, port=IRODS_PORT, user=IRODS_USER, password=IRODS_PASS, zone=IRODS_ZONE)
        except Exception as e:
            logger.error("Problem connecting to IRODS {} error: {}".format(os.environ['IRODS_HOST'], str(e)))
            exit(1)
    
    def __exit__(self):
        try:
            self.session.cleanup()
        except:
            pass



class USER(object):

    def __init__(self, name, instance):
        self.name = name
        self.must_keep = False
        self.irods_instance = instance
        self.attributes = None

        logger.debug("IRODS User: {}".format(self))

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return { 'name': self.name, 'attibutes': self.attributes, 'instance': self.instance() }

    def instance(self):
        if self.irods_instance:
            return { 'id': self.irods_instance.id, 'name': self.irods_instance.name, 'type': self.irods_instance.type, 'zone': self.irods_instance.zone, 'metadata': self.metadata() }
        else:
            return {}

    def metadata(self):
        result = {}

        if not self.irods_instance: return result

        for k in self.irods_instance.metadata.keys():

            result[k] = []

            for v in self.irods_instance.metadata.get_all(k):
                result[k].append(v.value)

        return result

    def keep(self, attributes=None):
        self.must_keep = True
        self.attributes = attributes
        return self
    
    def sync(self):
        if not self.irods_instance: return

        if not self.must_keep:
            self.remove()
        else:
            self.irods_instance.metadata.remove_all()

            ssh("useradd {}".format(self.name))
            ssh("su - {} -c \"mkdir -m 755 -p .ssh .irods\"".format(self.name))
            try:
                raise Exception("Not yet !")
                for k in self.attributes['sshPublicKey']:
                    ssh("su - {} -c \"echo '{}' > .ssh/authorized_keys\"".format(self.name, k))

                ssh("su - {} -c \"chmod 600 .ssh/authorized_keys\"".format(self.name, k))
            except:
                pass

            env = json.dumps({
                    "irods_host": "{}".format(IRODS_HOST),
                    "irods_port": int(IRODS_PORT),
                    "irods_user_name": "{}".format(self.name),
                    "irods_zone_name": "{}".format(IRODS_ZONE),
                    "irods_authentication_scheme": "PAM_INTERACTIVE",
                    "schema_version": "v3",
                    "irods_ssl_ca_certificate_file": "/etc/irods/ssl/irods.crt",
                    "irods_ssl_verify_server": "none"
                }, indent=4).replace('"', '\\""')

            ssh('su - {} -c "echo -e \'{}\' > .irods/irods_environment.json"'.format(self.name, env))

            if self.attributes:
                for k,v in self.attributes.items():
                    for i in v:
                        self.irods_instance.metadata.add(k, i)

    def remove(self):
        if not self.irods_instance: return

        logger.info("IRODS Remove User: {}".format(self.name))
        self.irods_instance.remove()

        ssh("shell", "userdel -r {}".format(self.name))

        self.must_keep = False
        self.irods_instance = None

class GROUP(object):

    def __init__(self, name, instance):
        self.name = name
        self.must_keep = False
        self.attributes = None
        self.members = {}
        self.irods_instance = instance

        if self.irods_instance:
            for m in self.irods_instance.members:
                self.members[m.name] = False

        logger.debug("IRODS Group: {}".format(self))

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return { "name" : self.name, 'attibutes': self.attributes, 'metadata': self.metadata(), 'members': self.members, 'instance': self.instance() }

    def instance(self):
        if self.irods_instance: 
            return { 'id': self.irods_instance.id, 'name': self.irods_instance.name, 'metadata': self.metadata() }
        else:
            return {}

    def metadata(self):
        result = {}

        if not self.irods_instance: return result

        for k in self.irods_instance.metadata.keys():

            result[k] = []

            for v in self.irods_instance.metadata.get_all(k):
                result[k].append(v.value)

        return result

    def keep(self, attributes=None):
        self.must_keep = True
        self.attributes = attributes
        return self

    def member(self, member):
        self.must_keep = True
        self.members[member] = True
        return self

    def sync(self):
        if not self.irods_instance: return

        if not self.must_keep:
            self.remove()
        else:
            for m in self.members.keys():
                if not self.members[m] and self.irods_instance.hasmember(m):
                    logger.info("IRODS Remove {} from Group: {}".format(m, self.name))
                    self.irods_instance.removemember(m)
                if self.members[m] and not self.irods_instance.hasmember(m):
                    logger.info("IRODS Add {} to Group: {}".format(m, self.name))
                    self.irods_instance.addmember(m)

            self.irods_instance.metadata.remove_all()

            if self.attributes:
                for k,v in self.attributes.items():
                    for i in v:
                        self.irods_instance.metadata.add(k, i)

    def remove(self):
        if not self.irods_instance: return

        for m in self.members:
            if self.irods_instance.hasmember(m):
                self.irods_instance.removemember(m)

        logger.info("IRODS Remove Group: {}".format(self.name))
        self.irods_instance.remove()

        self.must_keep = False
        self.irods_instance = None
        self.members = []

class iRODS_Users(iRODS):
    
    def __init__(self):
        super().__init__()
        self.users = {}

    def json(self):
        return { 'users': [ u.json() for _, u in self.users.items() ] }

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def add(self, name, instance=None):
        if name in self.users: return

        if not instance:
            logger.info("IRODS Create User: {}".format(name))
            if not DRY_RUN:
                instance = self.session.users.create(name, 'rodsuser')

        self.users[name] = USER(name, instance)

    def read(self):
        query = self.session.query(User.name, User.id, User.type).filter(
            Criterion('=', User.type, 'rodsuser'))

        for result in query:
            name = result[User.name]

            self.add(name, instance=self.session.users.get(name))

        logger.debug("iRODS Users: {}".format(self))

        return self

    def sync(self):
        for i in self.users.keys():
            self.users[i].sync()

class iRODS_Groups(iRODS):
    
    def __init__(self):
        super().__init__()
        self.groups = {}

    def json(self):
        return { 'groups': [ g.json() for _, g in self.groups.items() ] }

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def add(self, name, instance=None):
        if name in self.groups: return

        if not instance:
            logger.info("IRODS Create Group: {}".format(name))
            if not DRY_RUN:
                instance = self.session.user_groups.create(name)

        self.groups[name] = GROUP(name, instance)

    def read(self):        
        query = self.session.query(User.name, User.id, User.type).filter(
                Criterion('=', User.type, 'rodsgroup'))

        for result in query:
            name = result[User.name]
            if name in ['rodsadmin', 'public']:
                continue

            self.add(name, instance=self.session.user_groups.get(name))
        
        logger.debug("iRODS Groups: {}".format(self))

        return self

    def sync(self):
        for i in self.groups.keys():
            self.groups[i].sync()
    

def run():

    start_time = datetime.now()
    logger.info("SYNC started at: {}".format(start_time))

    # Read LDAP...
    my_ldap = Ldap()
    my_ldap.get_people()
    my_ldap.get_groups()

    # Sync iRODS people...
    my_irods = iRODS_Users().read()

    for u in my_ldap.people.keys():
        if u not in my_irods.users:
            my_irods.add(u)

        my_irods.users[u].keep(my_ldap.people[u]['attributes'])

    my_irods.sync()

    # Sync iRODS groups...
    my_irods = iRODS_Groups().read()

    for g in my_ldap.groups.keys():
        if g not in my_irods.groups:
            my_irods.add(g)

        group = my_irods.groups[g].keep(my_ldap.groups[g]['attributes'])

        for m in my_ldap.groups[g]['attributes']['member']:
            group.member(m)

    my_irods.sync()

    logger.info("SYNC completed at: {}".format(start_time))

if __name__ == "__main__":
    run()
