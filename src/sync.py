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

start_time = datetime.now()
logger.info("SYNC started at: {}".format(start_time))

IRODS_ZONE = os.environ.get('IRODS_ZONE', 'tempZone')
IRODS_HOST = os.environ.get('IRODS_HOST', 'localhost')
IRODS_PORT = os.environ.get('IRODS_PORT', 1247)
IRODS_USER = os.environ.get('IRODS_USER', '')
IRODS_PASS = os.environ.get('IRODS_PASS', '')

import pty
from subprocess import Popen, PIPE, STDOUT
from os import fork, waitpid, execv

class ssh():
    def __init__(self, host, execute='echo "done" > /root/testing.txt', user='root'):
        self.exec = execute
        self.host = host
        self.user = user
        self.run()

    def run(self):
        command = [
                '/usr/bin/ssh',
                '-o', 'StrictHostKeyChecking=accept-new',
                self.user+'@'+self.host,
                self.exec,
        ]

        logger.debug("Executing command: {} on {}".format(command, self.host))

        # PID = 0 for child, and the PID of the child for the parent    
        pid, child_fd = pty.fork()

        if not pid: # Child process
            # Replace child process with our SSH process
            execv(command[0], command)

        waitpid(pid, 0)

try:  
  ldap_session = ldap.initialize(os.environ['LDAP_HOST'])
  ldap_session.simple_bind_s(os.environ['LDAP_BIND_DN'], os.environ['LDAP_PASS'])
except Exception as e:
  logger.error("Problem connecting to LDAP {} error: {}".format(os.environ['LDAP_HOST'], str(e)))
  exit(1)

try:
  irods_session = iRODSSession(host=IRODS_HOST, port=IRODS_PORT, user=IRODS_USER, password=IRODS_PASS, zone=IRODS_ZONE)
except Exception as e:
  logger.error("Problem connecting to IRODS {} error: {}".format(os.environ['IRODS_HOST'], str(e)))
  exit(1)

def _ldap(dn, operation, ldif = None, searchScope = None, searchFilter = None, retrieveAttributes = None):
    result = None
    try:
      result_set = []

      ldap_result_id = ldap_session.search(dn, searchScope, searchFilter, retrieveAttributes)
      while 1:
        result_type, result_data = ldap_session.result(ldap_result_id, 0)
        if (result_data == []):
          break
        else:
          if result_type == ldap.RES_SEARCH_ENTRY:
            result_set.append(result_data)

      result = result_set

    except ldap.LDAPError as e:
       result = None
       logger.error("[IRODS] REQUEST: %s\n" % str(e))

    #logger.debug(result)
    return result

def ldap_search(dn, searchScope = ldap.SCOPE_SUBTREE, searchFilter = "(objectclass=*)", retrieveAttributes = []):
    return _ldap(dn, "SEARCH", searchScope=searchScope, searchFilter=searchFilter, retrieveAttributes=retrieveAttributes)

ldap_groups = {}
ldap_people = {}

def get_attributes(x):
   attributes = {} 
   
   for a in x.keys():
        attributes[a] = []
        for v in x[a]:
            attributes[a].append(v.decode())

   return attributes

ldap_user_key = os.environ.get('LDAP_USER_KEY', 'uid')
ldap_group_key = os.environ.get('LDAP_GROUP_KEY', 'cn')

for i in ldap_search(os.environ['LDAP_BASE_DN'],
	searchFilter = "(&(objectClass=inetOrgPerson)({}=*))".format(ldap_user_key),
	retrieveAttributes = []):

    attributes = get_attributes(i[0][1])

    if ldap_user_key not in attributes:
        logger.error("Missing '{}' attribute in LDAP USER Object !", ldap_user_key)
        continue

    if len(attributes[ldap_user_key]) > 1:
        logger.error("LDAP User key '{}' must be 1 value !".format(ldap_user_key))
        continue

    key = attributes[ldap_user_key][0]

    ldap_people[key] = { 'attributes': attributes }
   
logger.debug("LDAP Users: %s\n" % json.dumps(ldap_people, sort_keys=True, indent=4))

for i in ldap_search(os.environ['LDAP_BASE_DN'],
 	searchFilter = "({})".format(os.environ.get('LDAP_FILTER', "objectClass=groupOfMembers")),
	retrieveAttributes = []): 

    attributes = get_attributes(i[0][1])

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

            if m not in ldap_people:
                logger.error("Member {} not in LDAP People !".format(m))
                continue

            members.append(m)

    attributes['member'] = members

    ldap_groups[key] = { 'attributes': attributes }

logger.debug("LDAP_Groups: %s" % json.dumps(ldap_groups, sort_keys=True, indent=4))

irods_users = {}
irods_groups = {}

class USER(object):

    def __init__(self, name, current=None):
        self.name = name
        self.must_keep = False
        self.user = current
        self.attributes = None

        logger.debug("IRODS User: {}".format(self))

        irods_users[name] = self

    def __repr__(self):
        return json.dumps(self.json())

    def json(self):
        return { 'name': self.name, 'current': self.current() }

    def current(self):
        if self.user: 
            return { 'id': self.user.id, 'name': self.user.name, 'type': self.user.type, 'zone': self.user.zone, 'metadata': self.metadata() }
        else:
            return {}

    def metadata(self):
        if self.user:
            result = {}
            for k in self.user.metadata.keys():

                result[k] = []

                for v in self.user.metadata.get_all(k):
                    result[k].append(v.value)

            return result
        else:
            return {}

    def keep(self, attributes=None):
        self.must_keep = True
        self.attributes = attributes
        return self
    
    def sync(self):
        if not self.must_keep:
            self.remove()
        else:
            if not self.user:
                logger.info("IRODS Create User: {}".format(self.name))
                self.user = irods_session.users.create(self.name, 'rodsuser')

            self.user.metadata.remove_all()

            ssh("shell", "useradd {}".format(self.name))
            ssh("shell", "su - {} -c \"mkdir -m 755 -p .ssh .irods\"".format(self.name))
            try:
                for k in self.attributes['sshPublicKey']:
                    ssh("shell", "su - {} -c \"echo '{}' > .ssh/authorized_keys\"".format(self.name, k))

                ssh("shell", "su - {} -c \"chmod 600 .ssh/authorized_keys\"".format(self.name, k))
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

            ssh("shell", 'su - {} -c "echo -e \'{}\' > .irods/irods_environment.json"'.format(self.name, env))

            if self.attributes:
                for k,v in self.attributes.items():
                    for i in v:
                        self.user.metadata.add(k, i)

    def remove(self):
        if self.user:
            logger.info("IRODS Remove User: {}".format(self.name))
            self.user.remove()

        ssh("shell", "userdel -r {}".format(self.name))

        self.must_keep = False
        self.user = None

class GROUP(object):

    def __init__(self, name, current=None):
        self.name = name
        self.must_keep = False
        self.attributes = None
        self.members = {}
        self.group = current

        if name in ['public', 'rodsadmin']:
            self.must_keep = True

        if current:
           for m in current.members:
              self.members[m.name] = False

        logger.debug("IRODS Group: {}".format(self))

        irods_groups[name] = self

    def __repr__(self):
        return json.dumps(self.json())

    def json(self):
        return { "name" : self.name, 'metadata': self.metadata(), 'members': self.members, 'current': self.current() }

    def current(self):
        if self.group: 
            return { 'id': self.group.id, 'name': self.group.name, 'metadata': self.metadata() }
        else:
            return {}

    def metadata(self):
        if self.group:
            result = {}
            for k in self.group.metadata.keys():

                result[k] = []

                for v in self.group.metadata.get_all(k):
                    result[k].append(v.value)

            return result
        else:
            return {}

    def keep(self, attributes=None):
        self.must_keep = True
        self.attributes = attributes
        return self

    def member(self, member):
        self.must_keep = True
        self.members[member] = True
        self.attributes = attributes
        return self

    def sync(self):
        if not self.must_keep:
            self.remove()
        else:
            if not self.group:
                logger.info("IRODS Create Group: {}".format(self.name))
                self.group = irods_session.user_groups.create(self.name)

            for m in self.members.keys():
                if not self.members[m] and self.group.hasmember(m):
                    logger.info("IRODS Remove {} from Group: {}".format(m, self.name))
                    self.group.removemember(m)
                if self.members[m] and not self.group.hasmember(m):
                    logger.info("IRODS Add {} to Group: {}".format(m, self.name))
                    self.group.addmember(m)

            self.group.metadata.remove_all()

            if self.attributes:
                for k,v in self.attributes.items():
                    for i in v:
                        self.group.metadata.add(k, i)

    def remove(self):

        if self.group:
            for m in self.members:
                if self.group.hasmember(m):
                    self.group.removemember(m)

            logger.info("IRODS Remove Group: {}".format(self.name))
            self.group.remove()

        self.must_keep = False
        self.group = None
        self.members = []

def get_irods_users(sess):
    query = sess.query(User.name, User.id, User.type).filter(
        Criterion('=', User.type, 'rodsuser'))

    for result in query:
        USER(result[User.name], current=sess.users.get(result[User.name]))

def get_irods_groups(sess):
    query = sess.query(User.name, User.id, User.type).filter(
        Criterion('=', User.type, 'rodsgroup'))

    for result in query:
        GROUP(result[User.name], current=sess.user_groups.get(result[User.name]))

get_irods_users(irods_session)
get_irods_groups(irods_session)

for _, u in irods_users.items():
    logger.debug(f"User: {str(u)}")

for _, g in irods_groups.items():
    logger.debug(f"Group: {str(g)}")


# Make sure all LDAP entries are instantiated

for u in ldap_people.keys():
  if u not in irods_users:
    USER(u)

  irods_users[u].keep(ldap_people[u]['attributes'])

for g in ldap_groups.keys():
  if g not in irods_groups:
     GROUP(g)

  group = irods_groups[g].keep(ldap_groups[g]['attributes'])

  for m in ldap_groups[g]['attributes']['member']:
    group.member(m)

# Now finalize sync...

for u in irods_users.keys():
    irods_users[u].sync()
    
for g in irods_groups.keys():
    irods_groups[g].sync()

irods_session.cleanup()
ldap_session.unbind_s()

logger.info("SYNC completed at: {}".format(start_time))
