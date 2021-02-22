#!/usr/bin/env python
from __future__ import print_function

import os
import ldap
import json
import logging
import ssl

from datetime import datetime

from irods.session import iRODSSession
from irods.column import Criterion
from irods.models import User

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=logging.getLevelName(log_level),
    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('root')

IRODS_ZONE = os.environ.get('IRODS_ZONE', 'tempZone')
IRODS_HOST = os.environ.get('IRODS_HOST', 'localhost')
IRODS_PORT = os.environ.get('IRODS_PORT', 1247)
IRODS_USER = os.environ.get('IRODS_USER', '')
IRODS_PASS = os.environ.get('IRODS_PASS', '')

SSH_HOST = os.environ.get('SSH_HOST', 'localhost')
SSH_PORT = os.environ.get('SSH_PORT', 2222)
SSH_USER = os.environ.get('SSH_USER', 'root')

DRY_RUN = (os.environ.get('DRY_RUN', 'FALSE').upper() == 'TRUE')

import subprocess


class ssh():
    def __init__(self, command, host=SSH_HOST, port=SSH_PORT, user=SSH_USER):
        self.command = command
        self.host = host
        self.port = port
        self.user = user
        self.run()

    def run(self):

        command = [
                '/usr/bin/ssh',
                '-p', '{}'.format(self.port),
                '-o', 'StrictHostKeyChecking=no',
                self.user+'@'+self.host,
                self.command
        ]

        logger.info("Executing command: {} on {}".format(command, self.host))

        if DRY_RUN:
            return

        result = subprocess.run(command, capture_output=True, text=True)
        logger.info("stdout:\n{}".format(result.stdout))

class Ldap(object):

    def __init__(self):
        # Establish connection with LDAP...
        try:
            self.session = ldap.initialize(os.environ['LDAP_HOST'])
            self.session.simple_bind_s(
                os.environ['LDAP_BIND_DN'],
                os.environ['LDAP_ADMIN_PASSWORD']
            )

        except Exception as e:
            logger.error("Problem connecting to LDAP {} error: {}".format(os.environ['LDAP_HOST'], str(e)))
            exit(1)

        self.people = {}
        self.groups = {}

        self.get_people()
        self.get_groups()

    def __exit__(self, exception_type, exception_value, traceback):
        self.session.unbind_s()

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return {
            'people': self.people,
            'groups': self.groups
        }

    def search(self, dn, searchScope=ldap.SCOPE_SUBTREE,
            searchFilter="(objectclass=*)",
            retrieveAttributes=[]):

        result = None
        try:
            result_set = []

            ldap_result_id = self.session.search(
                dn, searchScope,
                searchFilter,
                retrieveAttributes
            )
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
                searchFilter="(&(objectClass=inetOrgPerson)({}=*))".format(ldap_user_key),
                retrieveAttributes=[]):

            attributes = self.get_attributes(i[0][1])

            if ldap_user_key not in attributes:
                logger.error("Missing '{}' attribute in LDAP USER Object !".format(ldap_user_key))
                continue

            if len(attributes[ldap_user_key]) > 1:
                logger.error("LDAP User key '{}' must be 1 value !".format(ldap_user_key))
                continue

            key = attributes[ldap_user_key][0]

            self.people[key] = {
                'attributes': attributes
            }

    def get_groups(self):
        ldap_group_key = os.environ.get('LDAP_GROUP_KEY', 'cn')

        for i in self.search(
            os.environ['LDAP_BASE_DN'],
            searchFilter="({})".format(
                    os.environ.get(
                        'LDAP_FILTER', "objectClass=groupOfMembers"
                    )
                ),
            retrieveAttributes=[]):

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

            self.groups[key] = {
                'attributes': attributes
            }


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
        return {
            'name': self.name,
            'instance': self.instance()
        }

    def instance(self):
        if self.irods_instance:
            return {
                'id': self.irods_instance.id,
                'name': self.irods_instance.name,
                'type': self.irods_instance.type,
                'zone': self.irods_instance.zone,
                'metadata': self.metadata()
            }
        else:
            return {}

    def metadata(self):
        result = {}

        if not self.irods_instance:
            return result

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
        if not self.irods_instance:
            return

        if not self.must_keep:
            self.remove()
        else:
            if not DRY_RUN:
                self.irods_instance.metadata.remove_all()

            ssh("sudo useradd -m {}".format(self.name))
            ssh("sudo su - {} -c \"mkdir -m 755 -p .ssh .irods\"".format(
                self.name
                ))

            pubkeys = self.attributes.get('sshPublicKey', [])

            for k in pubkeys:
                ssh("sudo su - {} -c \"echo '{}' > .ssh/authorized_keys\"".format(
                        self.name, k
                    )
                )

            if len(pubkeys) > 0:
                ssh("sudo su - {} -c \"chmod 600 .ssh/authorized_keys\"".format(
                        self.name
                    )
                )

            env = json.dumps({
                    "irods_host": "icat",
                    "irods_port": int(IRODS_PORT),
                    "irods_user_name": "{}".format(self.name),
                    "irods_zone_name": "{}".format(IRODS_ZONE),
                    "irods_authentication_scheme": "PAM_INTERACTIVE",
                    "schema_version": "v3",
                    "irods_ssl_ca_certificate_file": "/etc/irods/ssl/irods.crt",
                    "irods_ssl_verify_server": "none"
                }, indent=4).replace('"', '\\""')

            ssh('sudo su - {} -c "echo -e \'{}\' > .irods/irods_environment.json"'.format(
                    self.name, env
                    )
                )

            env = f"""
            irodsHost icat
            irodsPort {IRODS_PORT}
            irodsUserName {self.name}
            irodsZone {IRODS_ZONE}
            """

            ssh('sudo su - {} -c "echo -e \'{}\' > .irods/.irodsEnv"'.format(
                    self.name, env
                    )
                )

            if not DRY_RUN and self.attributes:
                for k, v in self.attributes.items():
                    for i in v:
                        self.irods_instance.metadata.add(k, i)

    def remove(self):
        if not self.irods_instance:
            return

        logger.info("IRODS Remove User: {}".format(self.name))
        if not DRY_RUN:
            self.irods_instance.remove()

        ssh("sudo userdel -r {}".format(self.name))

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
        return {
            "name": self.name,
            'members': [
                m for m in self.members.keys()
            ],
            'instance': self.instance()
        }

    def instance(self):
        if self.irods_instance:
            return {
                'id': self.irods_instance.id,
                'name': self.irods_instance.name,
                'metadata': self.metadata()
            }
        else:
            return {}

    def metadata(self):
        result = {}

        if not self.irods_instance:
            return result

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
        if not self.irods_instance:
            return

        if not self.must_keep:
            self.remove()
        else:
            for m in self.members.keys():
                if not self.members[m] and self.irods_instance.hasmember(m):
                    logger.info(
                        "IRODS Remove {} from Group: {} ...".format(
                            m, self.name
                        )
                    )
                    if not DRY_RUN:
                        self.irods_instance.removemember(m)
                if self.members[m] and not self.irods_instance.hasmember(m):
                    logger.info(
                        "IRODS Add {} to Group: {}...".format(
                            m, self.name
                        )
                    )
                    if not DRY_RUN:
                        self.irods_instance.addmember(m)

            if not DRY_RUN:
                self.irods_instance.metadata.remove_all()

            if not DRY_RUN and self.attributes:
                for k, v in self.attributes.items():
                    for i in v:
                        self.irods_instance.metadata.add(k, i)

    def remove(self):
        if not self.irods_instance:
            return

        for m in self.members:
            if self.irods_instance.hasmember(m):
                logger.info(
                    "IRODS Remove {} from group: {}...".format(
                        m, self.name
                    )
                )
                if not DRY_RUN:
                    self.irods_instance.removemember(m)

        logger.info("IRODS Remove Group: {}".format(self.name))
        if not DRY_RUN:
            self.irods_instance.remove()

        self.must_keep = False
        self.irods_instance = None
        self.members = []


class iRODS(object):

    def __init__(self):
        try:
            try:
                env_file = os.environ['IRODS_ENVIRONMENT_FILE']
            except KeyError as ke:
                logger.error("Problem finding env var IRODS_ENVIRONMENT_FILE, error: {}".format(str(ke)))
                env_file = os.path.expanduser('~/.irods/irods_environment.json')
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=None, capath=None, cadata=None)
            ssl_settings = {'ssl_context': ssl_context}
            self.session = iRODSSession(irods_env_file=env_file, **ssl_settings)
        except Exception as e:
            logger.error("Problem loading ~/.irods/irods_environment.json, error: {}".format(str(e)))
            self.session = iRODSSession(
                host=IRODS_HOST,
                port=IRODS_PORT,
                user=IRODS_USER,
                password=IRODS_PASS,
                zone=IRODS_ZONE
            )
        except Exception as e:
            logger.error(
                "Problem connecting to IRODS {} error: {}".
                format(os.environ['IRODS_HOST'], str(e))
            )
            exit(1)

        self.users = {}
        self.groups = {}

        self.get_users()
        self.get_groups()

    def __exit__(self, exception_type, exception_value, traceback):
        self.session.cleanup()
        self.session = None

    def json(self):
        return {
            'users': [u.json() for _, u in self.users.items()],
            'groups': [g.json() for _, g in self.groups.items()]
        }

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def add_user(self, name, instance=None):
        if name in self.users:
            return

        if not instance and not DRY_RUN:
            logger.info("IRODS Create User: {}".format(name))
            instance = self.session.users.create(name, 'rodsuser')

        self.users[name] = USER(name, instance)

    def add_group(self, name, instance=None):
        if name in self.groups:
            return

        if not instance and not DRY_RUN:
            logger.info("IRODS Create Group: {}".format(name))
            if not instance and not DRY_RUN:
                instance = self.session.user_groups.create(name)

        self.groups[name] = GROUP(name, instance)

    def get_users(self):
        query = self.session.query(User.name, User.id, User.type).filter(
            Criterion('=', User.type, 'rodsuser'))

        for result in query:
            name = result[User.name]

            self.add_user(name, instance=self.session.users.get(name))

        logger.debug("iRODS Users: {}".format(self))

        return self

    def get_groups(self):
        query = self.session.query(User.name, User.id, User.type).filter(
                Criterion('=', User.type, 'rodsgroup'))

        for result in query:
            name = result[User.name]
            if name in ['rodsadmin', 'public']:
                continue

            self.add_group(name, instance=self.session.user_groups.get(name))

        logger.debug("iRODS Groups: {}".format(self))

        return self

    def sync(self):
        logger.debug("Syncing...")

        for _, u in self.users.items():
            u.sync()

        for _, g in self.groups.items():
            g.sync()


def run():

    start_time = datetime.now()
    logger.info("SYNC started at: {}".format(start_time))

    # Read LDAP...
    my_ldap = Ldap()

    # Read iRODS...
    my_irods = iRODS()

    # process iRODS people...
    for u in my_ldap.people.keys():
        if u not in my_irods.users:
            my_irods.add_user(u)

        my_irods.users[u].keep(my_ldap.people[u]['attributes'])

    # process iRODS groups...
    for g in my_ldap.groups.keys():
        if g not in my_irods.groups:
            my_irods.add_group(g)

        my_irods.groups[g].keep(my_ldap.groups[g]['attributes'])

        for m in my_ldap.groups[g]['attributes']['member']:
            my_irods.groups[g].member(m)

    # Write changes to iRODS
    my_irods.sync()

    logger.info("SYNC completed at: {}".format(start_time))


if __name__ == "__main__":
    run()
