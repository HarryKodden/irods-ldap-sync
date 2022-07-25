#!/usr/bin/env python
from __future__ import print_function

import os
import ldap
import json
import logging
import ssl
import uuid

from datetime import datetime

from irods.session import iRODSSession
from irods.column import Criterion
from irods.models import User
from irods.access import iRODSAccess

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=logging.getLevelName(log_level),
    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('root')

# Start with some defaults...
IRODS_HOST = 'localhost'
IRODS_PORT = 1247
IRODS_USER = 'irods'
IRODS_ZONE = 'tempZone'
IRODS_AUTH = 'native'

DEFAULT_IRODS_ENVIRONMENT_FILE='~/.irods/irods_environment.json'

IRODS_JSON = {}

try:
    fname = os.environ.get('IRODS_JSON', os.path.expanduser(DEFAULT_IRODS_ENVIRONMENT_FILE))
    
    logger.info("Trying to read environment file: '{}'".format(fname))

    with open(fname) as f:
        IRODS_JSON = json.load(f)

        IRODS_HOST = IRODS_JSON.pop('irods_host', None)
        IRODS_PORT = IRODS_JSON.pop('irods_port', None)
        IRODS_USER = IRODS_JSON.pop('irods_user_name', None)
        IRODS_ZONE = IRODS_JSON.pop('irods_zone_name', None)

except Exception:
    pass

IRODS_HOST = os.environ.get('IRODS_HOST', IRODS_HOST)
IRODS_ZONE = os.environ.get('IRODS_ZONE', IRODS_ZONE)
IRODS_PORT = os.environ.get('IRODS_PORT', IRODS_PORT)
IRODS_USER = os.environ.get('IRODS_USER', IRODS_USER)
IRODS_AUTH = os.environ.get('IRODS_AUTH', IRODS_AUTH)
IRODS_CERT = os.environ.get('IRODS_CERT', None)

IRODS_PASS = os.environ.get('IRODS_PASS', None)
if not IRODS_PASS:
    try:
        IRODS_PASS = iRODSSession.get_irods_password(** IRODS_JSON)
    except:
        logger.error("No iRODS Password provided, can not proceed.")
        exit(-1)

SSH_SKIP = os.environ.get('SSH_SKIP', 'FALSE').upper() == 'TRUE'
SSH_HOST = os.environ.get('SSH_HOST', 'localhost')
SSH_PORT = os.environ.get('SSH_PORT', 2222)
SSH_USER = os.environ.get('SSH_USER', 'root')

DRY_RUN = (os.environ.get('DRY_RUN', 'FALSE').upper() == 'TRUE')

logger.info(f"Connecting to irods: {IRODS_USER}#{IRODS_ZONE}@{IRODS_HOST}:{IRODS_PORT}")

import subprocess

class ssh():
    def __init__(self, command, host=SSH_HOST, port=SSH_PORT, user=SSH_USER):
        global SSH_SKIP

        self.command = command
        self.host = host
        self.port = port
        self.user = user

        if SSH_SKIP:
            logger.debug("SKIPPING: {}".format(command))
        else:
            self.run()

    def run(self):

        command = [
                '/usr/bin/ssh',
                '-p', '{}'.format(self.port),
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                self.user+'@'+self.host,
                self.command
        ]

        logger.debug("Executing command: {} on {}".format(command, self.host))

        if DRY_RUN:
            return

        result = subprocess.run(command, capture_output=True, text=True)
        if result.stdout > '':
            logger.debug("{}:\n*** TOP OF STDOUT ***\n{}*** END OF STDOUT ***".format(command, result.stdout))
        if result.stderr > '':
            logger.debug("{}:\n*** TOP OF STDERR ***\n{}*** END OF STDERR ***".format(command, result.stderr))
    
class Ldap(object):

    def __init__(self):
        # Establish connection with LDAP...
        try:
            self.page_size = int(os.environ.get('LDAP_PAGE_SIZE', 50))

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

    def __enter__(self):
        self.get_people()
        self.get_groups()

        return self

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

        try:
            page_control = ldap.controls.SimplePagedResultsControl(True, size=self.page_size, cookie='')
            result = []
    
            while True:
    
                page_id = self.session.search_ext(
                    dn, searchScope,
                    searchFilter,
                    retrieveAttributes,
                    serverctrls=[page_control]
                )
                _, result_data, _, serverctrls = self.session.result3(page_id)

                
                for r in result_data:
                    result.append([r])

                controls = [
                    control for control in serverctrls
                    if control.controlType == ldap.controls.SimplePagedResultsControl.controlType
                ]

                if not controls:
                    logger.error('The server ignores RFC 2696 control')
                    
                if not controls[0].cookie:
                    break

                page_control.cookie = controls[0].cookie

        except ldap.LDAPError as e:
            result = None
            logger.error("[LDAP] SEARCH: '%s' ERROR: %s\n" % (dn, str(e)))
            exit(-1)

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
                os.environ.get('LDAP_BASE_DN',''),
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
            os.environ.get('LDAP_BASE_DN',''),
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

class USER:

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
            'id': self.irods_instance.id,
            'name': self.irods_instance.name,
            'type': self.irods_instance.type,
            'zone': self.irods_instance.zone,
            'metadata': self.metadata()
        } if self.irods_instance else {}

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

    def sync(self, salvage_function):

        if not self.irods_instance:
            return

        if not self.must_keep:
            logger.info("IRODS Remove User: {}".format(self.name))

            if not DRY_RUN:
                try:
                    # this succeeds if user has no data attached...
                    self.irods_instance.remove()
                except:
                    salvage_function(self)

                ssh("sudo userdel -r {} 2>/dev/null".format(self.name))

            self.must_keep = False
            self.irods_instance = None

        else:
            if not DRY_RUN:
                self.irods_instance.metadata.remove_all()

            ssh("sudo useradd -m {} 2>/dev/null".format(self.name))
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
                    "irods_authentication_scheme": IRODS_AUTH,
                    **IRODS_JSON
                }, indent=4).replace('"', '\\""')

            ssh('sudo su - {} -c "echo \'{}\' > {}"'.format(
                    self.name, env, DEFAULT_IRODS_ENVIRONMENT_FILE
                    )
                )

            env = f"""
            irodsHost icat
            irodsPort {IRODS_PORT}
            irodsUserName {self.name}
            irodsZone {IRODS_ZONE}
            """

            ssh('sudo su - {} -c "echo \'{}\' > .irods/.irodsEnv"'.format(
                    self.name, env
                    )
                )

            if not DRY_RUN and self.attributes:
                for k, v in self.attributes.items():
                    for i in v:
                        self.irods_instance.metadata.add(k, i)


class GROUP:

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
            'id': self.irods_instance.id,
            'name': self.irods_instance.name,
            'metadata': self.metadata(),
            'members': [
                m for m in self.members.keys()
            ],
        } if self.irods_instance else {}

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

    def sync(self, salvage_function):

        if not self.irods_instance:
            return

        if not self.must_keep:

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
                try:
                    # this succeeds if group no data attached...
                    self.irods_instance.remove()
                except Exception:
                    salvage_function(self)

            self.irods_instance = None
            self.members = []

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

irods_session = None

class iRODS(object):

    def __init__(self):

        self.users = {}
        self.groups = {}

        global irods_session

        if irods_session:
            # resuse earlier instantiated iRODS session.
            self.session = irods_session
            return

        session_options = {}

        if IRODS_CERT:
            session_options.update(
                ssl_context = ssl.create_default_context(cafile=IRODS_CERT)
            )   

        session_options.update(**IRODS_JSON)

        logger.debug("Session options: {}".format(session_options))

        try:
            self.session = iRODSSession(
                host=IRODS_HOST,
                port=IRODS_PORT,
                user=IRODS_USER,
                zone=IRODS_ZONE,
                password=IRODS_PASS,
                **session_options
            )
        except Exception as e:
            raise Exception(
                "Problem connecting to IRODS {} error: {}".
                    format(IRODS_HOST, str(e))
            )

        irods_session = self.session

    def __enter__(self):
        logger.debug("*** iRODS Connected!")

        self.get_users()
        self.get_groups()
        
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("*** iRODS Disconnect !")

    def json(self):
        return {
            'users': { k: v.json() for k,v in self.users.items() },
            'groups': { k: v.json() for k,v in self.groups.items() }
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

            instance = self.session.user_groups.get(name)

            if 'DELETED' in instance.metadata.keys():
                logger.debug("Deleted group detected")
                logger.debug("* Original user/group: {}".format(instance.metadata.get_one("DELETED").value))
                logger.debug("* Timestamp: {}".format(instance.metadata.get_one("TIMESTAMP").value))
                logger.debug("* Owners: {}".format([u.name for u in instance.members]))
                continue

            self.add_group(name, instance=instance)

        logger.debug("iRODS Groups: {}".format(self))

        return self

    def sync(self):
        logger.debug("Syncing...")

        def show_collection(title, collection, level=0):

            logger.info(f"[{title}-DIR]" + '*' * (level) + f" {collection.path}:")
            for d in collection.data_objects:
                logger.info(f"[{title}-OBJ]" + '*' * (level+1) + f" {d.path}")
            for c in collection.subcollections:
                show_collection(title, c, level+1)

        def data_salvager(obsolete):

            def destination(src, dst, target):
                path = target[len(src):]

                for p in path.split('/')[:-1]:
                    dst += f"/{p}"
                    if not self.session.collections.get(dst):
                        logger.info(f"[INTERMEDIATE COLLECTION]: {dst}")
                        self.session.collections.create(dst)

                    src += f"/{p}"

                    logger.info(f"*** Grant ownership to {src} to: {IRODS_USER}")
                    acl = iRODSAccess('admin:own', src, IRODS_USER, IRODS_ZONE)
                    self.session.permissions.set(acl)
                    
                return dst

            if isinstance(obsolete, GROUP) and len(obsolete.members) > 0:
                raise Exception("Obsolete group still has members")

            try:
                logger.info("*** Create salvage group...")

                instance = self.session.user_groups.create(str(uuid.uuid4()))
                instance.metadata.add("DELETED", obsolete.name)
                instance.metadata.add("TIMESTAMP", datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
                instance.addmember(IRODS_USER)

                src = "/{}/home/{}".format(IRODS_ZONE, obsolete.name)
                dst = "/{}/home/{}".format(IRODS_ZONE, instance.name)

                logger.info(f"*** Grant ownership to {src} to: {IRODS_USER}")
                acl = iRODSAccess('admin:own', src, IRODS_USER, IRODS_ZONE)
                self.session.permissions.set(acl, recursive=True)

                logger.info(f"*** Enable inherit on {dst}")
                acl = iRODSAccess('inherit', dst, instance.name, IRODS_ZONE)
                self.session.permissions.set(acl)

                contents = self.session.collections.get(src).walk(topdown=True)

                try:
                    while True:
                        _, dir, obj = next(contents)

                        for i in dir:
                            dest = destination(src, dst, i.path[len(src):])

                            logger.info(f"*** Grant ownership to {i.path} to: {IRODS_USER}")
                            acl = iRODSAccess('admin:own', i.path, IRODS_USER, IRODS_ZONE)
                            self.session.permissions.set(acl)

                            logger.info(f"Collection {i.path} moving to {dest}...")

                            self.session.collections.move(i.path, dest)

                        for i in obj:
                            dest = destination(src, dst, i.path[len(src):])

                            logger.info(f"Data object {i.path} moving to {dest}...")

                            self.session.data_objects.move(i.path, dest)

                except StopIteration:
                    logger.info("Contents processed !")

                show_collection("DST", self.session.collections.get(dst))

                logger.info("*** Remove irods instance: {}".format(obsolete.name))
                obsolete.irods_instance.remove()

            except Exception as e:
                logger.error("Error creating salvager group: {}".format(str(e)))

        for _, u in self.users.items():
            try:
                u.sync(data_salvager)
            except Exception:
                logger.error("Exception during sync user: {}".format(u.name))

        for _, g in self.groups.items():
            try:
                g.sync(data_salvager)
            except Exception as e:
                logger.error("Exception during sync group: {}, error: {}".format(g.name, str(e)))


def sync(dry_run = DRY_RUN):

    DRY_RUN = dry_run
    
    start_time = datetime.now()
    logger.info("SYNC started at: {}".format(start_time))
    logger.info("DRY_RUN: {}".format(DRY_RUN))

    # Read LDAP...

    with iRODS() as my_irods:
        with Ldap() as my_ldap:

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
    sync()
