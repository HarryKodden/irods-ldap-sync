import os
import logging
import pytest
from src.sync import DRY_RUN, sync, Ldap, iRODS, ssh

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class MutableLdap(Ldap):

    def delete(self, objectClass, target):

        try:
            filter = f"(&(ObjectClass={objectClass})({target}))"

            result = self.search(os.environ['LDAP_BASE_DN'], searchFilter=filter)

            assert(len(result) == 1)
            entries = result[0]

            assert(len(entries) == 1)
            rdn, _ = entries[0]

            logger.debug(rdn)
            assert(rdn.startswith(target))
        
            self.session.delete(rdn)
        except Exception as e:
            raise Exception("Error during LDAP delete: {}, error: {}".format(target, str(e)))

    def add(self, dn, attrs):
        from ldap import modlist

        try:
            logger.debug(dn)
            ldif = modlist.addModlist(attrs)
            logger.debug(ldif)
            self.session.add_s(dn,ldif)
        except Exception as e:
            raise Exception("Error during LDAP add: {}, error: {}".format(dn, str(e)))

    def add_person(self, name):
        logger.debug("Add person: {} toLDAP".format(name))

        self.add(
            f"{os.environ.get('LDAP_USER_KEY', 'uid')}={name},{os.environ['LDAP_BASE_DN']}",
            {
                'objectclass': [b'top',b'inetOrgPerson'],
                f"{os.environ.get('LDAP_USER_KEY', 'uid')}": [name.encode()],
                'sn': [b'n/a'],
                'cn': [b'n/a']
            }
        )

    def add_group(self, name):
        logger.debug("Add group: {} to LDAP".format(name))

        self.add(
            f"{os.environ.get('LDAP_GROUP_KEY', 'cn')}={name},{os.environ['LDAP_BASE_DN']}",
            {
                'objectclass': [b'top',b'groupOfMembers'],
                f"{os.environ.get('LDAP_GROUP_KEY', 'cn')}": [name.encode()]
            }
        )

    def delete_person(self, name):
        logger.debug("Delete person: {} from LDAP".format(name))

        self.delete("inetOrgPerson", "{}={}".format(
                os.environ.get('LDAP_USER_KEY', 'uid'), name
            )
        )        

    def delete_group(self, name):
        logger.debug("Delete group: {} from LDAP".format(name))
    
        self.delete("groupOfMembers", "{}={}".format(
                os.environ.get('LDAP_GROUP_KEY', 'cn'), name
            )
        )


class TestAll(BaseTest):

    user = "test_user"
    group = "test_group"

    @classmethod
    def teardown_class(cls):
        logger.info("Teardown, removing test user/group...")

        my_ldap = MutableLdap()

        try:
            my_ldap.delete_person(cls.user)
        except Exception:
            pass

        try:
            my_ldap.delete_group(cls.group)
        except Exception:
            pass
            
        try:
            sync()
        except Exception as e:
            pass

    def test_ldap_content(self):
        logger.debug(Ldap())

    def test_sync_ldap_to_irods_dry_run(self, depends=['test_ldap_content']):
        DRY_RUN = True
        sync()

    def test_sync_ldap_to_irods(self, depends=['test_ldap_content']):
        DRY_RUN = False
        sync()

        my_ldap = Ldap()
        my_irods = iRODS()

        for u in my_ldap.people.keys():
            assert u in my_irods.users.keys()
        for g in my_ldap.groups.keys():
            assert g in my_irods.groups.keys()

    def test_irods_content(self, depends=['test_sync_ldap_to_irods']):
        logger.debug(iRODS())

    def test_irods_iinit(self, depends=['test_irods_content']):
        password = os.environ.get('IRODS_PASS', 'password')
        ssh(f"echo {password} | iinit 2>/dev/null")

    def test_irods_iadmin_list_users(self, depends=['test_irods_iinit']):
        ssh("iadmin lu")

    def test_irods_iadmin_list_groups(self, depends=['test_irods_iinit']):
        ssh("iadmin lg")

    def test_irods_sync_user_updates(self, depends=['test_sync_ldap_to_irods']):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        my_ldap.add_person(self.user)
        sync()
        assert self.user in iRODS().users

        my_ldap.delete_person(self.user)
        sync()
        assert self.user not in iRODS().users
        
    def test_irods_sync_group_updates(self, depends=['test_sync_ldap_to_irods']):
        my_ldap = MutableLdap()
        
        DRY_RUN = False
        
        my_ldap.add_group(self.group)
        sync()
        assert self.group in iRODS().groups

        my_ldap.delete_group(self.group)
        sync()
        assert self.group not in iRODS().groups