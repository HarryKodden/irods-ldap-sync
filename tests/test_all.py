import os
import logging
import pytest
from src.sync import sync, Ldap, iRODS, ssh

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
        logger.info("Teardown, verify test user/group are removed")

        with MutableLdap() as my_ldap:

            """ if tests PASS, then test user/group are removed already
                if tests FAIL, maybe they are not removed decently,
                below is a safe guard for that situation
            """
            need_sync = False

            try:
                my_ldap.delete_person(cls.user)
                need_sync = True
            except Exception:
                pass

            try:
                my_ldap.delete_group(cls.group)
                need_sync = True
            except Exception:
                pass
            
            if need_sync:
                sync()

    @pytest.mark.order(1)
    def test_ldap_content(self):
        with Ldap() as my_ldap:
            logger.info(my_ldap)
    
    @pytest.mark.order(2)
    def test_sync_ldap_to_irods_dry_run(self):
        sync(dry_run=True)

    @pytest.mark.order(3)
    def test_sync_ldap_to_irods(self):
        sync()

        with Ldap() as my_ldap:
            with iRODS() as my_irods:

                for u in my_ldap.people.keys():
                    assert u in my_irods.users.keys()
                for g in my_ldap.groups.keys():
                    assert g in my_irods.groups.keys()

    @pytest.mark.order(4)
    def test_irods_content(self):
        with iRODS() as my_irods:
            logger.info(my_irods)
        
    @pytest.mark.order(5)
    def test_irods_iinit(self):
        password = os.environ.get('IRODS_PASS', 'password')
        ssh(f"echo {password} | iinit 2>/dev/null")

    @pytest.mark.order(6)
    def test_irods_iadmin_list_users(self):
        ssh("iadmin lu")

    @pytest.mark.order(7)
    def test_irods_iadmin_list_groups(self):
        ssh("iadmin lg")

    @pytest.mark.order(8)
    def test_irods_sync_user_updates(self):

        def update_user(with_data):
            with MutableLdap() as my_ldap:
            
                my_ldap.add_person(self.user)
                sync()
            
                with iRODS() as my_irods:
                    assert self.user in my_irods.users
                    password = 'secret'

                    if with_data:
                        logger.info("Create data for this user...")

                        my_irods.session.users.modify(self.user, 'password', password)
                        ssh(f"sudo su - {self.user} bash -c 'echo {password} | iinit 2>/dev/null; ls -l > data; imkdir foo; iput -f data; iput -f data foo/data;'")
 
                my_ldap.delete_person(self.user)
                sync()
            
                with iRODS() as my_irods:
                    assert self.user not in my_irods.users
                    
        for withdata_yes_or_no in (True, False):
            update_user(withdata_yes_or_no)
            
    def test_irods_sync_group_updates(self):
        with MutableLdap() as my_ldap:
                
            my_ldap.add_group(self.group)
            sync()

            ssh("iadmin lg")

            with iRODS() as my_irods:
                assert self.group in my_irods.groups

            my_ldap.delete_group(self.group)
            sync()
       
            with iRODS() as my_irods:
                assert self.group not in my_irods.groups