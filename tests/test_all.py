import os
import logging
from src.sync import DRY_RUN, run, Ldap, iRODS, ssh

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class MutableLdap(Ldap):

    def delete(self, objectClass, target):
        filter = f"(&(ObjectClass={objectClass})({target}))"

        result = self.search(os.environ['LDAP_BASE_DN'], searchFilter=filter)

        assert(len(result) == 1)
        entries = result[0]

        assert(len(entries) == 1)
        rdn, _ = entries[0]

        logger.info(rdn)
        assert(rdn.startswith(target))
        
        self.session.delete(rdn)

    def add(self, dn, attrs):
        from ldap import modlist

        logger.info(dn)
        ldif = modlist.addModlist(attrs)
        logger.info(ldif)
        self.session.add_s(dn,ldif)

    def add_person(self, name):
        logger.info("ADD PERSON: {}".format(name))

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
        logger.info("ADD GROUP: {}".format(name))

        self.add(
            f"{os.environ.get('LDAP_GROUP_KEY', 'cn')}={name},{os.environ['LDAP_BASE_DN']}",
            {
                'objectclass': [b'top',b'groupOfMembers'],
                f"{os.environ.get('LDAP_GROUP_KEY', 'cn')}": [name.encode()]
            }
        )

    def delete_person(self, name):
        logger.info("DELETE PERSON: {}".format(name))

        self.delete("inetOrgPerson", "{}={}".format(
                os.environ.get('LDAP_USER_KEY', 'uid'), name
            )
        )        

    def delete_group(self, name):
        logger.info("DELETE GROUP: {}".format(name))
    
        self.delete("groupOfMembers", "{}={}".format(
                os.environ.get('LDAP_GROUP_KEY', 'cn'), name
            )
        )


class TestAll(BaseTest):

    def test_01_ldap_content(self):
        my_ldap = Ldap()
        logger.info(my_ldap)

    def test_02_sync_ldap_to_irods_dry_run(self):
        DRY_RUN = True
        run()

    def test_02_sync_ldap_to_irods(self):
        DRY_RUN = False
        run()

    def test_03_irods_content(self):
        my_irods = iRODS()
        logger.info(my_irods)

    def test_04_irods_iinit(self):
        password = os.environ.get('IRODS_PASS', 'password')
        ssh(f"echo {password} | iinit 2>/dev/null")

    def test_05_irods_iadmin_list_users(self):
        ssh("iadmin lu")

    def test_06_irods_iadmin_list_groups(self):
        ssh("iadmin lg")

    def test_07_irods_sync_after_ldap_add_person(self):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        u = "test_user"
        try:
            my_ldap.delete_person(u)
        except Exception:
            pass

        my_ldap.add_person(u)
        run()
        my_irods = iRODS()
        
    def test_08_irods_sync_after_add_group(self):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        g = "test_group"

        try:
            my_ldap.delete_group(g)
        except Exception:
            pass

        my_ldap.add_group(g)
        run()
        my_irods = iRODS()
        
    def test_09_irods_sync_after_ldap_delete_person(self):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        u = "test_user"

        try:
            my_ldap.add_person(u)
        except Exception:
            pass

        my_ldap.delete_person(u)
        run()
        my_irods = iRODS()
        
    def test_10_irods_sync_after_delete_group(self):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        g = "test_group"
        try:
            my_ldap.add_group(g)
        except Exception:
            pass
        my_ldap.delete_group(g)
        run()
        my_irods = iRODS()
