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

    def test_07_irods_sync_after_ldap_updates(self):
        my_ldap = MutableLdap()
        
        DRY_RUN = False

        my_ldap.add_user("test7", {})
        run()
        my_irods = iRODS()
        logger.info(my_irods)

        #my_ldap.delete_person("test7")
        #run()
        
