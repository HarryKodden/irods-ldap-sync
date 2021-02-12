import os
import logging
from src.sync import run, Ldap, iRODS, ssh

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class TestAll(BaseTest):

    def test_01_ldap(self):
        my_ldap = Ldap()
        logger.info(my_ldap)

    def test_02_sync(self):
        run()

    def test_03_irods(self):
        my_irods = iRODS()
        logger.info(my_irods)

    def test_04_iinit(self):
        env = f"""
        irodsHost icat
        irodsPort {os.environ.get('IRODS_PORT', 1247)}
        irodsUserName {os.environ.get('IRODS_PASS', 'password')}
        irodsZone  {os.environ.get('IRODS_ZONE', 'tempZone' )}
        """
        password = os.environ.get('IRODS_PASS', 'password')

        ssh(f"echo {password} | iinit 2>/dev/null")

    def test_05_iadmin_list_users(self):
        ssh("iadmin lu")

    def test_06_iadmin_list_groups(self):
        ssh("iadmin lg")
