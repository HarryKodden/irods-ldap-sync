import logging
from src.sync import run, Ldap, iRODS, ssh

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class TestAll(BaseTest):

    def test_01_ldap(self):
        my_ldap = Ldap()
        logger.info(my_ldap)

    def test_01_sync(self):
        run()

    def test_03_irods(self):
        my_irods = iRODS()
        logger.info(my_irods)

    def test_04_ssh(self):
        ssh("echo 'hello world'")


