import logging
from src.sync import run, iRODS_Users, iRODS_Groups

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class TestAll(BaseTest):
    def test_run(self):
        run()

        users = iRODS_Users().read()
        logger.info(users)

        groups = iRODS_Groups().read()
        logger.info(groups)



