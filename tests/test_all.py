import logging
from src.sync import run

from tests.base_test import BaseTest

logger = logging.getLogger(__name__)

class TestAll(BaseTest):
    def test_run(self):
        run()
