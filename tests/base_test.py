from unittest import TestCase

import logging
import os
import threading
import asyncio
import socket
import time
import json

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class BaseTest(TestCase):

    ldap_conf = {
        'uri': os.environ.get("LDAP_URL", "ldap://localhost:389"),
        'basedn': os.environ.get("LDAP_BASE_DN", "de=example,dc=org"),
        'binddn': os.environ.get("LDAP_BIND_DN", "admin"),
        'passwd': os.environ.get("LDAP_ADMIN_PASSWORD", "secret")
    }

    irods_conf = {
        'irods_host': os.environ.get("IRODS_HOST", "localhost"),
        'irods_port': os.environ.get("IRODS_PORT", "1247"),
        'irods_user': os.environ.get("IRODS_USER", "rods"),
        'irods_pass': os.environ.get("IRODS_PASS", "password"),
        'irods_zone': os.environ.get("IRODS_ZONE", "tempZone")
    }
