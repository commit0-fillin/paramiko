"""
`.AuthHandler`
"""
import weakref
import threading
import time
import re
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_DISCONNECT, DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, cMSG_USERAUTH_REQUEST, cMSG_SERVICE_ACCEPT, DEBUG, AUTH_SUCCESSFUL, INFO, cMSG_USERAUTH_SUCCESS, cMSG_USERAUTH_FAILURE, AUTH_PARTIALLY_SUCCESSFUL, cMSG_USERAUTH_INFO_REQUEST, WARNING, AUTH_FAILED, cMSG_USERAUTH_PK_OK, cMSG_USERAUTH_INFO_RESPONSE, MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, MSG_USERAUTH_REQUEST, MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE, MSG_USERAUTH_BANNER, MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE, cMSG_USERAUTH_GSSAPI_RESPONSE, cMSG_USERAUTH_GSSAPI_TOKEN, cMSG_USERAUTH_GSSAPI_MIC, MSG_USERAUTH_GSSAPI_RESPONSE, MSG_USERAUTH_GSSAPI_TOKEN, MSG_USERAUTH_GSSAPI_ERROR, MSG_USERAUTH_GSSAPI_ERRTOK, MSG_USERAUTH_GSSAPI_MIC, MSG_NAMES, cMSG_USERAUTH_BANNER
from paramiko.message import Message
from paramiko.util import b, u
from paramiko.ssh_exception import SSHException, AuthenticationException, BadAuthenticationType, PartialAuthentication
from paramiko.server import InteractiveQuery
from paramiko.ssh_gss import GSSAuth, GSS_EXCEPTIONS

class AuthHandler:
    """
    Internal class to handle the mechanics of authentication.
    """

    def __init__(self, transport):
        self.transport = weakref.proxy(transport)
        self.username = None
        self.authenticated = False
        self.auth_event = threading.Event()
        self.auth_method = ''
        self.banner = None
        self.password = None
        self.private_key = None
        self.interactive_handler = None
        self.submethods = None
        self.auth_username = None
        self.auth_fail_count = 0
        self.gss_host = None
        self.gss_deleg_creds = True

    def auth_interactive(self, username, handler, event, submethods=''):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        self.username = username
        self.interactive_handler = handler
        self.auth_event = event
        self.submethods = submethods

        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string('ssh-connection')
        m.add_string('keyboard-interactive')
        m.add_string('')
        m.add_string(submethods)
        self.transport._send_message(m)

    def _get_key_type_and_bits(self, key):
        """
        Given any key, return its type/algorithm & bits-to-sign.

        Intended for input to or verification of, key signatures.
        """
        if isinstance(key, RSAKey):
            return 'ssh-rsa', key.public_blob.key_blob
        elif isinstance(key, DSSKey):
            return 'ssh-dss', key.public_blob.key_blob
        elif isinstance(key, ECDSAKey):
            return key.public_blob.key_type, key.public_blob.key_blob
        elif isinstance(key, Ed25519Key):
            return 'ssh-ed25519', key.public_blob.key_blob
        else:
            raise SSHException('Unknown key type')

class GssapiWithMicAuthHandler:
    """A specialized Auth handler for gssapi-with-mic

    During the GSSAPI token exchange we need a modified dispatch table,
    because the packet type numbers are not unique.
    """
    method = 'gssapi-with-mic'

    def __init__(self, delegate, sshgss):
        self._delegate = delegate
        self.sshgss = sshgss
    __handler_table = {MSG_SERVICE_REQUEST: _parse_service_request, MSG_USERAUTH_REQUEST: _parse_userauth_request, MSG_USERAUTH_GSSAPI_TOKEN: _parse_userauth_gssapi_token, MSG_USERAUTH_GSSAPI_MIC: _parse_userauth_gssapi_mic}

class AuthOnlyHandler(AuthHandler):
    """
    AuthHandler, and just auth, no service requests!

    .. versionadded:: 3.2
    """

    def send_auth_request(self, username, method, finish_message=None):
        """
        Submit a userauth request message & wait for response.

        Performs the transport message send call, sets self.auth_event, and
        will lock-n-block as necessary to both send, and wait for response to,
        the USERAUTH_REQUEST.

        Most callers will want to supply a callback to ``finish_message``,
        which accepts a Message ``m`` and may call mutator methods on it to add
        more fields.
        """
        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string('ssh-connection')
        m.add_string(method)
        if finish_message:
            finish_message(m)
        self.auth_event.clear()
        self.transport._send_message(m)
        self.auth_event.wait()
        return self.authenticated

    def auth_interactive(self, username, handler, submethods=''):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        return self.send_auth_request(username, 'keyboard-interactive', lambda m: m.add_string('').add_string(submethods))
