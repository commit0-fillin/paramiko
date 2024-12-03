"""
This module provides GSS-API / SSPI  authentication as defined in :rfc:`4462`.

.. note:: Credential delegation is not supported in server mode.

.. seealso:: :doc:`/api/kex_gss`

.. versionadded:: 1.15
"""
import struct
import os
import sys
GSS_AUTH_AVAILABLE = True
GSS_EXCEPTIONS = ()
_API = None
try:
    import gssapi
    if hasattr(gssapi, '__title__') and gssapi.__title__ == 'python-gssapi':
        _API = 'MIT'
        GSS_EXCEPTIONS = (gssapi.GSSException,)
    else:
        _API = 'PYTHON-GSSAPI-NEW'
        GSS_EXCEPTIONS = (gssapi.exceptions.GeneralError, gssapi.raw.misc.GSSError)
except (ImportError, OSError):
    try:
        import pywintypes
        import sspicon
        import sspi
        _API = 'SSPI'
        GSS_EXCEPTIONS = (pywintypes.error,)
    except ImportError:
        GSS_AUTH_AVAILABLE = False
        _API = None
from paramiko.common import MSG_USERAUTH_REQUEST
from paramiko.ssh_exception import SSHException
from paramiko._version import __version_info__

def GSSAuth(auth_method, gss_deleg_creds=True):
    """
    Provide SSH2 GSS-API / SSPI authentication.

    :param str auth_method: The name of the SSH authentication mechanism
                            (gssapi-with-mic or gss-keyex)
    :param bool gss_deleg_creds: Delegate client credentials or not.
                                 We delegate credentials by default.
    :return: Either an `._SSH_GSSAPI_OLD` or `._SSH_GSSAPI_NEW` (Unix)
             object or an `_SSH_SSPI` (Windows) object
    :rtype: object

    :raises: ``ImportError`` -- If no GSS-API / SSPI module could be imported.

    :see: `RFC 4462 <http://www.ietf.org/rfc/rfc4462.txt>`_
    :note: Check for the available API and return either an `._SSH_GSSAPI_OLD`
           (MIT GSSAPI using python-gssapi package) object, an
           `._SSH_GSSAPI_NEW` (MIT GSSAPI using gssapi package) object
           or an `._SSH_SSPI` (MS SSPI) object.
           If there is no supported API available,
           ``None`` will be returned.
    """
    if not GSS_AUTH_AVAILABLE:
        raise ImportError("No GSS-API / SSPI module could be imported.")
    
    if _API == "MIT":
        return _SSH_GSSAPI_OLD(auth_method, gss_deleg_creds)
    elif _API == "PYTHON-GSSAPI-NEW":
        return _SSH_GSSAPI_NEW(auth_method, gss_deleg_creds)
    elif _API == "SSPI":
        return _SSH_SSPI(auth_method, gss_deleg_creds)
    else:
        return None

class _SSH_GSSAuth:
    """
    Contains the shared variables and methods of `._SSH_GSSAPI_OLD`,
    `._SSH_GSSAPI_NEW` and `._SSH_SSPI`.
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        self._auth_method = auth_method
        self._gss_deleg_creds = gss_deleg_creds
        self._gss_host = None
        self._username = None
        self._session_id = None
        self._service = 'ssh-connection'
        '\n        OpenSSH supports Kerberos V5 mechanism only for GSS-API authentication,\n        so we also support the krb5 mechanism only.\n        '
        self._krb5_mech = '1.2.840.113554.1.2.2'
        self._gss_ctxt = None
        self._gss_ctxt_status = False
        self._gss_srv_ctxt = None
        self._gss_srv_ctxt_status = False
        self.cc_file = None

    def set_service(self, service):
        """
        This is just a setter to use a non default service.
        I added this method, because RFC 4462 doesn't specify "ssh-connection"
        as the only service value.

        :param str service: The desired SSH service
        """
        self._service = service

    def set_username(self, username):
        """
        Setter for C{username}. If GSS-API Key Exchange is performed, the
        username is not set by C{ssh_init_sec_context}.

        :param str username: The name of the user who attempts to login
        """
        self._username = username

    def ssh_gss_oids(self, mode='client'):
        """
        This method returns a single OID, because we only support the
        Kerberos V5 mechanism.

        :param str mode: Client for client mode and server for server mode
        :return: A byte sequence containing the number of supported
                 OIDs, the length of the OID and the actual OID encoded with
                 DER
        :note: In server mode we just return the OID length and the DER encoded
               OID.
        """
        krb5_oid = self._make_uint32(1) + self._encode_oid(self._krb5_mech)
        if mode == 'server':
            return krb5_oid[4:]
        return krb5_oid

    def _encode_oid(self, oid):
        """Helper method to encode OID"""
        oid_parts = [int(part) for part in oid.split('.')]
        encoded = bytes([40 * oid_parts[0] + oid_parts[1]])
        for part in oid_parts[2:]:
            encoded += self._encode_integer(part)
        return bytes([len(encoded)]) + encoded

    def _encode_integer(self, value):
        """Helper method to encode integer for OID"""
        result = []
        while value:
            result.insert(0, value & 0x7f)
            value >>= 7
        result = [item | 0x80 for item in result[:-1]] + result[-1:]
        return bytes(result)

    def ssh_check_mech(self, desired_mech):
        """
        Check if the given OID is the Kerberos V5 OID (server mode).

        :param str desired_mech: The desired GSS-API mechanism of the client
        :return: ``True`` if the given OID is supported, otherwise C{False}
        """
        return desired_mech == self._krb5_mech

    def _make_uint32(self, integer):
        """
        Create a 32 bit unsigned integer (The byte sequence of an integer).

        :param int integer: The integer value to convert
        :return: The byte sequence of an 32 bit integer
        """
        return struct.pack('>I', integer)

    def _ssh_build_mic(self, session_id, username, service, auth_method):
        """
        Create the SSH2 MIC filed for gssapi-with-mic.

        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :param str service: The requested SSH service
        :param str auth_method: The requested SSH authentication mechanism
        :return: The MIC as defined in RFC 4462. The contents of the
                 MIC field are:
                 string    session_identifier,
                 byte      SSH_MSG_USERAUTH_REQUEST,
                 string    user-name,
                 string    service (ssh-connection),
                 string    authentication-method
                           (gssapi-with-mic or gssapi-keyex)
        """
        mic = self._make_uint32(len(session_id)) + session_id
        mic += struct.pack('B', MSG_USERAUTH_REQUEST)
        mic += self._make_uint32(len(username)) + username.encode('utf-8')
        mic += self._make_uint32(len(service)) + service.encode('utf-8')
        mic += self._make_uint32(len(auth_method)) + auth_method.encode('utf-8')
        return mic

class _SSH_GSSAPI_OLD(_SSH_GSSAuth):
    """
    Implementation of the GSS-API MIT Kerberos Authentication for SSH2,
    using the older (unmaintained) python-gssapi package.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)
        if self._gss_deleg_creds:
            self._gss_flags = (gssapi.C_PROT_READY_FLAG, gssapi.C_INTEG_FLAG, gssapi.C_MUTUAL_FLAG, gssapi.C_DELEG_FLAG)
        else:
            self._gss_flags = (gssapi.C_PROT_READY_FLAG, gssapi.C_INTEG_FLAG, gssapi.C_MUTUAL_FLAG)

    def ssh_init_sec_context(self, target, desired_mech=None, username=None, recv_token=None):
        """
        Initialize a GSS-API context.

        :param str username: The name of the user who attempts to login
        :param str target: The hostname of the target to connect to
        :param str desired_mech: The negotiated GSS-API mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param str recv_token: The GSS-API token received from the Server
        :raises:
            `.SSHException` -- Is raised if the desired mechanism of the client
            is not supported
        :return: A ``String`` if the GSS-API has returned a token or
            ``None`` if no token was returned
        """
        pass

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for GSS-API Key Exchange or not
        :return: gssapi-with-mic:
                 Returns the MIC token from GSS-API for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from GSS-API with the SSH session ID as
                 message.
        """
        pass

    def ssh_accept_sec_context(self, hostname, recv_token, username=None):
        """
        Accept a GSS-API context (server mode).

        :param str hostname: The servers hostname
        :param str username: The name of the user who attempts to login
        :param str recv_token: The GSS-API Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                if no token was returned
        """
        pass

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``gssapi.GSSException`` -- if the MIC check failed
        """
        pass

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        """
        pass

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentials if credentials are delegated
        (server mode).

        :param str client_token: The GSS-API token received form the client
        :raises:
            ``NotImplementedError`` -- Credential delegation is currently not
            supported in server mode
        """
        pass
if __version_info__ < (2, 5):
    _SSH_GSSAPI = _SSH_GSSAPI_OLD

class _SSH_GSSAPI_NEW(_SSH_GSSAuth):
    """
    Implementation of the GSS-API MIT Kerberos Authentication for SSH2,
    using the newer, currently maintained gssapi package.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)
        if self._gss_deleg_creds:
            self._gss_flags = (gssapi.RequirementFlag.protection_ready, gssapi.RequirementFlag.integrity, gssapi.RequirementFlag.mutual_authentication, gssapi.RequirementFlag.delegate_to_peer)
        else:
            self._gss_flags = (gssapi.RequirementFlag.protection_ready, gssapi.RequirementFlag.integrity, gssapi.RequirementFlag.mutual_authentication)

    def ssh_init_sec_context(self, target, desired_mech=None, username=None, recv_token=None):
        """
        Initialize a GSS-API context.

        :param str username: The name of the user who attempts to login
        :param str target: The hostname of the target to connect to
        :param str desired_mech: The negotiated GSS-API mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param str recv_token: The GSS-API token received from the Server
        :raises: `.SSHException` -- Is raised if the desired mechanism of the
                 client is not supported
        :raises: ``gssapi.exceptions.GSSError`` if there is an error signaled
                                                by the GSS-API implementation
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                 if no token was returned
        """
        pass

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for GSS-API Key Exchange or not
        :return: gssapi-with-mic:
                 Returns the MIC token from GSS-API for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from GSS-API with the SSH session ID as
                 message.
        :rtype: str
        """
        pass

    def ssh_accept_sec_context(self, hostname, recv_token, username=None):
        """
        Accept a GSS-API context (server mode).

        :param str hostname: The servers hostname
        :param str username: The name of the user who attempts to login
        :param str recv_token: The GSS-API Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                if no token was returned
        """
        pass

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``gssapi.exceptions.GSSError`` -- if the MIC check failed
        """
        pass

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        :rtype: bool
        """
        pass

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentials if credentials are delegated
        (server mode).

        :param str client_token: The GSS-API token received form the client
        :raises: ``NotImplementedError`` -- Credential delegation is currently
                 not supported in server mode
        """
        pass

class _SSH_SSPI(_SSH_GSSAuth):
    """
    Implementation of the Microsoft SSPI Kerberos Authentication for SSH2.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)
        if self._gss_deleg_creds:
            self._gss_flags = sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_MUTUAL_AUTH | sspicon.ISC_REQ_DELEGATE
        else:
            self._gss_flags = sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_MUTUAL_AUTH

    def ssh_init_sec_context(self, target, desired_mech=None, username=None, recv_token=None):
        """
        Initialize a SSPI context.

        :param str username: The name of the user who attempts to login
        :param str target: The FQDN of the target to connect to
        :param str desired_mech: The negotiated SSPI mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param recv_token: The SSPI token received from the Server
        :raises:
            `.SSHException` -- Is raised if the desired mechanism of the client
            is not supported
        :return: A ``String`` if the SSPI has returned a token or ``None`` if
                 no token was returned
        """
        pass

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for Key Exchange with SSPI or not
        :return: gssapi-with-mic:
                 Returns the MIC token from SSPI for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from SSPI with the SSH session ID as
                 message.
        """
        pass

    def ssh_accept_sec_context(self, hostname, username, recv_token):
        """
        Accept a SSPI context (server mode).

        :param str hostname: The servers FQDN
        :param str username: The name of the user who attempts to login
        :param str recv_token: The SSPI Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the SSPI has returned a token or ``None`` if
                 no token was returned
        """
        pass

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``sspi.error`` -- if the MIC check failed
        """
        pass

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        """
        pass

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentails if credentials are delegated
        (server mode).

        :param str client_token: The SSPI token received form the client
        :raises:
            ``NotImplementedError`` -- Credential delegation is currently not
            supported in server mode
        """
        pass
