"""
Core protocol implementation
"""
import os
import socket
import sys
import threading
import time
import weakref
from hashlib import md5, sha1, sha256, sha512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import paramiko
from paramiko import util
from paramiko.auth_handler import AuthHandler, AuthOnlyHandler
from paramiko.ssh_gss import GSSAuth
from paramiko.channel import Channel
from paramiko.common import xffffffff, cMSG_CHANNEL_OPEN, cMSG_IGNORE, cMSG_GLOBAL_REQUEST, DEBUG, MSG_KEXINIT, MSG_IGNORE, MSG_DISCONNECT, MSG_DEBUG, ERROR, WARNING, cMSG_UNIMPLEMENTED, INFO, cMSG_KEXINIT, cMSG_NEWKEYS, MSG_NEWKEYS, cMSG_REQUEST_SUCCESS, cMSG_REQUEST_FAILURE, CONNECTION_FAILED_CODE, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED, cMSG_CHANNEL_OPEN_FAILURE, cMSG_CHANNEL_OPEN_SUCCESS, MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE, cMSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, MSG_CHANNEL_OPEN_SUCCESS, MSG_CHANNEL_OPEN_FAILURE, MSG_CHANNEL_OPEN, MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA, MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_REQUEST, MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MIN_WINDOW_SIZE, MIN_PACKET_SIZE, MAX_WINDOW_SIZE, DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE, HIGHEST_USERAUTH_MESSAGE_ID, MSG_UNIMPLEMENTED, MSG_NAMES, MSG_EXT_INFO, cMSG_EXT_INFO, byte_ord
from paramiko.compress import ZlibCompressor, ZlibDecompressor
from paramiko.dsskey import DSSKey
from paramiko.ed25519key import Ed25519Key
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.kex_gex import KexGex, KexGexSHA256
from paramiko.kex_group1 import KexGroup1
from paramiko.kex_group14 import KexGroup14, KexGroup14SHA256
from paramiko.kex_group16 import KexGroup16SHA512
from paramiko.kex_ecdh_nist import KexNistp256, KexNistp384, KexNistp521
from paramiko.kex_gss import KexGSSGex, KexGSSGroup1, KexGSSGroup14
from paramiko.message import Message
from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.primes import ModulusPack
from paramiko.rsakey import RSAKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.server import ServerInterface
from paramiko.sftp_client import SFTPClient
from paramiko.ssh_exception import BadAuthenticationType, ChannelException, IncompatiblePeer, MessageOrderError, ProxyCommandFailure, SSHException
from paramiko.util import ClosingContextManager, clamp_value, b
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
_active_threads = []
import atexit
atexit.register(_join_lingering_threads)

class Transport(threading.Thread, ClosingContextManager):
    """
    An SSH Transport attaches to a stream (usually a socket), negotiates an
    encrypted session, authenticates, and then creates stream tunnels, called
    `channels <.Channel>`, across the session.  Multiple channels can be
    multiplexed across a single session (and often are, in the case of port
    forwardings).

    Instances of this class may be used as context managers.
    """
    _ENCRYPT = object()
    _DECRYPT = object()
    _PROTO_ID = '2.0'
    _CLIENT_ID = 'paramiko_{}'.format(paramiko.__version__)
    _preferred_ciphers = ('aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc')
    _preferred_macs = ('hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96')
    _preferred_keys = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss')
    _preferred_pubkeys = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss')
    _preferred_kex = ('ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group16-sha512', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1')
    if KexCurve25519.is_available():
        _preferred_kex = ('curve25519-sha256@libssh.org',) + _preferred_kex
    _preferred_gsskex = ('gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==', 'gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==', 'gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==')
    _preferred_compression = ('none',)
    _cipher_info = {'aes128-ctr': {'class': algorithms.AES, 'mode': modes.CTR, 'block-size': 16, 'key-size': 16}, 'aes192-ctr': {'class': algorithms.AES, 'mode': modes.CTR, 'block-size': 16, 'key-size': 24}, 'aes256-ctr': {'class': algorithms.AES, 'mode': modes.CTR, 'block-size': 16, 'key-size': 32}, 'aes128-cbc': {'class': algorithms.AES, 'mode': modes.CBC, 'block-size': 16, 'key-size': 16}, 'aes192-cbc': {'class': algorithms.AES, 'mode': modes.CBC, 'block-size': 16, 'key-size': 24}, 'aes256-cbc': {'class': algorithms.AES, 'mode': modes.CBC, 'block-size': 16, 'key-size': 32}, '3des-cbc': {'class': TripleDES, 'mode': modes.CBC, 'block-size': 8, 'key-size': 24}}
    _mac_info = {'hmac-sha1': {'class': sha1, 'size': 20}, 'hmac-sha1-96': {'class': sha1, 'size': 12}, 'hmac-sha2-256': {'class': sha256, 'size': 32}, 'hmac-sha2-256-etm@openssh.com': {'class': sha256, 'size': 32}, 'hmac-sha2-512': {'class': sha512, 'size': 64}, 'hmac-sha2-512-etm@openssh.com': {'class': sha512, 'size': 64}, 'hmac-md5': {'class': md5, 'size': 16}, 'hmac-md5-96': {'class': md5, 'size': 12}}
    _key_info = {'ssh-rsa': RSAKey, 'ssh-rsa-cert-v01@openssh.com': RSAKey, 'rsa-sha2-256': RSAKey, 'rsa-sha2-256-cert-v01@openssh.com': RSAKey, 'rsa-sha2-512': RSAKey, 'rsa-sha2-512-cert-v01@openssh.com': RSAKey, 'ssh-dss': DSSKey, 'ssh-dss-cert-v01@openssh.com': DSSKey, 'ecdsa-sha2-nistp256': ECDSAKey, 'ecdsa-sha2-nistp256-cert-v01@openssh.com': ECDSAKey, 'ecdsa-sha2-nistp384': ECDSAKey, 'ecdsa-sha2-nistp384-cert-v01@openssh.com': ECDSAKey, 'ecdsa-sha2-nistp521': ECDSAKey, 'ecdsa-sha2-nistp521-cert-v01@openssh.com': ECDSAKey, 'ssh-ed25519': Ed25519Key, 'ssh-ed25519-cert-v01@openssh.com': Ed25519Key}
    _kex_info = {'diffie-hellman-group1-sha1': KexGroup1, 'diffie-hellman-group14-sha1': KexGroup14, 'diffie-hellman-group-exchange-sha1': KexGex, 'diffie-hellman-group-exchange-sha256': KexGexSHA256, 'diffie-hellman-group14-sha256': KexGroup14SHA256, 'diffie-hellman-group16-sha512': KexGroup16SHA512, 'gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==': KexGSSGroup1, 'gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==': KexGSSGroup14, 'gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==': KexGSSGex, 'ecdh-sha2-nistp256': KexNistp256, 'ecdh-sha2-nistp384': KexNistp384, 'ecdh-sha2-nistp521': KexNistp521}
    if KexCurve25519.is_available():
        _kex_info['curve25519-sha256@libssh.org'] = KexCurve25519
    _compression_info = {'zlib@openssh.com': (ZlibCompressor, ZlibDecompressor), 'zlib': (ZlibCompressor, ZlibDecompressor), 'none': (None, None)}
    _modulus_pack = None
    _active_check_timeout = 0.1

    def __init__(self, sock, default_window_size=DEFAULT_WINDOW_SIZE, default_max_packet_size=DEFAULT_MAX_PACKET_SIZE, gss_kex=False, gss_deleg_creds=True, disabled_algorithms=None, server_sig_algs=True, strict_kex=True, packetizer_class=None):
        """
        Create a new SSH session over an existing socket, or socket-like
        object.  This only creates the `.Transport` object; it doesn't begin
        the SSH session yet.  Use `connect` or `start_client` to begin a client
        session, or `start_server` to begin a server session.

        If the object is not actually a socket, it must have the following
        methods:

        - ``send(bytes)``: Writes from 1 to ``len(bytes)`` bytes, and returns
          an int representing the number of bytes written.  Returns
          0 or raises ``EOFError`` if the stream has been closed.
        - ``recv(int)``: Reads from 1 to ``int`` bytes and returns them as a
          string.  Returns 0 or raises ``EOFError`` if the stream has been
          closed.
        - ``close()``: Closes the socket.
        - ``settimeout(n)``: Sets a (float) timeout on I/O operations.

        For ease of use, you may also pass in an address (as a tuple) or a host
        string as the ``sock`` argument.  (A host string is a hostname with an
        optional port (separated by ``":"``) which will be converted into a
        tuple of ``(hostname, port)``.)  A socket will be connected to this
        address and used for communication.  Exceptions from the ``socket``
        call may be thrown in this case.

        .. note::
            Modifying the the window and packet sizes might have adverse
            effects on your channels created from this transport. The default
            values are the same as in the OpenSSH code base and have been
            battle tested.

        :param socket sock:
            a socket or socket-like object to create the session over.
        :param int default_window_size:
            sets the default window size on the transport. (defaults to
            2097152)
        :param int default_max_packet_size:
            sets the default max packet size on the transport. (defaults to
            32768)
        :param bool gss_kex:
            Whether to enable GSSAPI key exchange when GSSAPI is in play.
            Default: ``False``.
        :param bool gss_deleg_creds:
            Whether to enable GSSAPI credential delegation when GSSAPI is in
            play. Default: ``True``.
        :param dict disabled_algorithms:
            If given, must be a dictionary mapping algorithm type to an
            iterable of algorithm identifiers, which will be disabled for the
            lifetime of the transport.

            Keys should match the last word in the class' builtin algorithm
            tuple attributes, such as ``"ciphers"`` to disable names within
            ``_preferred_ciphers``; or ``"kex"`` to disable something defined
            inside ``_preferred_kex``. Values should exactly match members of
            the matching attribute.

            For example, if you need to disable
            ``diffie-hellman-group16-sha512`` key exchange (perhaps because
            your code talks to a server which implements it differently from
            Paramiko), specify ``disabled_algorithms={"kex":
            ["diffie-hellman-group16-sha512"]}``.
        :param bool server_sig_algs:
            Whether to send an extra message to compatible clients, in server
            mode, with a list of supported pubkey algorithms. Default:
            ``True``.
        :param bool strict_kex:
            Whether to advertise (and implement, if client also advertises
            support for) a "strict kex" mode for safer handshaking. Default:
            ``True``.
        :param packetizer_class:
            Which class to use for instantiating the internal packet handler.
            Default: ``None`` (i.e.: use `Packetizer` as normal).

        .. versionchanged:: 1.15
            Added the ``default_window_size`` and ``default_max_packet_size``
            arguments.
        .. versionchanged:: 1.15
            Added the ``gss_kex`` and ``gss_deleg_creds`` kwargs.
        .. versionchanged:: 2.6
            Added the ``disabled_algorithms`` kwarg.
        .. versionchanged:: 2.9
            Added the ``server_sig_algs`` kwarg.
        .. versionchanged:: 3.4
            Added the ``strict_kex`` kwarg.
        .. versionchanged:: 3.4
            Added the ``packetizer_class`` kwarg.
        """
        self.active = False
        self.hostname = None
        self.server_extensions = {}
        self.advertise_strict_kex = strict_kex
        self.agreed_on_strict_kex = False
        if isinstance(sock, str):
            hl = sock.split(':', 1)
            self.hostname = hl[0]
            if len(hl) == 1:
                sock = (hl[0], 22)
            else:
                sock = (hl[0], int(hl[1]))
        if type(sock) is tuple:
            hostname, port = sock
            self.hostname = hostname
            reason = 'No suitable address family'
            addrinfos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, socktype, proto, canonname, sockaddr in addrinfos:
                if socktype == socket.SOCK_STREAM:
                    af = family
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    try:
                        sock.connect((hostname, port))
                    except socket.error as e:
                        reason = str(e)
                    else:
                        break
            else:
                raise SSHException('Unable to connect to {}: {}'.format(hostname, reason))
        threading.Thread.__init__(self)
        self.daemon = True
        self.sock = sock
        self.sock.settimeout(self._active_check_timeout)
        self.packetizer = (packetizer_class or Packetizer)(sock)
        self.local_version = 'SSH-' + self._PROTO_ID + '-' + self._CLIENT_ID
        self.remote_version = ''
        self.local_cipher = self.remote_cipher = ''
        self.local_kex_init = self.remote_kex_init = None
        self.local_mac = self.remote_mac = None
        self.local_compression = self.remote_compression = None
        self.session_id = None
        self.host_key_type = None
        self.host_key = None
        self.use_gss_kex = gss_kex
        self.gss_kex_used = False
        self.kexgss_ctxt = None
        self.gss_host = None
        if self.use_gss_kex:
            self.kexgss_ctxt = GSSAuth('gssapi-keyex', gss_deleg_creds)
            self._preferred_kex = self._preferred_gsskex + self._preferred_kex
        self.kex_engine = None
        self.H = None
        self.K = None
        self.initial_kex_done = False
        self.in_kex = False
        self.authenticated = False
        self._expected_packet = tuple()
        self.lock = threading.Lock()
        self._channels = ChannelMap()
        self.channel_events = {}
        self.channels_seen = {}
        self._channel_counter = 0
        self.default_max_packet_size = default_max_packet_size
        self.default_window_size = default_window_size
        self._forward_agent_handler = None
        self._x11_handler = None
        self._tcp_handler = None
        self.saved_exception = None
        self.clear_to_send = threading.Event()
        self.clear_to_send_lock = threading.Lock()
        self.clear_to_send_timeout = 30.0
        self.log_name = 'paramiko.transport'
        self.logger = util.get_logger(self.log_name)
        self.packetizer.set_log(self.logger)
        self.auth_handler = None
        self.global_response = None
        self.completion_event = None
        self.banner_timeout = 15
        self.handshake_timeout = 15
        self.auth_timeout = 30
        self.channel_timeout = 60 * 60
        self.disabled_algorithms = disabled_algorithms or {}
        self.server_sig_algs = server_sig_algs
        self.server_mode = False
        self.server_object = None
        self.server_key_dict = {}
        self.server_accepts = []
        self.server_accept_cv = threading.Condition(self.lock)
        self.subsystem_table = {}
        self._handler_table = {MSG_EXT_INFO: self._parse_ext_info, MSG_NEWKEYS: self._parse_newkeys, MSG_GLOBAL_REQUEST: self._parse_global_request, MSG_REQUEST_SUCCESS: self._parse_request_success, MSG_REQUEST_FAILURE: self._parse_request_failure, MSG_CHANNEL_OPEN_SUCCESS: self._parse_channel_open_success, MSG_CHANNEL_OPEN_FAILURE: self._parse_channel_open_failure, MSG_CHANNEL_OPEN: self._parse_channel_open, MSG_KEXINIT: self._negotiate_keys}

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.
        """
        id_ = hex(id(self) & xffffffff)
        out = '<paramiko.Transport at {}'.format(id_)
        if not self.active:
            out += ' (unconnected)'
        else:
            if self.local_cipher != '':
                out += ' (cipher {}, {:d} bits)'.format(self.local_cipher, self._cipher_info[self.local_cipher]['key-size'] * 8)
            if self.is_authenticated():
                out += ' (active; {} open channel(s))'.format(len(self._channels))
            elif self.initial_kex_done:
                out += ' (connected; awaiting auth)'
            else:
                out += ' (connecting)'
        out += '>'
        return out

    def atfork(self):
        """
        Terminate this Transport without closing the session.  On posix
        systems, if a Transport is open during process forking, both parent
        and child will share the underlying socket, but only one process can
        use the connection (without corrupting the session).  Use this method
        to clean up a Transport object without disrupting the other process.

        .. versionadded:: 1.5.3
        """
        self.close()
        self.sock = None
        self.packetizer = None

    def get_security_options(self):
        """
        Return a `.SecurityOptions` object which can be used to tweak the
        encryption algorithms this transport will permit (for encryption,
        digest/hash operations, public keys, and key exchanges) and the order
        of preference for them.
        """
        return SecurityOptions(self)

    def set_gss_host(self, gss_host, trust_dns=True, gssapi_requested=True):
        """
        Normalize/canonicalize ``self.gss_host`` depending on various factors.

        :param str gss_host:
            The explicitly requested GSS-oriented hostname to connect to (i.e.
            what the host's name is in the Kerberos database.) Defaults to
            ``self.hostname`` (which will be the 'real' target hostname and/or
            host portion of given socket object.)
        :param bool trust_dns:
            Indicates whether or not DNS is trusted; if true, DNS will be used
            to canonicalize the GSS hostname (which again will either be
            ``gss_host`` or the transport's default hostname.)
            (Defaults to True due to backwards compatibility.)
        :param bool gssapi_requested:
            Whether GSSAPI key exchange or authentication was even requested.
            If not, this is a no-op and nothing happens
            (and ``self.gss_host`` is not set.)
            (Defaults to True due to backwards compatibility.)
        :returns: ``None``.
        """
        if not gssapi_requested:
            return

        if gss_host is None:
            gss_host = self.hostname

        if trust_dns:
            from socket import gaierror
            try:
                gss_host = socket.getfqdn(gss_host)
            except gaierror:
                # Can't resolve it, use it as-is
                pass

        self.gss_host = gss_host

    def start_client(self, event=None, timeout=None):
        """
        Negotiate a new SSH2 session as a client.  This is the first step after
        creating a new `.Transport`.  A separate thread is created for protocol
        negotiation.

        If an event is passed in, this method returns immediately.  When
        negotiation is done (successful or not), the given ``Event`` will
        be triggered.  On failure, `is_active` will return ``False``.

        (Since 1.4) If ``event`` is ``None``, this method will not return until
        negotiation is done.  On success, the method returns normally.
        Otherwise an SSHException is raised.

        After a successful negotiation, you will usually want to authenticate,
        calling `auth_password <Transport.auth_password>` or
        `auth_publickey <Transport.auth_publickey>`.

        .. note:: `connect` is a simpler method for connecting as a client.

        .. note::
            After calling this method (or `start_server` or `connect`), you
            should no longer directly read from or write to the original socket
            object.

        :param .threading.Event event:
            an event to trigger when negotiation is complete (optional)

        :param float timeout:
            a timeout, in seconds, for SSH2 session negotiation (optional)

        :raises:
            `.SSHException` -- if negotiation fails (and no ``event`` was
            passed in)
        """
        self.active = True
        if event is not None:
            self.completion_event = event
        self.packetizer.set_log(lambda x: self._log(DEBUG, 'Packetizer: ' + x))
        self.kex_engine.set_log(lambda x: self._log(DEBUG, 'Kex: ' + x))
        
        if timeout is not None:
            self.packetizer.start_handshake(timeout)
        
        self._send_kex_init()
        self.kex_engine.parse_next(MSG_KEXINIT)
        
        if self.completion_event is not None:
            self.completion_event.wait()
            if not self.active:
                raise SSHException('Negotiation failed.')
        else:
            while True:
                if not self.active:
                    raise SSHException('Negotiation failed.')
                if self.initial_kex_done:
                    break
                if timeout is not None and self.packetizer.handshake_timed_out():
                    raise SSHException('Timeout waiting for handshake')
                self.kex_engine.parse_next()
                time.sleep(0.1)
        
        self.packetizer.complete_handshake()

    def start_server(self, event=None, server=None):
        """
        Negotiate a new SSH2 session as a server.  This is the first step after
        creating a new `.Transport` and setting up your server host key(s).  A
        separate thread is created for protocol negotiation.

        If an event is passed in, this method returns immediately.  When
        negotiation is done (successful or not), the given ``Event`` will
        be triggered.  On failure, `is_active` will return ``False``.

        (Since 1.4) If ``event`` is ``None``, this method will not return until
        negotiation is done.  On success, the method returns normally.
        Otherwise an SSHException is raised.

        After a successful negotiation, the client will need to authenticate.
        Override the methods `get_allowed_auths
        <.ServerInterface.get_allowed_auths>`, `check_auth_none
        <.ServerInterface.check_auth_none>`, `check_auth_password
        <.ServerInterface.check_auth_password>`, and `check_auth_publickey
        <.ServerInterface.check_auth_publickey>` in the given ``server`` object
        to control the authentication process.

        After a successful authentication, the client should request to open a
        channel.  Override `check_channel_request
        <.ServerInterface.check_channel_request>` in the given ``server``
        object to allow channels to be opened.

        .. note::
            After calling this method (or `start_client` or `connect`), you
            should no longer directly read from or write to the original socket
            object.

        :param .threading.Event event:
            an event to trigger when negotiation is complete.
        :param .ServerInterface server:
            an object used to perform authentication and create `channels
            <.Channel>`

        :raises:
            `.SSHException` -- if negotiation fails (and no ``event`` was
            passed in)
        """
        pass

    def add_server_key(self, key):
        """
        Add a host key to the list of keys used for server mode.  When behaving
        as a server, the host key is used to sign certain packets during the
        SSH2 negotiation, so that the client can trust that we are who we say
        we are.  Because this is used for signing, the key must contain private
        key info, not just the public half.  Only one key of each type (RSA or
        DSS) is kept.

        :param .PKey key:
            the host key to add, usually an `.RSAKey` or `.DSSKey`.
        """
        pass

    def get_server_key(self):
        """
        Return the active host key, in server mode.  After negotiating with the
        client, this method will return the negotiated host key.  If only one
        type of host key was set with `add_server_key`, that's the only key
        that will ever be returned.  But in cases where you have set more than
        one type of host key (for example, an RSA key and a DSS key), the key
        type will be negotiated by the client, and this method will return the
        key of the type agreed on.  If the host key has not been negotiated
        yet, ``None`` is returned.  In client mode, the behavior is undefined.

        :return:
            host key (`.PKey`) of the type negotiated by the client, or
            ``None``.
        """
        pass

    @staticmethod
    def load_server_moduli(filename=None):
        """
        (optional)
        Load a file of prime moduli for use in doing group-exchange key
        negotiation in server mode.  It's a rather obscure option and can be
        safely ignored.

        In server mode, the remote client may request "group-exchange" key
        negotiation, which asks the server to send a random prime number that
        fits certain criteria.  These primes are pretty difficult to compute,
        so they can't be generated on demand.  But many systems contain a file
        of suitable primes (usually named something like ``/etc/ssh/moduli``).
        If you call `load_server_moduli` and it returns ``True``, then this
        file of primes has been loaded and we will support "group-exchange" in
        server mode.  Otherwise server mode will just claim that it doesn't
        support that method of key negotiation.

        :param str filename:
            optional path to the moduli file, if you happen to know that it's
            not in a standard location.
        :return:
            True if a moduli file was successfully loaded; False otherwise.

        .. note:: This has no effect when used in client mode.
        """
        pass

    def close(self):
        """
        Close this session, and any open channels that are tied to it.
        """
        pass

    def get_remote_server_key(self):
        """
        Return the host key of the server (in client mode).

        .. note::
            Previously this call returned a tuple of ``(key type, key
            string)``. You can get the same effect by calling `.PKey.get_name`
            for the key type, and ``str(key)`` for the key string.

        :raises: `.SSHException` -- if no session is currently active.

        :return: public key (`.PKey`) of the remote server
        """
        pass

    def is_active(self):
        """
        Return true if this session is active (open).

        :return:
            True if the session is still active (open); False if the session is
            closed
        """
        pass

    def open_session(self, window_size=None, max_packet_size=None, timeout=None):
        """
        Request a new channel to the server, of type ``"session"``.  This is
        just an alias for calling `open_channel` with an argument of
        ``"session"``.

        .. note:: Modifying the the window and packet sizes might have adverse
            effects on the session created. The default values are the same
            as in the OpenSSH code base and have been battle tested.

        :param int window_size:
            optional window size for this session.
        :param int max_packet_size:
            optional max packet size for this session.

        :return: a new `.Channel`

        :raises:
            `.SSHException` -- if the request is rejected or the session ends
            prematurely

        .. versionchanged:: 1.13.4/1.14.3/1.15.3
            Added the ``timeout`` argument.
        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        pass

    def open_x11_channel(self, src_addr=None):
        """
        Request a new channel to the client, of type ``"x11"``.  This
        is just an alias for ``open_channel('x11', src_addr=src_addr)``.

        :param tuple src_addr:
            the source address (``(str, int)``) of the x11 server (port is the
            x11 port, ie. 6010)
        :return: a new `.Channel`

        :raises:
            `.SSHException` -- if the request is rejected or the session ends
            prematurely
        """
        pass

    def open_forward_agent_channel(self):
        """
        Request a new channel to the client, of type
        ``"auth-agent@openssh.com"``.

        This is just an alias for ``open_channel('auth-agent@openssh.com')``.

        :return: a new `.Channel`

        :raises: `.SSHException` --
            if the request is rejected or the session ends prematurely
        """
        pass

    def open_forwarded_tcpip_channel(self, src_addr, dest_addr):
        """
        Request a new channel back to the client, of type ``forwarded-tcpip``.

        This is used after a client has requested port forwarding, for sending
        incoming connections back to the client.

        :param src_addr: originator's address
        :param dest_addr: local (server) connected address
        """
        pass

    def open_channel(self, kind, dest_addr=None, src_addr=None, window_size=None, max_packet_size=None, timeout=None):
        """
        Request a new channel to the server. `Channels <.Channel>` are
        socket-like objects used for the actual transfer of data across the
        session. You may only request a channel after negotiating encryption
        (using `connect` or `start_client`) and authenticating.

        .. note:: Modifying the the window and packet sizes might have adverse
            effects on the channel created. The default values are the same
            as in the OpenSSH code base and have been battle tested.

        :param str kind:
            the kind of channel requested (usually ``"session"``,
            ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``)
        :param tuple dest_addr:
            the destination address (address + port tuple) of this port
            forwarding, if ``kind`` is ``"forwarded-tcpip"`` or
            ``"direct-tcpip"`` (ignored for other channel types)
        :param src_addr: the source address of this port forwarding, if
            ``kind`` is ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``
        :param int window_size:
            optional window size for this session.
        :param int max_packet_size:
            optional max packet size for this session.
        :param float timeout:
            optional timeout opening a channel, default 3600s (1h)

        :return: a new `.Channel` on success

        :raises:
            `.SSHException` -- if the request is rejected, the session ends
            prematurely or there is a timeout opening a channel

        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        pass

    def request_port_forward(self, address, port, handler=None):
        """
        Ask the server to forward TCP connections from a listening port on
        the server, across this SSH session.

        If a handler is given, that handler is called from a different thread
        whenever a forwarded connection arrives.  The handler parameters are::

            handler(
                channel,
                (origin_addr, origin_port),
                (server_addr, server_port),
            )

        where ``server_addr`` and ``server_port`` are the address and port that
        the server was listening on.

        If no handler is set, the default behavior is to send new incoming
        forwarded connections into the accept queue, to be picked up via
        `accept`.

        :param str address: the address to bind when forwarding
        :param int port:
            the port to forward, or 0 to ask the server to allocate any port
        :param callable handler:
            optional handler for incoming forwarded connections, of the form
            ``func(Channel, (str, int), (str, int))``.

        :return: the port number (`int`) allocated by the server

        :raises:
            `.SSHException` -- if the server refused the TCP forward request
        """
        pass

    def cancel_port_forward(self, address, port):
        """
        Ask the server to cancel a previous port-forwarding request.  No more
        connections to the given address & port will be forwarded across this
        ssh connection.

        :param str address: the address to stop forwarding
        :param int port: the port to stop forwarding
        """
        pass

    def open_sftp_client(self):
        """
        Create an SFTP client channel from an open transport.  On success, an
        SFTP session will be opened with the remote host, and a new
        `.SFTPClient` object will be returned.

        :return:
            a new `.SFTPClient` referring to an sftp session (channel) across
            this transport
        """
        pass

    def send_ignore(self, byte_count=None):
        """
        Send a junk packet across the encrypted link.  This is sometimes used
        to add "noise" to a connection to confuse would-be attackers.  It can
        also be used as a keep-alive for long lived connections traversing
        firewalls.

        :param int byte_count:
            the number of random bytes to send in the payload of the ignored
            packet -- defaults to a random number from 10 to 41.
        """
        pass

    def renegotiate_keys(self):
        """
        Force this session to switch to new keys.  Normally this is done
        automatically after the session hits a certain number of packets or
        bytes sent or received, but this method gives you the option of forcing
        new keys whenever you want.  Negotiating new keys causes a pause in
        traffic both ways as the two sides swap keys and do computations.  This
        method returns when the session has switched to new keys.

        :raises:
            `.SSHException` -- if the key renegotiation failed (which causes
            the session to end)
        """
        pass

    def set_keepalive(self, interval):
        """
        Turn on/off keepalive packets (default is off).  If this is set, after
        ``interval`` seconds without sending any data over the connection, a
        "keepalive" packet will be sent (and ignored by the remote host).  This
        can be useful to keep connections alive over a NAT, for example.

        :param int interval:
            seconds to wait before sending a keepalive packet (or
            0 to disable keepalives).
        """
        pass

    def global_request(self, kind, data=None, wait=True):
        """
        Make a global request to the remote host.  These are normally
        extensions to the SSH2 protocol.

        :param str kind: name of the request.
        :param tuple data:
            an optional tuple containing additional data to attach to the
            request.
        :param bool wait:
            ``True`` if this method should not return until a response is
            received; ``False`` otherwise.
        :return:
            a `.Message` containing possible additional data if the request was
            successful (or an empty `.Message` if ``wait`` was ``False``);
            ``None`` if the request was denied.
        """
        pass

    def accept(self, timeout=None):
        """
        Return the next channel opened by the client over this transport, in
        server mode.  If no channel is opened before the given timeout,
        ``None`` is returned.

        :param int timeout:
            seconds to wait for a channel, or ``None`` to wait forever
        :return: a new `.Channel` opened by the client
        """
        pass

    def connect(self, hostkey=None, username='', password=None, pkey=None, gss_host=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_trust_dns=True):
        """
        Negotiate an SSH2 session, and optionally verify the server's host key
        and authenticate using a password or private key.  This is a shortcut
        for `start_client`, `get_remote_server_key`, and
        `Transport.auth_password` or `Transport.auth_publickey`.  Use those
        methods if you want more control.

        You can use this method immediately after creating a Transport to
        negotiate encryption with a server.  If it fails, an exception will be
        thrown.  On success, the method will return cleanly, and an encrypted
        session exists.  You may immediately call `open_channel` or
        `open_session` to get a `.Channel` object, which is used for data
        transfer.

        .. note::
            If you fail to supply a password or private key, this method may
            succeed, but a subsequent `open_channel` or `open_session` call may
            fail because you haven't authenticated yet.

        :param .PKey hostkey:
            the host key expected from the server, or ``None`` if you don't
            want to do host key verification.
        :param str username: the username to authenticate as.
        :param str password:
            a password to use for authentication, if you want to use password
            authentication; otherwise ``None``.
        :param .PKey pkey:
            a private key to use for authentication, if you want to use private
            key authentication; otherwise ``None``.
        :param str gss_host:
            The target's name in the kerberos database. Default: hostname
        :param bool gss_auth:
            ``True`` if you want to use GSS-API authentication.
        :param bool gss_kex:
            Perform GSS-API Key Exchange and user authentication.
        :param bool gss_deleg_creds:
            Whether to delegate GSS-API client credentials.
        :param gss_trust_dns:
            Indicates whether or not the DNS is trusted to securely
            canonicalize the name of the host being connected to (default
            ``True``).

        :raises: `.SSHException` -- if the SSH2 negotiation fails, the host key
            supplied by the server is incorrect, or authentication fails.

        .. versionchanged:: 2.3
            Added the ``gss_trust_dns`` argument.
        """
        pass

    def get_exception(self):
        """
        Return any exception that happened during the last server request.
        This can be used to fetch more specific error information after using
        calls like `start_client`.  The exception (if any) is cleared after
        this call.

        :return:
            an exception, or ``None`` if there is no stored exception.

        .. versionadded:: 1.1
        """
        pass

    def set_subsystem_handler(self, name, handler, *args, **kwargs):
        """
        Set the handler class for a subsystem in server mode.  If a request
        for this subsystem is made on an open ssh channel later, this handler
        will be constructed and called -- see `.SubsystemHandler` for more
        detailed documentation.

        Any extra parameters (including keyword arguments) are saved and
        passed to the `.SubsystemHandler` constructor later.

        :param str name: name of the subsystem.
        :param handler:
            subclass of `.SubsystemHandler` that handles this subsystem.
        """
        pass

    def is_authenticated(self):
        """
        Return true if this session is active and authenticated.

        :return:
            True if the session is still open and has been authenticated
            successfully; False if authentication failed and/or the session is
            closed.
        """
        pass

    def get_username(self):
        """
        Return the username this connection is authenticated for.  If the
        session is not authenticated (or authentication failed), this method
        returns ``None``.

        :return: username that was authenticated (a `str`), or ``None``.
        """
        pass

    def get_banner(self):
        """
        Return the banner supplied by the server upon connect. If no banner is
        supplied, this method returns ``None``.

        :returns: server supplied banner (`str`), or ``None``.

        .. versionadded:: 1.13
        """
        pass

    def auth_none(self, username):
        """
        Try to authenticate to the server using no authentication at all.
        This will almost always fail.  It may be useful for determining the
        list of authentication types supported by the server, by catching the
        `.BadAuthenticationType` exception raised.

        :param str username: the username to authenticate as
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if "none" authentication isn't allowed
            by the server for this user
        :raises:
            `.SSHException` -- if the authentication failed due to a network
            error

        .. versionadded:: 1.5
        """
        pass

    def auth_password(self, username, password, event=None, fallback=True):
        """
        Authenticate to the server using a password.  The username and password
        are sent over an encrypted link.

        If an ``event`` is passed in, this method will return immediately, and
        the event will be triggered once authentication succeeds or fails.  On
        success, `is_authenticated` will return ``True``.  On failure, you may
        use `get_exception` to get more detailed error information.

        Since 1.1, if no event is passed, this method will block until the
        authentication succeeds or fails.  On failure, an exception is raised.
        Otherwise, the method simply returns.

        Since 1.5, if no event is passed and ``fallback`` is ``True`` (the
        default), if the server doesn't support plain password authentication
        but does support so-called "keyboard-interactive" mode, an attempt
        will be made to authenticate using this interactive mode.  If it fails,
        the normal exception will be thrown as if the attempt had never been
        made.  This is useful for some recent Gentoo and Debian distributions,
        which turn off plain password authentication in a misguided belief
        that interactive authentication is "more secure".  (It's not.)

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param basestring password: the password to authenticate with
        :param .threading.Event event:
            an event to trigger when the authentication attempt is complete
            (whether it was successful or not)
        :param bool fallback:
            ``True`` if an attempt at an automated "interactive" password auth
            should be made if the server doesn't support normal password auth
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if password authentication isn't
            allowed by the server for this user (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        pass

    def auth_publickey(self, username, key, event=None):
        """
        Authenticate to the server using a private key.  The key is used to
        sign data from the server, so it must include the private part.

        If an ``event`` is passed in, this method will return immediately, and
        the event will be triggered once authentication succeeds or fails.  On
        success, `is_authenticated` will return ``True``.  On failure, you may
        use `get_exception` to get more detailed error information.

        Since 1.1, if no event is passed, this method will block until the
        authentication succeeds or fails.  On failure, an exception is raised.
        Otherwise, the method simply returns.

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param .PKey key: the private key to authenticate with
        :param .threading.Event event:
            an event to trigger when the authentication attempt is complete
            (whether it was successful or not)
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if public-key authentication isn't
            allowed by the server for this user (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        pass

    def auth_interactive(self, username, handler, submethods=''):
        """
        Authenticate to the server interactively.  A handler is used to answer
        arbitrary questions from the server.  On many servers, this is just a
        dumb wrapper around PAM.

        This method will block until the authentication succeeds or fails,
        periodically calling the handler asynchronously to get answers to
        authentication questions.  The handler may be called more than once
        if the server continues to ask questions.

        The handler is expected to be a callable that will handle calls of the
        form: ``handler(title, instructions, prompt_list)``.  The ``title`` is
        meant to be a dialog-window title, and the ``instructions`` are user
        instructions (both are strings).  ``prompt_list`` will be a list of
        prompts, each prompt being a tuple of ``(str, bool)``.  The string is
        the prompt and the boolean indicates whether the user text should be
        echoed.

        A sample call would thus be:
        ``handler('title', 'instructions', [('Password:', False)])``.

        The handler should return a list or tuple of answers to the server's
        questions.

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param callable handler: a handler for responding to server questions
        :param str submethods: a string list of desired submethods (optional)
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty).

        :raises: `.BadAuthenticationType` -- if public-key authentication isn't
            allowed by the server for this user
        :raises: `.AuthenticationException` -- if the authentication failed
        :raises: `.SSHException` -- if there was a network error

        .. versionadded:: 1.5
        """
        pass

    def auth_interactive_dumb(self, username, handler=None, submethods=''):
        """
        Authenticate to the server interactively but dumber.
        Just print the prompt and / or instructions to stdout and send back
        the response. This is good for situations where partial auth is
        achieved by key and then the user has to enter a 2fac token.
        """
        pass

    def auth_gssapi_with_mic(self, username, gss_host, gss_deleg_creds):
        """
        Authenticate to the Server using GSS-API / SSPI.

        :param str username: The username to authenticate as
        :param str gss_host: The target host
        :param bool gss_deleg_creds: Delegate credentials or not
        :return: list of auth types permissible for the next stage of
                 authentication (normally empty)
        :raises: `.BadAuthenticationType` -- if gssapi-with-mic isn't
            allowed by the server (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        pass

    def auth_gssapi_keyex(self, username):
        """
        Authenticate to the server with GSS-API/SSPI if GSS-API kex is in use.

        :param str username: The username to authenticate as.
        :returns:
            a list of auth types permissible for the next stage of
            authentication (normally empty)
        :raises: `.BadAuthenticationType` --
            if GSS-API Key Exchange was not performed (and no event was passed
            in)
        :raises: `.AuthenticationException` --
            if the authentication failed (and no event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        pass

    def set_log_channel(self, name):
        """
        Set the channel for this transport's logging.  The default is
        ``"paramiko.transport"`` but it can be set to anything you want. (See
        the `.logging` module for more info.)  SSH Channels will log to a
        sub-channel of the one specified.

        :param str name: new channel name for logging

        .. versionadded:: 1.1
        """
        pass

    def get_log_channel(self):
        """
        Return the channel name used for this transport's logging.

        :return: channel name as a `str`

        .. versionadded:: 1.2
        """
        pass

    def set_hexdump(self, hexdump):
        """
        Turn on/off logging a hex dump of protocol traffic at DEBUG level in
        the logs.  Normally you would want this off (which is the default),
        but if you are debugging something, it may be useful.

        :param bool hexdump:
            ``True`` to log protocol traffix (in hex) to the log; ``False``
            otherwise.
        """
        pass

    def get_hexdump(self):
        """
        Return ``True`` if the transport is currently logging hex dumps of
        protocol traffic.

        :return: ``True`` if hex dumps are being logged, else ``False``.

        .. versionadded:: 1.4
        """
        pass

    def use_compression(self, compress=True):
        """
        Turn on/off compression.  This will only have an affect before starting
        the transport (ie before calling `connect`, etc).  By default,
        compression is off since it negatively affects interactive sessions.

        :param bool compress:
            ``True`` to ask the remote client/server to compress traffic;
            ``False`` to refuse compression

        .. versionadded:: 1.5.2
        """
        pass

    def getpeername(self):
        """
        Return the address of the remote side of this Transport, if possible.

        This is effectively a wrapper around ``getpeername`` on the underlying
        socket.  If the socket-like object has no ``getpeername`` method, then
        ``("unknown", 0)`` is returned.

        :return:
            the address of the remote host, if known, as a ``(str, int)``
            tuple.
        """
        pass

    def _get_modulus_pack(self):
        """used by KexGex to find primes for group exchange"""
        pass

    def _next_channel(self):
        """you are holding the lock"""
        pass

    def _unlink_channel(self, chanid):
        """used by a Channel to remove itself from the active channel list"""
        pass

    def _send_user_message(self, data):
        """
        send a message, but block if we're in key negotiation.  this is used
        for user-initiated requests.
        """
        pass

    def _set_K_H(self, k, h):
        """
        Used by a kex obj to set the K (root key) and H (exchange hash).
        """
        pass

    def _expect_packet(self, *ptypes):
        """
        Used by a kex obj to register the next packet type it expects to see.
        """
        pass

    def _compute_key(self, id, nbytes):
        """id is 'A' - 'F' for the various keys used by ssh"""
        pass

    def _ensure_authed(self, ptype, message):
        """
        Checks message type against current auth state.

        If server mode, and auth has not succeeded, and the message is of a
        post-auth type (channel open or global request) an appropriate error
        response Message is crafted and returned to caller for sending.

        Otherwise (client mode, authed, or pre-auth message) returns None.
        """
        pass

    def _enforce_strict_kex(self, ptype):
        """
        Conditionally raise `MessageOrderError` during strict initial kex.

        This method should only be called inside code that handles non-KEXINIT
        messages; it does not interrogate ``ptype`` besides using it to log
        more accurately.
        """
        pass

    def _send_kex_init(self):
        """
        announce to the other side that we'd like to negotiate keys, and what
        kind of key negotiation we support.
        """
        pass

    def _activate_inbound(self):
        """switch on newly negotiated encryption parameters for
        inbound traffic"""
        pass

    def _activate_outbound(self):
        """switch on newly negotiated encryption parameters for
        outbound traffic"""
        pass
    _channel_handler_table = {MSG_CHANNEL_SUCCESS: Channel._request_success, MSG_CHANNEL_FAILURE: Channel._request_failed, MSG_CHANNEL_DATA: Channel._feed, MSG_CHANNEL_EXTENDED_DATA: Channel._feed_extended, MSG_CHANNEL_WINDOW_ADJUST: Channel._window_adjust, MSG_CHANNEL_REQUEST: Channel._handle_request, MSG_CHANNEL_EOF: Channel._handle_eof, MSG_CHANNEL_CLOSE: Channel._handle_close}

class SecurityOptions:
    """
    Simple object containing the security preferences of an ssh transport.
    These are tuples of acceptable ciphers, digests, key types, and key
    exchange algorithms, listed in order of preference.

    Changing the contents and/or order of these fields affects the underlying
    `.Transport` (but only if you change them before starting the session).
    If you try to add an algorithm that paramiko doesn't recognize,
    ``ValueError`` will be raised.  If you try to assign something besides a
    tuple to one of the fields, ``TypeError`` will be raised.
    """
    __slots__ = '_transport'

    def __init__(self, transport):
        self._transport = transport

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.
        """
        return '<paramiko.SecurityOptions for {!r}>'.format(self._transport)

    @property
    def ciphers(self):
        """Symmetric encryption ciphers"""
        pass

    @property
    def digests(self):
        """Digest (one-way hash) algorithms"""
        pass

    @property
    def key_types(self):
        """Public-key algorithms"""
        pass

    @property
    def kex(self):
        """Key exchange algorithms"""
        pass

    @property
    def compression(self):
        """Compression algorithms"""
        pass

class ChannelMap:

    def __init__(self):
        self._map = weakref.WeakValueDictionary()
        self._lock = threading.Lock()

    def __len__(self):
        self._lock.acquire()
        try:
            return len(self._map)
        finally:
            self._lock.release()

class ServiceRequestingTransport(Transport):
    """
    Transport, but also handling service requests, like it oughtta!

    .. versionadded:: 3.2
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._service_userauth_accepted = False
        self._handler_table[MSG_SERVICE_ACCEPT] = self._parse_service_accept
