"""
SSH client & key policies
"""
from binascii import hexlify
import getpass
import inspect
import os
import socket
import warnings
from errno import ECONNREFUSED, EHOSTUNREACH
from paramiko.agent import Agent
from paramiko.common import DEBUG
from paramiko.config import SSH_PORT
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.hostkeys import HostKeys
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException, BadHostKeyException, NoValidConnectionsError
from paramiko.transport import Transport
from paramiko.util import ClosingContextManager

class SSHClient(ClosingContextManager):
    """
    A high-level representation of a session with an SSH server.  This class
    wraps `.Transport`, `.Channel`, and `.SFTPClient` to take care of most
    aspects of authenticating and opening channels.  A typical use case is::

        client = SSHClient()
        client.load_system_host_keys()
        client.connect('ssh.example.com')
        stdin, stdout, stderr = client.exec_command('ls -l')

    You may pass in explicit overrides for authentication and server host key
    checking.  The default mechanism is to try to use local key files or an
    SSH agent (if one is running).

    Instances of this class may be used as context managers.

    .. versionadded:: 1.6
    """

    def __init__(self):
        """
        Create a new SSHClient.
        """
        self._system_host_keys = HostKeys()
        self._host_keys = HostKeys()
        self._host_keys_filename = None
        self._log_channel = None
        self._policy = RejectPolicy()
        self._transport = None
        self._agent = None

    def load_system_host_keys(self, filename=None):
        """
        Load host keys from a system (read-only) file.  Host keys read with
        this method will not be saved back by `save_host_keys`.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).

        If ``filename`` is left as ``None``, an attempt will be made to read
        keys from the user's local "known hosts" file, as used by OpenSSH,
        and no exception will be raised if the file can't be read.  This is
        probably only useful on posix.

        :param str filename: the filename to read, or ``None``

        :raises: ``IOError`` --
            if a filename was provided and the file could not be read
        """
        if filename is None:
            # Try to get the user's .ssh known_hosts file
            filename = os.path.expanduser('~/.ssh/known_hosts')
            if not os.path.exists(filename):
                return
        
        try:
            self._system_host_keys.load(filename)
        except IOError:
            # Only raise IOError if a filename was explicitly provided
            if filename is not None:
                raise

    def load_host_keys(self, filename):
        """
        Load host keys from a local host-key file.  Host keys read with this
        method will be checked after keys loaded via `load_system_host_keys`,
        but will be saved back by `save_host_keys` (so they can be modified).
        The missing host key policy `.AutoAddPolicy` adds keys to this set and
        saves them, when connecting to a previously-unknown server.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).  When automatically saving, the last hostname is used.

        :param str filename: the filename to read

        :raises: ``IOError`` -- if the filename could not be read
        """
        self._host_keys.load(filename)
        self._host_keys_filename = filename

    def save_host_keys(self, filename):
        """
        Save the host keys back to a file.  Only the host keys loaded with
        `load_host_keys` (plus any added directly) will be saved -- not any
        host keys loaded with `load_system_host_keys`.

        :param str filename: the filename to save to

        :raises: ``IOError`` -- if the file could not be written
        """
        with open(filename, 'w') as f:
            for hostname, keys in self._host_keys.items():
                for keytype, key in keys.items():
                    f.write(f"{hostname} {keytype} {key.get_base64()}\n")

    def get_host_keys(self):
        """
        Get the local `.HostKeys` object.  This can be used to examine the
        local host keys or change them.

        :return: the local host keys as a `.HostKeys` object.
        """
        return self._host_keys

    def set_log_channel(self, name):
        """
        Set the channel for logging.  The default is ``"paramiko.transport"``
        but it can be set to anything you want.

        :param str name: new channel name for logging
        """
        self._log_channel = name

    def set_missing_host_key_policy(self, policy):
        """
        Set policy to use when connecting to servers without a known host key.

        Specifically:

        * A **policy** is a "policy class" (or instance thereof), namely some
          subclass of `.MissingHostKeyPolicy` such as `.RejectPolicy` (the
          default), `.AutoAddPolicy`, `.WarningPolicy`, or a user-created
          subclass.
        * A host key is **known** when it appears in the client object's cached
          host keys structures (those manipulated by `load_system_host_keys`
          and/or `load_host_keys`).

        :param .MissingHostKeyPolicy policy:
            the policy to use when receiving a host key from a
            previously-unknown server
        """
        self._policy = policy

    def _families_and_addresses(self, hostname, port):
        """
        Yield pairs of address families and addresses to try for connecting.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :returns: Yields an iterable of ``(family, address)`` tuples
        """
        guess = False
        addrinfos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for (family, socktype, proto, canonname, sockaddr) in addrinfos:
            if socktype == socket.SOCK_STREAM:
                yield family, sockaddr
                guess = True
        if not guess:
            # some OS like AIX don't indicate SOCK_STREAM support, so just
            # return the first address
            family, _, _, _, sockaddr = addrinfos[0]
            yield family, sockaddr

    def connect(self, hostname, port=SSH_PORT, username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, channel_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None, transport_factory=None, auth_strategy=None):
        """
        Connect to an SSH server and authenticate to it.  The server's host key
        is checked against the system host keys (see `load_system_host_keys`)
        and any local host keys (`load_host_keys`).  If the server's hostname
        is not found in either set of host keys, the missing host key policy
        is used (see `set_missing_host_key_policy`).  The default policy is
        to reject the key and raise an `.SSHException`.

        Authentication is attempted in the following order of priority:

            - The ``pkey`` or ``key_filename`` passed in (if any)

              - ``key_filename`` may contain OpenSSH public certificate paths
                as well as regular private-key paths; when files ending in
                ``-cert.pub`` are found, they are assumed to match a private
                key, and both components will be loaded. (The private key
                itself does *not* need to be listed in ``key_filename`` for
                this to occur - *just* the certificate.)

            - Any key we can find through an SSH agent
            - Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in
              ``~/.ssh/``

              - When OpenSSH-style public certificates exist that match an
                existing such private key (so e.g. one has ``id_rsa`` and
                ``id_rsa-cert.pub``) the certificate will be loaded alongside
                the private key and used for authentication.

            - Plain username/password auth, if a password was given

        If a private key requires a password to unlock it, and a password is
        passed in, that password will be used to attempt to unlock the key.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :param str username:
            the username to authenticate as (defaults to the current local
            username)
        :param str password:
            Used for password authentication; is also used for private key
            decryption if ``passphrase`` is not given.
        :param str passphrase:
            Used for decrypting private keys.
        :param .PKey pkey: an optional private key to use for authentication
        :param str key_filename:
            the filename, or list of filenames, of optional private key(s)
            and/or certs to try for authentication
        :param float timeout:
            an optional timeout (in seconds) for the TCP connect
        :param bool allow_agent:
            set to False to disable connecting to the SSH agent
        :param bool look_for_keys:
            set to False to disable searching for discoverable private key
            files in ``~/.ssh/``
        :param bool compress: set to True to turn on compression
        :param socket sock:
            an open socket or socket-like object (such as a `.Channel`) to use
            for communication to the target host
        :param bool gss_auth:
            ``True`` if you want to use GSS-API authentication
        :param bool gss_kex:
            Perform GSS-API Key Exchange and user authentication
        :param bool gss_deleg_creds: Delegate GSS-API client credentials or not
        :param str gss_host:
            The targets name in the kerberos database. default: hostname
        :param bool gss_trust_dns:
            Indicates whether or not the DNS is trusted to securely
            canonicalize the name of the host being connected to (default
            ``True``).
        :param float banner_timeout: an optional timeout (in seconds) to wait
            for the SSH banner to be presented.
        :param float auth_timeout: an optional timeout (in seconds) to wait for
            an authentication response.
        :param float channel_timeout: an optional timeout (in seconds) to wait
             for a channel open response.
        :param dict disabled_algorithms:
            an optional dict passed directly to `.Transport` and its keyword
            argument of the same name.
        :param transport_factory:
            an optional callable which is handed a subset of the constructor
            arguments (primarily those related to the socket, GSS
            functionality, and algorithm selection) and generates a
            `.Transport` instance to be used by this client. Defaults to
            `.Transport.__init__`.
        :param auth_strategy:
            an optional instance of `.AuthStrategy`, triggering use of this
            newer authentication mechanism instead of SSHClient's legacy auth
            method.

            .. warning::
                This parameter is **incompatible** with all other
                authentication-related parameters (such as, but not limited to,
                ``password``, ``key_filename`` and ``allow_agent``) and will
                trigger an exception if given alongside them.

        :returns:
            `.AuthResult` if ``auth_strategy`` is non-``None``; otherwise,
            returns ``None``.

        :raises BadHostKeyException:
            if the server's host key could not be verified.
        :raises AuthenticationException:
            if authentication failed.
        :raises UnableToAuthenticate:
            if authentication failed (when ``auth_strategy`` is non-``None``;
            and note that this is a subclass of ``AuthenticationException``).
        :raises socket.error:
            if a socket error (other than connection-refused or
            host-unreachable) occurred while connecting.
        :raises NoValidConnectionsError:
            if all valid connection targets for the requested hostname (eg IPv4
            and IPv6) yielded connection-refused or host-unreachable socket
            errors.
        :raises SSHException:
            if there was any other error connecting or establishing an SSH
            session.

        .. versionchanged:: 1.15
            Added the ``banner_timeout``, ``gss_auth``, ``gss_kex``,
            ``gss_deleg_creds`` and ``gss_host`` arguments.
        .. versionchanged:: 2.3
            Added the ``gss_trust_dns`` argument.
        .. versionchanged:: 2.4
            Added the ``passphrase`` argument.
        .. versionchanged:: 2.6
            Added the ``disabled_algorithms`` argument.
        .. versionchanged:: 2.12
            Added the ``transport_factory`` argument.
        .. versionchanged:: 3.2
            Added the ``auth_strategy`` argument.
        """
        pass

    def close(self):
        """
        Close this SSHClient and its underlying `.Transport`.

        This should be called anytime you are done using the client object.

        .. warning::
            Paramiko registers garbage collection hooks that will try to
            automatically close connections for you, but this is not presently
            reliable. Failure to explicitly close your client after use may
            lead to end-of-process hangs!
        """
        pass

    def exec_command(self, command, bufsize=-1, timeout=None, get_pty=False, environment=None):
        """
        Execute a command on the SSH server.  A new `.Channel` is opened and
        the requested command is executed.  The command's input and output
        streams are returned as Python ``file``-like objects representing
        stdin, stdout, and stderr.

        :param str command: the command to execute
        :param int bufsize:
            interpreted the same way as by the built-in ``file()`` function in
            Python
        :param int timeout:
            set command's channel timeout. See `.Channel.settimeout`
        :param bool get_pty:
            Request a pseudo-terminal from the server (default ``False``).
            See `.Channel.get_pty`
        :param dict environment:
            a dict of shell environment variables, to be merged into the
            default environment that the remote command executes within.

            .. warning::
                Servers may silently reject some environment variables; see the
                warning in `.Channel.set_environment_variable` for details.

        :return:
            the stdin, stdout, and stderr of the executing command, as a
            3-tuple

        :raises: `.SSHException` -- if the server fails to execute the command

        .. versionchanged:: 1.10
            Added the ``get_pty`` kwarg.
        """
        pass

    def invoke_shell(self, term='vt100', width=80, height=24, width_pixels=0, height_pixels=0, environment=None):
        """
        Start an interactive shell session on the SSH server.  A new `.Channel`
        is opened and connected to a pseudo-terminal using the requested
        terminal type and size.

        :param str term:
            the terminal type to emulate (for example, ``"vt100"``)
        :param int width: the width (in characters) of the terminal window
        :param int height: the height (in characters) of the terminal window
        :param int width_pixels: the width (in pixels) of the terminal window
        :param int height_pixels: the height (in pixels) of the terminal window
        :param dict environment: the command's environment
        :return: a new `.Channel` connected to the remote shell

        :raises: `.SSHException` -- if the server fails to invoke a shell
        """
        pass

    def open_sftp(self):
        """
        Open an SFTP session on the SSH server.

        :return: a new `.SFTPClient` session object
        """
        pass

    def get_transport(self):
        """
        Return the underlying `.Transport` object for this SSH connection.
        This can be used to perform lower-level tasks, like opening specific
        kinds of channels.

        :return: the `.Transport` for this connection
        """
        pass

    def _key_from_filepath(self, filename, klass, password):
        """
        Attempt to derive a `.PKey` from given string path ``filename``:

        - If ``filename`` appears to be a cert, the matching private key is
          loaded.
        - Otherwise, the filename is assumed to be a private key, and the
          matching public cert will be loaded if it exists.
        """
        pass

    def _auth(self, username, password, pkey, key_filenames, allow_agent, look_for_keys, gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase):
        """
        Try, in order:

            - The key(s) passed in, if one was passed in.
            - Any key we can find through an SSH agent (if allowed).
            - Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in ~/.ssh/
              (if allowed).
            - Plain username/password auth, if a password was given.

        (The password might be needed to unlock a private key [if 'passphrase'
        isn't also given], or for two-factor authentication [for which it is
        required].)
        """
        pass

class MissingHostKeyPolicy:
    """
    Interface for defining the policy that `.SSHClient` should use when the
    SSH server's hostname is not in either the system host keys or the
    application's keys.  Pre-made classes implement policies for automatically
    adding the key to the application's `.HostKeys` object (`.AutoAddPolicy`),
    and for automatically rejecting the key (`.RejectPolicy`).

    This function may be used to ask the user to verify the key, for example.
    """

    def missing_host_key(self, client, hostname, key):
        """
        Called when an `.SSHClient` receives a server key for a server that
        isn't in either the system or local `.HostKeys` object.  To accept
        the key, simply return.  To reject, raised an exception (which will
        be passed to the calling application).
        """
        pass

class AutoAddPolicy(MissingHostKeyPolicy):
    """
    Policy for automatically adding the hostname and new host key to the
    local `.HostKeys` object, and saving it.  This is used by `.SSHClient`.
    """

class RejectPolicy(MissingHostKeyPolicy):
    """
    Policy for automatically rejecting the unknown hostname & key.  This is
    used by `.SSHClient`.
    """

class WarningPolicy(MissingHostKeyPolicy):
    """
    Policy for logging a Python-style warning for an unknown host key, but
    accepting it. This is used by `.SSHClient`.
    """
