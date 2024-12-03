"""
SSH Agent interface
"""
import os
import socket
import struct
import sys
import threading
import time
import tempfile
import stat
from logging import DEBUG
from select import select
from paramiko.common import io_sleep, byte_chr
from paramiko.ssh_exception import SSHException, AuthenticationException
from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.util import asbytes, get_logger
cSSH2_AGENTC_REQUEST_IDENTITIES = byte_chr(11)
SSH2_AGENT_IDENTITIES_ANSWER = 12
cSSH2_AGENTC_SIGN_REQUEST = byte_chr(13)
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4
ALGORITHM_FLAG_MAP = {'rsa-sha2-256': SSH_AGENT_RSA_SHA2_256, 'rsa-sha2-512': SSH_AGENT_RSA_SHA2_512}
for key, value in list(ALGORITHM_FLAG_MAP.items()):
    ALGORITHM_FLAG_MAP[f'{key}-cert-v01@openssh.com'] = value

class AgentSSH:

    def __init__(self):
        self._conn = None
        self._keys = ()

    def get_keys(self):
        """
        Return the list of keys available through the SSH agent, if any.  If
        no SSH agent was running (or it couldn't be contacted), an empty list
        will be returned.

        This method performs no IO, just returns the list of keys retrieved
        when the connection was made.

        :return:
            a tuple of `.AgentKey` objects representing keys available on the
            SSH agent
        """
        return self._keys

class AgentProxyThread(threading.Thread):
    """
    Class in charge of communication between two channels.
    """

    def __init__(self, agent):
        threading.Thread.__init__(self, target=self.run)
        self._agent = agent
        self._exit = False

class AgentLocalProxy(AgentProxyThread):
    """
    Class to be used when wanting to ask a local SSH Agent being
    asked from a remote fake agent (so use a unix socket for ex.)
    """

    def __init__(self, agent):
        AgentProxyThread.__init__(self, agent)

    def get_connection(self):
        """
        Return a pair of socket object and string address.

        May block!
        """
        import tempfile
        import socket
        import os

        temp_dir = tempfile.mkdtemp(prefix='ssh-')
        socket_path = os.path.join(temp_dir, 'agent.{}'.format(os.getpid()))
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socket_path)
        sock.listen(1)

        return sock, socket_path

class AgentRemoteProxy(AgentProxyThread):
    """
    Class to be used when wanting to ask a remote SSH Agent
    """

    def __init__(self, agent, chan):
        AgentProxyThread.__init__(self, agent)
        self.__chan = chan

def get_agent_connection():
    """
    Returns some SSH agent object, or None if none were found/supported.

    .. versionadded:: 2.10
    """
    import os
    import socket

    # Try to connect to the SSH agent
    agent_sock = os.environ.get('SSH_AUTH_SOCK')
    if agent_sock:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(agent_sock)
            return sock
        except socket.error:
            return None

    # If no SSH agent is available, return None
    return None

class AgentClientProxy:
    """
    Class proxying request as a client:

    #. client ask for a request_forward_agent()
    #. server creates a proxy and a fake SSH Agent
    #. server ask for establishing a connection when needed,
       calling the forward_agent_handler at client side.
    #. the forward_agent_handler launch a thread for connecting
       the remote fake agent and the local agent
    #. Communication occurs ...
    """

    def __init__(self, chanRemote):
        self._conn = None
        self.__chanR = chanRemote
        self.thread = AgentRemoteProxy(self, chanRemote)
        self.thread.start()

    def __del__(self):
        self.close()

    def connect(self):
        """
        Method automatically called by ``AgentProxyThread.run``.
        """
        if self._conn is None:
            self._conn = get_agent_connection()
        return self._conn is not None

    def close(self):
        """
        Close the current connection and terminate the agent
        Should be called manually
        """
        if self._conn:
            self._conn.close()
            self._conn = None
        if self.thread:
            self.thread.join()

class AgentServerProxy(AgentSSH):
    """
    Allows an SSH server to access a forwarded agent.

    This also creates a unix domain socket on the system to allow external
    programs to also access the agent. For this reason, you probably only want
    to create one of these.

    :meth:`connect` must be called before it is usable. This will also load the
    list of keys the agent contains. You must also call :meth:`close` in
    order to clean up the unix socket and the thread that maintains it.
    (:class:`contextlib.closing` might be helpful to you.)

    :param .Transport t: Transport used for SSH Agent communication forwarding

    :raises: `.SSHException` -- mostly if we lost the agent
    """

    def __init__(self, t):
        AgentSSH.__init__(self)
        self.__t = t
        self._dir = tempfile.mkdtemp('sshproxy')
        os.chmod(self._dir, stat.S_IRWXU)
        self._file = self._dir + '/sshproxy.ssh'
        self.thread = AgentLocalProxy(self)
        self.thread.start()

    def __del__(self):
        self.close()

    def close(self):
        """
        Terminate the agent, clean the files, close connections
        Should be called manually
        """
        if self.thread:
            self.thread.exit = True
            self.thread.join()

        if self._conn:
            self._conn.close()
            self._conn = None

        import os
        import shutil

        if os.path.exists(self._file):
            os.remove(self._file)
        if os.path.exists(self._dir):
            shutil.rmtree(self._dir)

    def get_env(self):
        """
        Helper for the environment under unix

        :return:
            a dict containing the ``SSH_AUTH_SOCK`` environment variables
        """
        return {'SSH_AUTH_SOCK': self._file}

class AgentRequestHandler:
    """
    Primary/default implementation of SSH agent forwarding functionality.

    Simply instantiate this class, handing it a live command-executing session
    object, and it will handle forwarding any local SSH agent processes it
    finds.

    For example::

        # Connect
        client = SSHClient()
        client.connect(host, port, username)
        # Obtain session
        session = client.get_transport().open_session()
        # Forward local agent
        AgentRequestHandler(session)
        # Commands executed after this point will see the forwarded agent on
        # the remote end.
        session.exec_command("git clone https://my.git.repository/")
    """

    def __init__(self, chanClient):
        self._conn = None
        self.__chanC = chanClient
        chanClient.request_forward_agent(self._forward_agent_handler)
        self.__clientProxys = []

    def __del__(self):
        self.close()

class Agent(AgentSSH):
    """
    Client interface for using private keys from an SSH agent running on the
    local machine.  If an SSH agent is running, this class can be used to
    connect to it and retrieve `.PKey` objects which can be used when
    attempting to authenticate to remote SSH servers.

    Upon initialization, a session with the local machine's SSH agent is
    opened, if one is running. If no agent is running, initialization will
    succeed, but `get_keys` will return an empty tuple.

    :raises: `.SSHException` --
        if an SSH agent is found, but speaks an incompatible protocol

    .. versionchanged:: 2.10
        Added support for native openssh agent on windows (extending previous
        putty pageant support)
    """

    def __init__(self):
        AgentSSH.__init__(self)
        conn = get_agent_connection()
        if not conn:
            return
        self._connect(conn)

    def close(self):
        """
        Close the SSH agent connection.
        """
        pass

class AgentKey(PKey):
    """
    Private key held in a local SSH agent.  This type of key can be used for
    authenticating to a remote server (signing).  Most other key operations
    work as expected.

    .. versionchanged:: 3.2
        Added the ``comment`` kwarg and attribute.

    .. versionchanged:: 3.2
        Added the ``.inner_key`` attribute holding a reference to the 'real'
        key instance this key is a proxy for, if one was obtainable, else None.
    """

    def __init__(self, agent, blob, comment=''):
        self.agent = agent
        self.blob = blob
        self.comment = comment
        msg = Message(blob)
        self.name = msg.get_text()
        self._logger = get_logger(__file__)
        self.inner_key = None
        try:
            self.inner_key = PKey.from_type_string(key_type=self.name, key_bytes=blob)
        except UnknownKeyType:
            err = 'Unable to derive inner_key for agent key of type {!r}'
            self.log(DEBUG, err.format(self.name))

    def __getattr__(self, name):
        """
        Proxy any un-implemented methods/properties to the inner_key.
        """
        if self.inner_key is None:
            raise AttributeError(name)
        return getattr(self.inner_key, name)
