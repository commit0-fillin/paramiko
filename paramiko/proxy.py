import os
import shlex
import signal
from select import select
import socket
import time
subprocess, subprocess_import_error = (None, None)
try:
    import subprocess
except ImportError as e:
    subprocess_import_error = e
from paramiko.ssh_exception import ProxyCommandFailure
from paramiko.util import ClosingContextManager

class ProxyCommand(ClosingContextManager):
    """
    Wraps a subprocess running ProxyCommand-driven programs.

    This class implements a the socket-like interface needed by the
    `.Transport` and `.Packetizer` classes. Using this class instead of a
    regular socket makes it possible to talk with a Popen'd command that will
    proxy traffic between the client and a server hosted in another machine.

    Instances of this class may be used as context managers.
    """

    def __init__(self, command_line):
        """
        Create a new CommandProxy instance. The instance created by this
        class can be passed as an argument to the `.Transport` class.

        :param str command_line:
            the command that should be executed and used as the proxy.
        """
        if subprocess is None:
            raise subprocess_import_error
        self.cmd = shlex.split(command_line)
        self.process = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.timeout = None

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        :param str content: string to be sent to the forked command
        """
        try:
            self.process.stdin.write(content)
            self.process.stdin.flush()
            return len(content)
        except IOError:
            return 0

    def recv(self, size):
        """
        Read from the standard output of the forked program.

        :param int size: how many chars should be read

        :return: the string of bytes read, which may be shorter than requested
        """
        if self.timeout is not None:
            rlist, wlist, xlist = select([self.process.stdout], [], [], self.timeout)
            if len(rlist) == 0:
                raise socket.timeout()
        try:
            return self.process.stdout.read(size)
        except IOError:
            return b''
