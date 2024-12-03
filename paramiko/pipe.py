"""
Abstraction of a one-way pipe where the read end can be used in
`select.select`. Normally this is trivial, but Windows makes it nearly
impossible.

The pipe acts like an Event, which can be set or cleared. When set, the pipe
will trigger as readable in `select <select.select>`.
"""
import sys
import os
import socket

class PosixPipe:

    def __init__(self):
        self._rfd, self._wfd = os.pipe()
        self._set = False
        self._forever = False
        self._closed = False

class WindowsPipe:
    """
    On Windows, only an OS-level "WinSock" may be used in select(), but reads
    and writes must be to the actual socket object.
    """

    def __init__(self):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv.bind(('127.0.0.1', 0))
        serv.listen(1)
        self._rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._rsock.connect(('127.0.0.1', serv.getsockname()[1]))
        self._wsock, addr = serv.accept()
        serv.close()
        self._set = False
        self._forever = False
        self._closed = False

class OrPipe:

    def __init__(self, pipe):
        self._set = False
        self._partner = None
        self._pipe = pipe

def make_or_pipe(pipe):
    """
    wraps a pipe into two pipe-like objects which are "or"d together to
    affect the real pipe. if either returned pipe is set, the wrapped pipe
    is set. when both are cleared, the wrapped pipe is cleared.
    """
    a = OrPipe(pipe)
    b = OrPipe(pipe)
    a._partner = b
    b._partner = a
    return a, b
