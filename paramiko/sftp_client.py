from binascii import hexlify
import errno
import os
import stat
import threading
import time
import weakref
from paramiko import util
from paramiko.channel import Channel
from paramiko.message import Message
from paramiko.common import INFO, DEBUG, o777
from paramiko.sftp import BaseSFTP, CMD_OPENDIR, CMD_HANDLE, SFTPError, CMD_READDIR, CMD_NAME, CMD_CLOSE, SFTP_FLAG_READ, SFTP_FLAG_WRITE, SFTP_FLAG_CREATE, SFTP_FLAG_TRUNC, SFTP_FLAG_APPEND, SFTP_FLAG_EXCL, CMD_OPEN, CMD_REMOVE, CMD_RENAME, CMD_MKDIR, CMD_RMDIR, CMD_STAT, CMD_ATTRS, CMD_LSTAT, CMD_SYMLINK, CMD_SETSTAT, CMD_READLINK, CMD_REALPATH, CMD_STATUS, CMD_EXTENDED, SFTP_OK, SFTP_EOF, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED, int64
from paramiko.sftp_attr import SFTPAttributes
from paramiko.ssh_exception import SSHException
from paramiko.sftp_file import SFTPFile
from paramiko.util import ClosingContextManager, b, u

def _to_unicode(s):
    """
    decode a string as ascii or utf8 if possible (as required by the sftp
    protocol).  if neither works, just return a byte string because the server
    probably doesn't know the filename's encoding.
    """
    try:
        return s.decode('ascii')
    except UnicodeDecodeError:
        try:
            return s.decode('utf-8')
        except UnicodeDecodeError:
            return s
b_slash = b'/'

class SFTPClient(BaseSFTP, ClosingContextManager):
    """
    SFTP client object.

    Used to open an SFTP session across an open SSH `.Transport` and perform
    remote file operations.

    Instances of this class may be used as context managers.
    """

    def __init__(self, sock):
        """
        Create an SFTP client from an existing `.Channel`.  The channel
        should already have requested the ``"sftp"`` subsystem.

        An alternate way to create an SFTP client context is by using
        `from_transport`.

        :param .Channel sock: an open `.Channel` using the ``"sftp"`` subsystem

        :raises:
            `.SSHException` -- if there's an exception while negotiating sftp
        """
        BaseSFTP.__init__(self)
        self.sock = sock
        self.ultra_debug = False
        self.request_number = 1
        self._lock = threading.Lock()
        self._cwd = None
        self._expecting = weakref.WeakValueDictionary()
        if type(sock) is Channel:
            transport = self.sock.get_transport()
            self.logger = util.get_logger(transport.get_log_channel() + '.sftp')
            self.ultra_debug = transport.get_hexdump()
        try:
            server_version = self._send_version()
        except EOFError:
            raise SSHException('EOF during negotiation')
        self._log(INFO, 'Opened sftp connection (server version {})'.format(server_version))

    @classmethod
    def from_transport(cls, t, window_size=None, max_packet_size=None):
        """
        Create an SFTP client channel from an open `.Transport`.

        Setting the window and packet sizes might affect the transfer speed.
        The default settings in the `.Transport` class are the same as in
        OpenSSH and should work adequately for both files transfers and
        interactive sessions.

        :param .Transport t: an open `.Transport` which is already
            authenticated
        :param int window_size:
            optional window size for the `.SFTPClient` session.
        :param int max_packet_size:
            optional max packet size for the `.SFTPClient` session..

        :return:
            a new `.SFTPClient` object, referring to an sftp session (channel)
            across the transport

        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        chan = t.open_session(window_size=window_size, max_packet_size=max_packet_size)
        if chan is None:
            return None
        chan.invoke_subsystem('sftp')
        return cls(chan)

    def close(self):
        """
        Close the SFTP session and its underlying channel.

        .. versionadded:: 1.4
        """
        self.sock.close()
        self.sock = None

    def get_channel(self):
        """
        Return the underlying `.Channel` object for this SFTP session.  This
        might be useful for doing things like setting a timeout on the channel.

        .. versionadded:: 1.7.1
        """
        return self.sock

    def listdir(self, path='.'):
        """
        Return a list containing the names of the entries in the given
        ``path``.

        The list is in arbitrary order.  It does not include the special
        entries ``'.'`` and ``'..'`` even if they are present in the folder.
        This method is meant to mirror ``os.listdir`` as closely as possible.
        For a list of full `.SFTPAttributes` objects, see `listdir_attr`.

        :param str path: path to list (defaults to ``'.'``)
        """
        return [f.filename for f in self.listdir_attr(path)]

    def listdir_attr(self, path='.'):
        """
        Return a list containing `.SFTPAttributes` objects corresponding to
        files in the given ``path``.  The list is in arbitrary order.  It does
        not include the special entries ``'.'`` and ``'..'`` even if they are
        present in the folder.

        The returned `.SFTPAttributes` objects will each have an additional
        field: ``longname``, which may contain a formatted string of the file's
        attributes, in unix format.  The content of this string will probably
        depend on the SFTP server implementation.

        :param str path: path to list (defaults to ``'.'``)
        :return: list of `.SFTPAttributes` objects

        .. versionadded:: 1.2
        """
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_OPENDIR, path)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_binary()
        filelist = []
        while True:
            try:
                t, msg = self._request(CMD_READDIR, handle)
                if t != CMD_NAME:
                    raise SFTPError('Expected name response')
                count = msg.get_int()
                for i in range(count):
                    filename = msg.get_text()
                    longname = msg.get_text()
                    attr = SFTPAttributes._from_msg(msg)
                    if (filename != '.') and (filename != '..'):
                        attr.filename = filename
                        attr.longname = longname
                        filelist.append(attr)
            except EOFError:
                break
        self._request(CMD_CLOSE, handle)
        return filelist

    def listdir_iter(self, path='.', read_aheads=50):
        """
        Generator version of `.listdir_attr`.

        See the API docs for `.listdir_attr` for overall details.

        This function adds one more kwarg on top of `.listdir_attr`:
        ``read_aheads``, an integer controlling how many
        ``SSH_FXP_READDIR`` requests are made to the server. The default of 50
        should suffice for most file listings as each request/response cycle
        may contain multiple files (dependent on server implementation.)

        .. versionadded:: 1.15
        """
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_OPENDIR, path)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_binary()
        
        read_ahead_count = 0
        while True:
            try:
                if read_ahead_count == 0:
                    t, msg = self._request(CMD_READDIR, handle)
                    if t != CMD_NAME:
                        raise SFTPError('Expected name response')
                    read_ahead_count = read_aheads
                
                count = msg.get_int()
                for i in range(count):
                    filename = msg.get_text()
                    longname = msg.get_text()
                    attr = SFTPAttributes._from_msg(msg)
                    if (filename != '.') and (filename != '..'):
                        attr.filename = filename
                        attr.longname = longname
                        yield attr
                
                read_ahead_count -= 1
            except EOFError:
                break
        
        self._request(CMD_CLOSE, handle)

    def open(self, filename, mode='r', bufsize=-1):
        """
        Open a file on the remote server.  The arguments are the same as for
        Python's built-in `python:file` (aka `python:open`).  A file-like
        object is returned, which closely mimics the behavior of a normal
        Python file object, including the ability to be used as a context
        manager.

        The mode indicates how the file is to be opened: ``'r'`` for reading,
        ``'w'`` for writing (truncating an existing file), ``'a'`` for
        appending, ``'r+'`` for reading/writing, ``'w+'`` for reading/writing
        (truncating an existing file), ``'a+'`` for reading/appending.  The
        Python ``'b'`` flag is ignored, since SSH treats all files as binary.
        The ``'U'`` flag is supported in a compatible way.

        Since 1.5.2, an ``'x'`` flag indicates that the operation should only
        succeed if the file was created and did not previously exist.  This has
        no direct mapping to Python's file flags, but is commonly known as the
        ``O_EXCL`` flag in posix.

        The file will be buffered in standard Python style by default, but
        can be altered with the ``bufsize`` parameter.  ``<=0`` turns off
        buffering, ``1`` uses line buffering, and any number greater than 1
        (``>1``) uses that specific buffer size.

        :param str filename: name of the file to open
        :param str mode: mode (Python-style) to open in
        :param int bufsize: desired buffering (default: ``-1``)
        :return: an `.SFTPFile` object representing the open file

        :raises: ``IOError`` -- if the file could not be opened.
        """
        pass
    file = open

    def remove(self, path):
        """
        Remove the file at the given path.  This only works on files; for
        removing folders (directories), use `rmdir`.

        :param str path: path (absolute or relative) of the file to remove

        :raises: ``IOError`` -- if the path refers to a folder (directory)
        """
        pass
    unlink = remove

    def rename(self, oldpath, newpath):
        """
        Rename a file or folder from ``oldpath`` to ``newpath``.

        .. note::
            This method implements 'standard' SFTP ``RENAME`` behavior; those
            seeking the OpenSSH "POSIX rename" extension behavior should use
            `posix_rename`.

        :param str oldpath:
            existing name of the file or folder
        :param str newpath:
            new name for the file or folder, must not exist already

        :raises:
            ``IOError`` -- if ``newpath`` is a folder, or something else goes
            wrong
        """
        pass

    def posix_rename(self, oldpath, newpath):
        """
        Rename a file or folder from ``oldpath`` to ``newpath``, following
        posix conventions.

        :param str oldpath: existing name of the file or folder
        :param str newpath: new name for the file or folder, will be
            overwritten if it already exists

        :raises:
            ``IOError`` -- if ``newpath`` is a folder, posix-rename is not
            supported by the server or something else goes wrong

        :versionadded: 2.2
        """
        pass

    def mkdir(self, path, mode=o777):
        """
        Create a folder (directory) named ``path`` with numeric mode ``mode``.
        The default mode is 0777 (octal).  On some systems, mode is ignored.
        Where it is used, the current umask value is first masked out.

        :param str path: name of the folder to create
        :param int mode: permissions (posix-style) for the newly-created folder
        """
        pass

    def rmdir(self, path):
        """
        Remove the folder named ``path``.

        :param str path: name of the folder to remove
        """
        pass

    def stat(self, path):
        """
        Retrieve information about a file on the remote system.  The return
        value is an object whose attributes correspond to the attributes of
        Python's ``stat`` structure as returned by ``os.stat``, except that it
        contains fewer fields.  An SFTP server may return as much or as little
        info as it wants, so the results may vary from server to server.

        Unlike a Python `python:stat` object, the result may not be accessed as
        a tuple.  This is mostly due to the author's slack factor.

        The fields supported are: ``st_mode``, ``st_size``, ``st_uid``,
        ``st_gid``, ``st_atime``, and ``st_mtime``.

        :param str path: the filename to stat
        :return:
            an `.SFTPAttributes` object containing attributes about the given
            file
        """
        pass

    def lstat(self, path):
        """
        Retrieve information about a file on the remote system, without
        following symbolic links (shortcuts).  This otherwise behaves exactly
        the same as `stat`.

        :param str path: the filename to stat
        :return:
            an `.SFTPAttributes` object containing attributes about the given
            file
        """
        pass

    def symlink(self, source, dest):
        """
        Create a symbolic link to the ``source`` path at ``destination``.

        :param str source: path of the original file
        :param str dest: path of the newly created symlink
        """
        pass

    def chmod(self, path, mode):
        """
        Change the mode (permissions) of a file.  The permissions are
        unix-style and identical to those used by Python's `os.chmod`
        function.

        :param str path: path of the file to change the permissions of
        :param int mode: new permissions
        """
        pass

    def chown(self, path, uid, gid):
        """
        Change the owner (``uid``) and group (``gid``) of a file.  As with
        Python's `os.chown` function, you must pass both arguments, so if you
        only want to change one, use `stat` first to retrieve the current
        owner and group.

        :param str path: path of the file to change the owner and group of
        :param int uid: new owner's uid
        :param int gid: new group id
        """
        pass

    def utime(self, path, times):
        """
        Set the access and modified times of the file specified by ``path``.
        If ``times`` is ``None``, then the file's access and modified times
        are set to the current time.  Otherwise, ``times`` must be a 2-tuple
        of numbers, of the form ``(atime, mtime)``, which is used to set the
        access and modified times, respectively.  This bizarre API is mimicked
        from Python for the sake of consistency -- I apologize.

        :param str path: path of the file to modify
        :param tuple times:
            ``None`` or a tuple of (access time, modified time) in standard
            internet epoch time (seconds since 01 January 1970 GMT)
        """
        pass

    def truncate(self, path, size):
        """
        Change the size of the file specified by ``path``.  This usually
        extends or shrinks the size of the file, just like the `~file.truncate`
        method on Python file objects.

        :param str path: path of the file to modify
        :param int size: the new size of the file
        """
        pass

    def readlink(self, path):
        """
        Return the target of a symbolic link (shortcut).  You can use
        `symlink` to create these.  The result may be either an absolute or
        relative pathname.

        :param str path: path of the symbolic link file
        :return: target path, as a `str`
        """
        pass

    def normalize(self, path):
        """
        Return the normalized path (on the server) of a given path.  This
        can be used to quickly resolve symbolic links or determine what the
        server is considering to be the "current folder" (by passing ``'.'``
        as ``path``).

        :param str path: path to be normalized
        :return: normalized form of the given path (as a `str`)

        :raises: ``IOError`` -- if the path can't be resolved on the server
        """
        pass

    def chdir(self, path=None):
        """
        Change the "current directory" of this SFTP session.  Since SFTP
        doesn't really have the concept of a current working directory, this is
        emulated by Paramiko.  Once you use this method to set a working
        directory, all operations on this `.SFTPClient` object will be relative
        to that path. You can pass in ``None`` to stop using a current working
        directory.

        :param str path: new current working directory

        :raises:
            ``IOError`` -- if the requested path doesn't exist on the server

        .. versionadded:: 1.4
        """
        pass

    def getcwd(self):
        """
        Return the "current working directory" for this SFTP session, as
        emulated by Paramiko.  If no directory has been set with `chdir`,
        this method will return ``None``.

        .. versionadded:: 1.4
        """
        pass

    def putfo(self, fl, remotepath, file_size=0, callback=None, confirm=True):
        """
        Copy the contents of an open file object (``fl``) to the SFTP server as
        ``remotepath``. Any exception raised by operations will be passed
        through.

        The SFTP operations use pipelining for speed.

        :param fl: opened file or file-like object to copy
        :param str remotepath: the destination path on the SFTP server
        :param int file_size:
            optional size parameter passed to callback. If none is specified,
            size defaults to 0
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred
            (since 1.7.4)
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size (since 1.7.7)

        :return:
            an `.SFTPAttributes` object containing attributes about the given
            file.

        .. versionadded:: 1.10
        """
        pass

    def put(self, localpath, remotepath, callback=None, confirm=True):
        """
        Copy a local file (``localpath``) to the SFTP server as ``remotepath``.
        Any exception raised by operations will be passed through.  This
        method is primarily provided as a convenience.

        The SFTP operations use pipelining for speed.

        :param str localpath: the local file to copy
        :param str remotepath: the destination path on the SFTP server. Note
            that the filename should be included. Only specifying a directory
            may result in an error.
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size

        :return: an `.SFTPAttributes` object containing attributes about the
            given file

        .. versionadded:: 1.4
        .. versionchanged:: 1.7.4
            ``callback`` and rich attribute return value added.
        .. versionchanged:: 1.7.7
            ``confirm`` param added.
        """
        pass

    def getfo(self, remotepath, fl, callback=None, prefetch=True, max_concurrent_prefetch_requests=None):
        """
        Copy a remote file (``remotepath``) from the SFTP server and write to
        an open file or file-like object, ``fl``.  Any exception raised by
        operations will be passed through.  This method is primarily provided
        as a convenience.

        :param object remotepath: opened file or file-like object to copy to
        :param str fl:
            the destination path on the local host or open file object
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred
        :param bool prefetch:
            controls whether prefetching is performed (default: True)
        :param int max_concurrent_prefetch_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.
        :return: the `number <int>` of bytes written to the opened file object

        .. versionadded:: 1.10
        .. versionchanged:: 2.8
            Added the ``prefetch`` keyword argument.
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        """
        pass

    def get(self, remotepath, localpath, callback=None, prefetch=True, max_concurrent_prefetch_requests=None):
        """
        Copy a remote file (``remotepath``) from the SFTP server to the local
        host as ``localpath``.  Any exception raised by operations will be
        passed through.  This method is primarily provided as a convenience.

        :param str remotepath: the remote file to copy
        :param str localpath: the destination path on the local host
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred
        :param bool prefetch:
            controls whether prefetching is performed (default: True)
        :param int max_concurrent_prefetch_requests:
            The maximum number of concurrent read requests to prefetch.
            When this is ``None`` (the default), do not limit the number of
            concurrent prefetch requests. Note: OpenSSH's sftp internally
            imposes a limit of 64 concurrent requests, while Paramiko imposes
            no limit by default; consider setting a limit if a file can be
            successfully received with sftp but hangs with Paramiko.

        .. versionadded:: 1.4
        .. versionchanged:: 1.7.4
            Added the ``callback`` param
        .. versionchanged:: 2.8
            Added the ``prefetch`` keyword argument.
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        """
        pass

    def _convert_status(self, msg):
        """
        Raises EOFError or IOError on error status; otherwise does nothing.
        """
        pass

    def _adjust_cwd(self, path):
        """
        Return an adjusted path if we're emulating a "current working
        directory" for the server.
        """
        pass

class SFTP(SFTPClient):
    """
    An alias for `.SFTPClient` for backwards compatibility.
    """
    pass
