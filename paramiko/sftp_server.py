"""
Server-mode SFTP support.
"""
import os
import errno
import errno
import sys
from hashlib import md5, sha1
from paramiko import util
from paramiko.sftp import BaseSFTP, Message, SFTP_FAILURE, SFTP_PERMISSION_DENIED, SFTP_NO_SUCH_FILE, int64
from paramiko.sftp_si import SFTPServerInterface
from paramiko.sftp_attr import SFTPAttributes
from paramiko.common import DEBUG
from paramiko.server import SubsystemHandler
from paramiko.util import b
from paramiko.sftp import CMD_HANDLE, SFTP_DESC, CMD_STATUS, SFTP_EOF, CMD_NAME, SFTP_BAD_MESSAGE, CMD_EXTENDED_REPLY, SFTP_FLAG_READ, SFTP_FLAG_WRITE, SFTP_FLAG_APPEND, SFTP_FLAG_CREATE, SFTP_FLAG_TRUNC, SFTP_FLAG_EXCL, CMD_NAMES, CMD_OPEN, CMD_CLOSE, SFTP_OK, CMD_READ, CMD_DATA, CMD_WRITE, CMD_REMOVE, CMD_RENAME, CMD_MKDIR, CMD_RMDIR, CMD_OPENDIR, CMD_READDIR, CMD_STAT, CMD_ATTRS, CMD_LSTAT, CMD_FSTAT, CMD_SETSTAT, CMD_FSETSTAT, CMD_READLINK, CMD_SYMLINK, CMD_REALPATH, CMD_EXTENDED, SFTP_OP_UNSUPPORTED
_hash_class = {'sha1': sha1, 'md5': md5}

class SFTPServer(BaseSFTP, SubsystemHandler):
    """
    Server-side SFTP subsystem support.  Since this is a `.SubsystemHandler`,
    it can be (and is meant to be) set as the handler for ``"sftp"`` requests.
    Use `.Transport.set_subsystem_handler` to activate this class.
    """

    def __init__(self, channel, name, server, sftp_si=SFTPServerInterface, *args, **kwargs):
        """
        The constructor for SFTPServer is meant to be called from within the
        `.Transport` as a subsystem handler.  ``server`` and any additional
        parameters or keyword parameters are passed from the original call to
        `.Transport.set_subsystem_handler`.

        :param .Channel channel: channel passed from the `.Transport`.
        :param str name: name of the requested subsystem.
        :param .ServerInterface server:
            the server object associated with this channel and subsystem
        :param sftp_si:
            a subclass of `.SFTPServerInterface` to use for handling individual
            requests.
        """
        BaseSFTP.__init__(self)
        SubsystemHandler.__init__(self, channel, name, server)
        transport = channel.get_transport()
        self.logger = util.get_logger(transport.get_log_channel() + '.sftp')
        self.ultra_debug = transport.get_hexdump()
        self.next_handle = 1
        self.file_table = {}
        self.folder_table = {}
        self.server = sftp_si(server, *args, **kwargs)

    @staticmethod
    def convert_errno(e):
        """
        Convert an errno value (as from an ``OSError`` or ``IOError``) into a
        standard SFTP result code.  This is a convenience function for trapping
        exceptions in server code and returning an appropriate result.

        :param int e: an errno code, as from ``OSError.errno``.
        :return: an `int` SFTP error code like ``SFTP_NO_SUCH_FILE``.
        """
        if e == errno.EACCES:
            return SFTP_PERMISSION_DENIED
        elif e == errno.ENOENT:
            return SFTP_NO_SUCH_FILE
        elif e == errno.ENOTDIR:
            return SFTP_NO_SUCH_FILE
        else:
            return SFTP_FAILURE

    @staticmethod
    def set_file_attr(filename, attr):
        """
        Change a file's attributes on the local filesystem.  The contents of
        ``attr`` are used to change the permissions, owner, group ownership,
        and/or modification & access time of the file, depending on which
        attributes are present in ``attr``.

        This is meant to be a handy helper function for translating SFTP file
        requests into local file operations.

        :param str filename:
            name of the file to alter (should usually be an absolute path).
        :param .SFTPAttributes attr: attributes to change.
        """
        if attr._flags & attr.FLAG_PERMISSIONS:
            os.chmod(filename, attr.st_mode)
        if attr._flags & attr.FLAG_UIDGID:
            os.chown(filename, attr.st_uid, attr.st_gid)
        if attr._flags & attr.FLAG_AMTIME:
            os.utime(filename, (attr.st_atime, attr.st_mtime))

    def _convert_pflags(self, pflags):
        """convert SFTP-style open() flags to Python's os.open() flags"""
        flags = 0
        if pflags & SFTP_FLAG_READ:
            flags |= os.O_RDONLY
        if pflags & SFTP_FLAG_WRITE:
            flags |= os.O_WRONLY
        if pflags & SFTP_FLAG_APPEND:
            flags |= os.O_APPEND
        if pflags & SFTP_FLAG_CREATE:
            flags |= os.O_CREAT
        if pflags & SFTP_FLAG_TRUNC:
            flags |= os.O_TRUNC
        if pflags & SFTP_FLAG_EXCL:
            flags |= os.O_EXCL
        return flags
from paramiko.sftp_handle import SFTPHandle
