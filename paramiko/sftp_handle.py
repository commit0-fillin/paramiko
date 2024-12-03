"""
Abstraction of an SFTP file handle (for server mode).
"""
import os
from paramiko.sftp import SFTP_OP_UNSUPPORTED, SFTP_OK
from paramiko.util import ClosingContextManager

class SFTPHandle(ClosingContextManager):
    """
    Abstract object representing a handle to an open file (or folder) in an
    SFTP server implementation.  Each handle has a string representation used
    by the client to refer to the underlying file.

    Server implementations can (and should) subclass SFTPHandle to implement
    features of a file handle, like `stat` or `chattr`.

    Instances of this class may be used as context managers.
    """

    def __init__(self, flags=0):
        """
        Create a new file handle representing a local file being served over
        SFTP.  If ``flags`` is passed in, it's used to determine if the file
        is open in append mode.

        :param int flags: optional flags as passed to
            `.SFTPServerInterface.open`
        """
        self.__flags = flags
        self.__name = None
        self.__files = {}
        self.__tell = None

    def close(self):
        """
        When a client closes a file, this method is called on the handle.
        Normally you would use this method to close the underlying OS level
        file object(s).

        The default implementation checks for attributes on ``self`` named
        ``readfile`` and/or ``writefile``, and if either or both are present,
        their ``close()`` methods are called.  This means that if you are
        using the default implementations of `read` and `write`, this
        method's default implementation should be fine also.
        """
        if hasattr(self, 'readfile'):
            self.readfile.close()
        if hasattr(self, 'writefile'):
            self.writefile.close()

    def read(self, offset, length):
        """
        Read up to ``length`` bytes from this file, starting at position
        ``offset``.  The offset may be a Python long, since SFTP allows it
        to be 64 bits.

        If the end of the file has been reached, this method may return an
        empty string to signify EOF, or it may also return ``SFTP_EOF``.

        The default implementation checks for an attribute on ``self`` named
        ``readfile``, and if present, performs the read operation on the Python
        file-like object found there.  (This is meant as a time saver for the
        common case where you are wrapping a Python file object.)

        :param offset: position in the file to start reading from.
        :param int length: number of bytes to attempt to read.
        :return: the `bytes` read, or an error code `int`.
        """
        if hasattr(self, 'readfile'):
            self.readfile.seek(offset)
            return self.readfile.read(length)
        return SFTP_OP_UNSUPPORTED

    def write(self, offset, data):
        """
        Write ``data`` into this file at position ``offset``.  Extending the
        file past its original end is expected.  Unlike Python's normal
        ``write()`` methods, this method cannot do a partial write: it must
        write all of ``data`` or else return an error.

        The default implementation checks for an attribute on ``self`` named
        ``writefile``, and if present, performs the write operation on the
        Python file-like object found there.  The attribute is named
        differently from ``readfile`` to make it easy to implement read-only
        (or write-only) files, but if both attributes are present, they should
        refer to the same file.

        :param offset: position in the file to start reading from.
        :param bytes data: data to write into the file.
        :return: an SFTP error code like ``SFTP_OK``.
        """
        if hasattr(self, 'writefile'):
            self.writefile.seek(offset)
            self.writefile.write(data)
            return SFTP_OK
        return SFTP_OP_UNSUPPORTED

    def stat(self):
        """
        Return an `.SFTPAttributes` object referring to this open file, or an
        error code.  This is equivalent to `.SFTPServerInterface.stat`, except
        it's called on an open file instead of a path.

        :return:
            an attributes object for the given file, or an SFTP error code
            (like ``SFTP_PERMISSION_DENIED``).
        :rtype: `.SFTPAttributes` or error code
        """
        if hasattr(self, 'readfile'):
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        elif hasattr(self, 'writefile'):
            return SFTPAttributes.from_stat(os.fstat(self.writefile.fileno()))
        return SFTP_OP_UNSUPPORTED

    def chattr(self, attr):
        """
        Change the attributes of this file.  The ``attr`` object will contain
        only those fields provided by the client in its request, so you should
        check for the presence of fields before using them.

        :param .SFTPAttributes attr: the attributes to change on this file.
        :return: an `int` error code like ``SFTP_OK``.
        """
        file_obj = getattr(self, 'readfile', None) or getattr(self, 'writefile', None)
        if file_obj:
            try:
                if attr._flags & attr.FLAG_PERMISSIONS:
                    os.chmod(file_obj.name, attr.st_mode)
                if attr._flags & attr.FLAG_UIDGID:
                    os.chown(file_obj.name, attr.st_uid, attr.st_gid)
                if attr._flags & attr.FLAG_AMTIME:
                    os.utime(file_obj.name, (attr.st_atime, attr.st_mtime))
                return SFTP_OK
            except OSError:
                return SFTP_PERMISSION_DENIED
        return SFTP_OP_UNSUPPORTED

    def _set_files(self, files):
        """
        Used by the SFTP server code to cache a directory listing.  (In
        the SFTP protocol, listing a directory is a multi-stage process
        requiring a temporary handle.)
        """
        self.__files = files

    def _get_next_files(self):
        """
        Used by the SFTP server code to retrieve a cached directory
        listing.
        """
        return self.__files
from paramiko.sftp_server import SFTPServer
