"""
SFTP file object
"""
from binascii import hexlify
from collections import deque
import socket
import threading
import time
from paramiko.common import DEBUG, io_sleep
from paramiko.file import BufferedFile
from paramiko.util import u
from paramiko.sftp import CMD_CLOSE, CMD_READ, CMD_DATA, SFTPError, CMD_WRITE, CMD_STATUS, CMD_FSTAT, CMD_ATTRS, CMD_FSETSTAT, CMD_EXTENDED, int64
from paramiko.sftp_attr import SFTPAttributes

class SFTPFile(BufferedFile):
    """
    Proxy object for a file on the remote server, in client mode SFTP.

    Instances of this class may be used as context managers in the same way
    that built-in Python file objects are.
    """
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)
        self.pipelined = False
        self._prefetching = False
        self._prefetch_done = False
        self._prefetch_data = {}
        self._prefetch_extents = {}
        self._prefetch_lock = threading.Lock()
        self._saved_exception = None
        self._reqs = deque()

    def __del__(self):
        self._close(async_=True)

    def close(self):
        """
        Close the file.
        """
        self._close()

    def _data_in_prefetch_buffers(self, offset):
        """
        if a block of data is present in the prefetch buffers, at the given
        offset, return the offset of the relevant prefetch buffer.  otherwise,
        return None.  this guarantees nothing about the number of bytes
        collected in the prefetch buffer so far.
        """
        with self._prefetch_lock:
            for file_offset, data in self._prefetch_data.items():
                if file_offset <= offset < file_offset + len(data):
                    return file_offset
        return None

    def _read_prefetch(self, size):
        """
        read data out of the prefetch buffer, if possible.  if the data isn't
        in the buffer, return None.  otherwise, behaves like a normal read.
        """
        with self._prefetch_lock:
            for offset, data in self._prefetch_data.items():
                if offset <= self._pos < offset + len(data):
                    chunk = data[self._pos - offset : self._pos - offset + size]
                    self._pos += len(chunk)
                    return chunk
        return None

    def settimeout(self, timeout):
        """
        Set a timeout on read/write operations on the underlying socket or
        ssh `.Channel`.

        :param float timeout:
            seconds to wait for a pending read/write operation before raising
            ``socket.timeout``, or ``None`` for no timeout

        .. seealso:: `.Channel.settimeout`
        """
        self.sftp.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a `float`) associated with the
        socket or ssh `.Channel` used for this file.

        .. seealso:: `.Channel.gettimeout`
        """
        return self.sftp.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        `.Channel`.

        :param int blocking:
            0 to set non-blocking mode; non-0 to set blocking mode.

        .. seealso:: `.Channel.setblocking`
        """
        self.sftp.sock.setblocking(blocking)

    def seekable(self):
        """
        Check if the file supports random access.

        :return:
            `True` if the file supports random access. If `False`,
            :meth:`seek` will raise an exception
        """
        return True

    def seek(self, offset, whence=0):
        """
        Set the file's current position.

        See `file.seek` for details.
        """
        self._check_exception()
        if whence == self.SEEK_SET:
            new_pos = offset
        elif whence == self.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == self.SEEK_END:
            new_pos = self.stat().st_size + offset
        else:
            raise ValueError("Invalid whence")
        if new_pos < 0:
            raise IOError("Invalid argument")
        self._pos = new_pos

    def stat(self):
        """
        Retrieve information about this file from the remote system.  This is
        exactly like `.SFTPClient.stat`, except that it operates on an
        already-open file.

        :returns:
            an `.SFTPAttributes` object containing attributes about this file.
        """
        self._check_exception()
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError("Expected attributes")
        return SFTPAttributes._from_msg(msg)

    def chmod(self, mode):
        """
        Change the mode (permissions) of this file.  The permissions are
        unix-style and identical to those used by Python's `os.chmod`
        function.

        :param int mode: new permissions
        """
        self._check_exception()
        attr = SFTPAttributes()
        attr.st_mode = mode
        self.sftp._request(CMD_FSETSTAT, self.handle + attr._pack())

    def chown(self, uid, gid):
        """
        Change the owner (``uid``) and group (``gid``) of this file.  As with
        Python's `os.chown` function, you must pass both arguments, so if you
        only want to change one, use `stat` first to retrieve the current
        owner and group.

        :param int uid: new owner's uid
        :param int gid: new group id
        """
        self._check_exception()
        attr = SFTPAttributes()
        attr.st_uid = uid
        attr.st_gid = gid
        self.sftp._request(CMD_FSETSTAT, self.handle + attr._pack())

    def utime(self, times):
        """
        Set the access and modified times of this file.  If
        ``times`` is ``None``, then the file's access and modified times are
        set to the current time.  Otherwise, ``times`` must be a 2-tuple of
        numbers, of the form ``(atime, mtime)``, which is used to set the
        access and modified times, respectively.  This bizarre API is mimicked
        from Python for the sake of consistency -- I apologize.

        :param tuple times:
            ``None`` or a tuple of (access time, modified time) in standard
            internet epoch time (seconds since 01 January 1970 GMT)
        """
        self._check_exception()
        if times is None:
            times = (time.time(), time.time())
        attr = SFTPAttributes()
        attr.st_atime = int(times[0])
        attr.st_mtime = int(times[1])
        self.sftp._request(CMD_FSETSTAT, self.handle + attr._pack())

    def truncate(self, size):
        """
        Change the size of this file.  This usually extends
        or shrinks the size of the file, just like the ``truncate()`` method on
        Python file objects.

        :param size: the new size of the file
        """
        self._check_exception()
        attr = SFTPAttributes()
        attr.st_size = size
        self.sftp._request(CMD_FSETSTAT, self.handle + attr._pack())

    def check(self, hash_algorithm, offset=0, length=0, block_size=0):
        """
        Ask the server for a hash of a section of this file.  This can be used
        to verify a successful upload or download, or for various rsync-like
        operations.

        The file is hashed from ``offset``, for ``length`` bytes.
        If ``length`` is 0, the remainder of the file is hashed.  Thus, if both
        ``offset`` and ``length`` are zero, the entire file is hashed.

        Normally, ``block_size`` will be 0 (the default), and this method will
        return a byte string representing the requested hash (for example, a
        string of length 16 for MD5, or 20 for SHA-1).  If a non-zero
        ``block_size`` is given, each chunk of the file (from ``offset`` to
        ``offset + length``) of ``block_size`` bytes is computed as a separate
        hash.  The hash results are all concatenated and returned as a single
        string.

        For example, ``check('sha1', 0, 1024, 512)`` will return a string of
        length 40.  The first 20 bytes will be the SHA-1 of the first 512 bytes
        of the file, and the last 20 bytes will be the SHA-1 of the next 512
        bytes.

        :param str hash_algorithm:
            the name of the hash algorithm to use (normally ``"sha1"`` or
            ``"md5"``)
        :param offset:
            offset into the file to begin hashing (0 means to start from the
            beginning)
        :param length:
            number of bytes to hash (0 means continue to the end of the file)
        :param int block_size:
            number of bytes to hash per result (must not be less than 256; 0
            means to compute only one hash of the entire segment)
        :return:
            `str` of bytes representing the hash of each block, concatenated
            together

        :raises:
            ``IOError`` -- if the server doesn't support the "check-file"
            extension, or possibly doesn't support the hash algorithm requested

        .. note:: Many (most?) servers don't support this extension yet.

        .. versionadded:: 1.4
        """
        self._check_exception()
        t, msg = self.sftp._request(CMD_EXTENDED, 'check-file',
                                    self.handle,
                                    hash_algorithm,
                                    long(offset),
                                    long(length),
                                    block_size)
        if t != CMD_EXTENDED_REPLY:
            raise SFTPError('Expected extended reply')
        return msg.get_string()

    def set_pipelined(self, pipelined=True):
        """
        Turn on/off the pipelining of write operations to this file.  When
        pipelining is on, paramiko won't wait for the server response after
        each write operation.  Instead, they're collected as they come in. At
        the first non-write operation (including `.close`), all remaining
        server responses are collected.  This means that if there was an error
        with one of your later writes, an exception might be thrown from within
        `.close` instead of `.write`.

        By default, files are not pipelined.

        :param bool pipelined:
            ``True`` if pipelining should be turned on for this file; ``False``
            otherwise

        .. versionadded:: 1.5
        """
        self.pipelined = pipelined

    def prefetch(self, file_size=None, max_concurrent_requests=None):
        """
        Pre-fetch the remaining contents of this file in anticipation of future
        `.read` calls.  If reading the entire file, pre-fetching can
        dramatically improve the download speed by avoiding roundtrip latency.
        The file's contents are incrementally buffered in a background thread.

        The prefetched data is stored in a buffer until read via the `.read`
        method.  Once data has been read, it's removed from the buffer.  The
        data may be read in a random order (using `.seek`); chunks of the
        buffer that haven't been read will continue to be buffered.

        :param int file_size:
            When this is ``None`` (the default), this method calls `stat` to
            determine the remote file size. In some situations, doing so can
            cause exceptions or hangs (see `#562
            <https://github.com/paramiko/paramiko/pull/562>`_); as a
            workaround, one may call `stat` explicitly and pass its value in
            via this parameter.
        :param int max_concurrent_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.

        .. versionadded:: 1.5.1
        .. versionchanged:: 1.16.0
            The ``file_size`` parameter was added (with no default value).
        .. versionchanged:: 1.16.1
            The ``file_size`` parameter was made optional for backwards
            compatibility.
        .. versionchanged:: 3.3
            Added ``max_concurrent_requests``.
        """
        if file_size is None:
            file_size = self.stat().st_size
        self._prefetching = True
        self._prefetch_done = False
        self._prefetch_data = {}
        self._prefetch_extents = {}

        def prefetch_thread():
            self._prefetch_thread_id = threading.get_ident()
            offset = self._pos
            while offset < file_size:
                if not self._prefetching:
                    break
                size = min(self.MAX_REQUEST_SIZE, file_size - offset)
                data = self.read(size, offset)
                if not data:
                    break
                with self._prefetch_lock:
                    self._prefetch_data[offset] = data
                    self._prefetch_extents[offset] = len(data)
                offset += len(data)
            self._prefetch_done = True

        max_concurrent_requests = max_concurrent_requests or 10
        prefetch_thread = threading.Thread(target=prefetch_thread)
        prefetch_thread.start()

    def readv(self, chunks, max_concurrent_prefetch_requests=None):
        """
        Read a set of blocks from the file by (offset, length).  This is more
        efficient than doing a series of `.seek` and `.read` calls, since the
        prefetch machinery is used to retrieve all the requested blocks at
        once.

        :param chunks:
            a list of ``(offset, length)`` tuples indicating which sections of
            the file to read
        :param int max_concurrent_prefetch_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.
        :return: a list of blocks read, in the same order as in ``chunks``

        .. versionadded:: 1.5.4
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        """
        self._check_exception()
        max_concurrent_requests = max_concurrent_prefetch_requests or 10
        blocks = []
        for offset, length in chunks:
            data = self._read_prefetch(length)
            if data is None:
                data = self.read(length, offset)
            blocks.append(data)
        return blocks

    def _check_exception(self):
        """if there's a saved exception, raise & clear it"""
        if self._saved_exception is not None:
            exc = self._saved_exception
            self._saved_exception = None
            raise exc
