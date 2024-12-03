import stat
import time
from paramiko.common import x80000000, o700, o70, xffffffff

class SFTPAttributes:
    """
    Representation of the attributes of a file (or proxied file) for SFTP in
    client or server mode.  It attempts to mirror the object returned by
    `os.stat` as closely as possible, so it may have the following fields,
    with the same meanings as those returned by an `os.stat` object:

        - ``st_size``
        - ``st_uid``
        - ``st_gid``
        - ``st_mode``
        - ``st_atime``
        - ``st_mtime``

    Because SFTP allows flags to have other arbitrary named attributes, these
    are stored in a dict named ``attr``.  Occasionally, the filename is also
    stored, in ``filename``.
    """
    FLAG_SIZE = 1
    FLAG_UIDGID = 2
    FLAG_PERMISSIONS = 4
    FLAG_AMTIME = 8
    FLAG_EXTENDED = x80000000

    def __init__(self):
        """
        Create a new (empty) SFTPAttributes object.  All fields will be empty.
        """
        self._flags = 0
        self.st_size = None
        self.st_uid = None
        self.st_gid = None
        self.st_mode = None
        self.st_atime = None
        self.st_mtime = None
        self.attr = {}

    @classmethod
    def from_stat(cls, obj, filename=None):
        """
        Create an `.SFTPAttributes` object from an existing ``stat`` object (an
        object returned by `os.stat`).

        :param object obj: an object returned by `os.stat` (or equivalent).
        :param str filename: the filename associated with this file.
        :return: new `.SFTPAttributes` object with the same attribute fields.
        """
        attr = cls()
        attr.st_size = getattr(obj, 'st_size', None)
        attr.st_uid = getattr(obj, 'st_uid', None)
        attr.st_gid = getattr(obj, 'st_gid', None)
        attr.st_mode = getattr(obj, 'st_mode', None)
        attr.st_atime = getattr(obj, 'st_atime', None)
        attr.st_mtime = getattr(obj, 'st_mtime', None)
        if filename is not None:
            attr.filename = filename
        
        # Set flags based on which attributes are present
        if attr.st_size is not None:
            attr._flags |= cls.FLAG_SIZE
        if attr.st_uid is not None and attr.st_gid is not None:
            attr._flags |= cls.FLAG_UIDGID
        if attr.st_mode is not None:
            attr._flags |= cls.FLAG_PERMISSIONS
        if attr.st_atime is not None and attr.st_mtime is not None:
            attr._flags |= cls.FLAG_AMTIME
        
        return attr

    def __repr__(self):
        return '<SFTPAttributes: {}>'.format(self._debug_str())

    def __str__(self):
        """create a unix-style long description of the file (like ls -l)"""
        if self.st_mode is not None:
            kind = stat.S_IFMT(self.st_mode)
            if kind == stat.S_IFIFO:
                ks = 'p'
            elif kind == stat.S_IFCHR:
                ks = 'c'
            elif kind == stat.S_IFDIR:
                ks = 'd'
            elif kind == stat.S_IFBLK:
                ks = 'b'
            elif kind == stat.S_IFREG:
                ks = '-'
            elif kind == stat.S_IFLNK:
                ks = 'l'
            elif kind == stat.S_IFSOCK:
                ks = 's'
            else:
                ks = '?'
            ks += self._rwx((self.st_mode & o700) >> 6, self.st_mode & stat.S_ISUID)
            ks += self._rwx((self.st_mode & o70) >> 3, self.st_mode & stat.S_ISGID)
            ks += self._rwx(self.st_mode & 7, self.st_mode & stat.S_ISVTX, True)
        else:
            ks = '?---------'
        if self.st_mtime is None or self.st_mtime == xffffffff:
            datestr = '(unknown date)'
        else:
            time_tuple = time.localtime(self.st_mtime)
            if abs(time.time() - self.st_mtime) > 15552000:
                datestr = time.strftime('%d %b %Y', time_tuple)
            else:
                datestr = time.strftime('%d %b %H:%M', time_tuple)
        filename = getattr(self, 'filename', '?')
        uid = self.st_uid
        gid = self.st_gid
        size = self.st_size
        if uid is None:
            uid = 0
        if gid is None:
            gid = 0
        if size is None:
            size = 0
        return '%s   1 %-8d %-8d %8d %-12s %s' % (ks, uid, gid, size, datestr, filename)
