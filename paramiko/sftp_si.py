"""
An interface to override for SFTP server support.
"""
import os
import sys
from paramiko.sftp import (
    SFTP_OK, SFTP_EOF, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED, SFTP_FAILURE,
    SFTP_BAD_MESSAGE, SFTP_NO_CONNECTION, SFTP_CONNECTION_LOST, SFTP_OP_UNSUPPORTED
)
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle

class SFTPServerInterface:
    """
    This class defines an interface for controlling the behavior of paramiko
    when using the `.SFTPServer` subsystem to provide an SFTP server.

    Methods on this class are called from the SFTP session's thread, so you can
    block as long as necessary without affecting other sessions (even other
    SFTP sessions).  However, raising an exception will usually cause the SFTP
    session to abruptly end, so you will usually want to catch exceptions and
    return an appropriate error code.

    All paths are in string form instead of unicode because not all SFTP
    clients & servers obey the requirement that paths be encoded in UTF-8.
    """

    def __init__(self, server, *args, **kwargs):
        """
        Create a new SFTPServerInterface object.  This method does nothing by
        default and is meant to be overridden by subclasses.

        :param .ServerInterface server:
            the server object associated with this channel and SFTP subsystem
        """
        super().__init__(*args, **kwargs)

    def session_started(self):
        """
        The SFTP server session has just started.  This method is meant to be
        overridden to perform any necessary setup before handling callbacks
        from SFTP operations.
        """
        self.logger.info("SFTP session started")

    def session_ended(self):
        """
        The SFTP server session has just ended, either cleanly or via an
        exception.  This method is meant to be overridden to perform any
        necessary cleanup before this `.SFTPServerInterface` object is
        destroyed.
        """
        self.logger.info("SFTP session ended")

    def open(self, path, flags, attr):
        """
        Open a file on the server and create a handle for future operations
        on that file.  On success, a new object subclassed from `.SFTPHandle`
        should be returned.  This handle will be used for future operations
        on the file (read, write, etc).  On failure, an error code such as
        ``SFTP_PERMISSION_DENIED`` should be returned.

        ``flags`` contains the requested mode for opening (read-only,
        write-append, etc) as a bitset of flags from the ``os`` module:

            - ``os.O_RDONLY``
            - ``os.O_WRONLY``
            - ``os.O_RDWR``
            - ``os.O_APPEND``
            - ``os.O_CREAT``
            - ``os.O_TRUNC``
            - ``os.O_EXCL``

        (One of ``os.O_RDONLY``, ``os.O_WRONLY``, or ``os.O_RDWR`` will always
        be set.)

        The ``attr`` object contains requested attributes of the file if it
        has to be created.  Some or all attribute fields may be missing if
        the client didn't specify them.

        .. note:: The SFTP protocol defines all files to be in "binary" mode.
            There is no equivalent to Python's "text" mode.

        :param str path:
            the requested path (relative or absolute) of the file to be opened.
        :param int flags:
            flags or'd together from the ``os`` module indicating the requested
            mode for opening the file.
        :param .SFTPAttributes attr:
            requested attributes of the file if it is newly created.
        :return: a new `.SFTPHandle` or error code.
        """
        try:
            binary_flag = 'b'
            mode = 'r'  # Default to read mode
            if flags & os.O_WRONLY:
                mode = 'w'
            elif flags & os.O_RDWR:
                mode = 'r+'
            if flags & os.O_APPEND:
                mode = 'a' if 'w' not in mode else mode.replace('w', 'a')
            if flags & os.O_CREAT:
                mode += '+'
            
            mode += binary_flag
            
            f = open(path, mode)
            return SFTPHandle(f)
        except IOError as e:
            return SFTP_PERMISSION_DENIED
        except Exception as e:
            return SFTP_FAILURE

    def list_folder(self, path):
        """
        Return a list of files within a given folder.  The ``path`` will use
        posix notation (``"/"`` separates folder names) and may be an absolute
        or relative path.

        The list of files is expected to be a list of `.SFTPAttributes`
        objects, which are similar in structure to the objects returned by
        ``os.stat``.  In addition, each object should have its ``filename``
        field filled in, since this is important to a directory listing and
        not normally present in ``os.stat`` results.  The method
        `.SFTPAttributes.from_stat` will usually do what you want.

        In case of an error, you should return one of the ``SFTP_*`` error
        codes, such as ``SFTP_PERMISSION_DENIED``.

        :param str path: the requested path (relative or absolute) to be
            listed.
        :return:
            a list of the files in the given folder, using `.SFTPAttributes`
            objects.

        .. note::
            You should normalize the given ``path`` first (see the `os.path`
            module) and check appropriate permissions before returning the list
            of files.  Be careful of malicious clients attempting to use
            relative paths to escape restricted folders, if you're doing a
            direct translation from the SFTP server path to your local
            filesystem.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            if not os.path.isdir(normalized_path):
                return SFTP_NO_SUCH_FILE
            
            file_list = []
            for filename in os.listdir(normalized_path):
                filepath = os.path.join(normalized_path, filename)
                attr = SFTPAttributes.from_stat(os.stat(filepath))
                attr.filename = filename
                file_list.append(attr)
            
            return file_list
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def stat(self, path):
        """
        Return an `.SFTPAttributes` object for a path on the server, or an
        error code.  If your server supports symbolic links (also known as
        "aliases"), you should follow them.  (`lstat` is the corresponding
        call that doesn't follow symlinks/aliases.)

        :param str path:
            the requested path (relative or absolute) to fetch file statistics
            for.
        :return:
            an `.SFTPAttributes` object for the given file, or an SFTP error
            code (like ``SFTP_PERMISSION_DENIED``).
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            return SFTPAttributes.from_stat(os.stat(normalized_path))
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def lstat(self, path):
        """
        Return an `.SFTPAttributes` object for a path on the server, or an
        error code.  If your server supports symbolic links (also known as
        "aliases"), you should not follow them -- instead, you should
        return data on the symlink or alias itself.  (`stat` is the
        corresponding call that follows symlinks/aliases.)

        :param str path:
            the requested path (relative or absolute) to fetch file statistics
            for.
        :type path: str
        :return:
            an `.SFTPAttributes` object for the given file, or an SFTP error
            code (like ``SFTP_PERMISSION_DENIED``).
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            return SFTPAttributes.from_stat(os.lstat(normalized_path))
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def remove(self, path):
        """
        Delete a file, if possible.

        :param str path:
            the requested path (relative or absolute) of the file to delete.
        :return: an SFTP error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            os.remove(normalized_path)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except IsADirectoryError:
            return SFTP_FAILURE
        except Exception:
            return SFTP_FAILURE

    def rename(self, oldpath, newpath):
        """
        Rename (or move) a file.  The SFTP specification implies that this
        method can be used to move an existing file into a different folder,
        and since there's no other (easy) way to move files via SFTP, it's
        probably a good idea to implement "move" in this method too, even for
        files that cross disk partition boundaries, if at all possible.

        .. note:: You should return an error if a file with the same name as
            ``newpath`` already exists.  (The rename operation should be
            non-desctructive.)

        .. note::
            This method implements 'standard' SFTP ``RENAME`` behavior; those
            seeking the OpenSSH "POSIX rename" extension behavior should use
            `posix_rename`.

        :param str oldpath:
            the requested path (relative or absolute) of the existing file.
        :param str newpath: the requested new path of the file.
        :return: an SFTP error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_oldpath = os.path.normpath(os.path.join('/', oldpath))
            normalized_newpath = os.path.normpath(os.path.join('/', newpath))
            
            if os.path.exists(normalized_newpath):
                return SFTP_FAILURE
            
            os.rename(normalized_oldpath, normalized_newpath)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def posix_rename(self, oldpath, newpath):
        """
        Rename (or move) a file, following posix conventions. If newpath
        already exists, it will be overwritten.

        :param str oldpath:
            the requested path (relative or absolute) of the existing file.
        :param str newpath: the requested new path of the file.
        :return: an SFTP error code `int` like ``SFTP_OK``.

        :versionadded: 2.2
        """
        try:
            normalized_oldpath = os.path.normpath(os.path.join('/', oldpath))
            normalized_newpath = os.path.normpath(os.path.join('/', newpath))
            
            os.replace(normalized_oldpath, normalized_newpath)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def mkdir(self, path, attr):
        """
        Create a new directory with the given attributes.  The ``attr``
        object may be considered a "hint" and ignored.

        The ``attr`` object will contain only those fields provided by the
        client in its request, so you should use ``hasattr`` to check for
        the presence of fields before using them.  In some cases, the ``attr``
        object may be completely empty.

        :param str path:
            requested path (relative or absolute) of the new folder.
        :param .SFTPAttributes attr: requested attributes of the new folder.
        :return: an SFTP error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            os.mkdir(normalized_path)
            
            if hasattr(attr, 'st_mode'):
                os.chmod(normalized_path, attr.st_mode)
            
            return SFTP_OK
        except FileExistsError:
            return SFTP_FAILURE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def rmdir(self, path):
        """
        Remove a directory if it exists.  The ``path`` should refer to an
        existing, empty folder -- otherwise this method should return an
        error.

        :param str path:
            requested path (relative or absolute) of the folder to remove.
        :return: an SFTP error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            os.rmdir(normalized_path)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except OSError:  # Directory not empty
            return SFTP_FAILURE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def chattr(self, path, attr):
        """
        Change the attributes of a file.  The ``attr`` object will contain
        only those fields provided by the client in its request, so you
        should check for the presence of fields before using them.

        :param str path:
            requested path (relative or absolute) of the file to change.
        :param attr:
            requested attributes to change on the file (an `.SFTPAttributes`
            object)
        :return: an error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            
            if hasattr(attr, 'st_mode'):
                os.chmod(normalized_path, attr.st_mode)
            
            if hasattr(attr, 'st_uid') and hasattr(attr, 'st_gid'):
                os.chown(normalized_path, attr.st_uid, attr.st_gid)
            
            if hasattr(attr, 'st_atime') and hasattr(attr, 'st_mtime'):
                os.utime(normalized_path, (attr.st_atime, attr.st_mtime))
            
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def canonicalize(self, path):
        """
        Return the canonical form of a path on the server.  For example,
        if the server's home folder is ``/home/foo``, the path
        ``"../betty"`` would be canonicalized to ``"/home/betty"``.  Note
        the obvious security issues: if you're serving files only from a
        specific folder, you probably don't want this method to reveal path
        names outside that folder.

        You may find the Python methods in ``os.path`` useful, especially
        ``os.path.normpath`` and ``os.path.realpath``.

        The default implementation returns ``os.path.normpath('/' + path)``.
        """
        return os.path.normpath('/' + path)

    def readlink(self, path):
        """
        Return the target of a symbolic link (or shortcut) on the server.
        If the specified path doesn't refer to a symbolic link, an error
        should be returned.

        :param str path: path (relative or absolute) of the symbolic link.
        :return:
            the target `str` path of the symbolic link, or an error code like
            ``SFTP_NO_SUCH_FILE``.
        """
        try:
            normalized_path = os.path.normpath(os.path.join('/', path))
            target = os.readlink(normalized_path)
            return target
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except OSError:  # Not a symbolic link
            return SFTP_FAILURE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE

    def symlink(self, target_path, path):
        """
        Create a symbolic link on the server, as new pathname ``path``,
        with ``target_path`` as the target of the link.

        :param str target_path:
            path (relative or absolute) of the target for this new symbolic
            link.
        :param str path:
            path (relative or absolute) of the symbolic link to create.
        :return: an error code `int` like ``SFTP_OK``.
        """
        try:
            normalized_target_path = os.path.normpath(os.path.join('/', target_path))
            normalized_path = os.path.normpath(os.path.join('/', path))
            os.symlink(normalized_target_path, normalized_path)
            return SFTP_OK
        except FileExistsError:
            return SFTP_FAILURE
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except Exception:
            return SFTP_FAILURE
