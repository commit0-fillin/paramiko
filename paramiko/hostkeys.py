from base64 import encodebytes, decodebytes
import binascii
import os
import re
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.util import get_logger, constant_time_bytes_eq, b, u
from paramiko.ssh_exception import SSHException, InvalidHostKey

class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        self._entries = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (``"ssh-rsa"`` or ``"ssh-dss"``)
        :param .PKey key: the key to add
        """
        for entry in self._entries:
            if entry.hostnames == [hostname] and entry.key.get_name() == keytype:
                entry.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line)
                    if entry.key:
                        for hostname in entry.hostnames:
                            self.add(hostname, entry.key.get_name(), entry.key)
                except (ValueError, IndexError, InvalidHostKey):
                    continue

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, 'w') as f:
            for entry in self._entries:
                for hostname in entry.hostnames:
                    f.write(f"{hostname} {entry.key.get_name()} {entry.key.get_base64()}\n")

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.  The keytype will be either ``"ssh-rsa"`` or ``"ssh-dss"``.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """
        keys = {}
        for entry in self._entries:
            if self._hostname_matches(hostname, entry):
                keys[entry.key.get_name()] = entry.key
        return keys if keys else None

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        :returns bool:
        """
        for host in entry.hostnames:
            if host.startswith('|1|'):
                # This is a hashed hostname
                if self._compare_hash(hostname, host):
                    return True
            elif host == hostname:
                return True
        return False

    def _compare_hash(self, hostname, hashed_hostname):
        salt, hash_value = hashed_hostname[3:].split('|')
        salt = decodebytes(salt.encode('ascii'))
        hash_value = decodebytes(hash_value.encode('ascii'))
        hmac_obj = HMAC(salt, hostname.encode('utf-8'), sha1)
        return hmac_obj.digest() == hash_value

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        for entry in self._entries:
            if self._hostname_matches(hostname, entry):
                if entry.key == key:
                    return True
        return False

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if hostname in e.hostnames and e.key.get_name() == key_type:
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(20)
        else:
            if not isinstance(salt, bytes):
                salt = salt.encode('ascii')
            if len(salt) != 20:
                raise ValueError("Salt must be 20 bytes long")

        hmac_obj = HMAC(salt, hostname.encode('utf-8'), sha1)
        hostname_hash = hmac_obj.digest()

        return '|1|{}|{}'.format(
            encodebytes(salt).decode('ascii').strip(),
            encodebytes(hostname_hash).decode('ascii').strip()
        )

class InvalidHostKey(Exception):

    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)

class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None):
        self.valid = hostnames is not None and key is not None
        self.hostnames = hostnames
        self.key = key

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        fields = line.split()
        if len(fields) < 3:
            raise InvalidHostKey("Not enough fields: {}".format(line))

        hostnames = fields[0].split(',')
        keytype = fields[1]
        key = b(' '.join(fields[2:]))

        try:
            key = decodebytes(key.encode('ascii'))
        except:
            raise InvalidHostKey("Invalid key: {}".format(line))

        try:
            pkey = PKey.from_type_string(keytype, key)
        except UnknownKeyType:
            raise InvalidHostKey("Unknown key type: {}".format(keytype))

        return cls(hostnames, pkey)

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            return '{} {} {}\n'.format(
                ','.join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64()
            )
        return None

    def __repr__(self):
        return '<HostKeyEntry {!r}: {!r}>'.format(self.hostnames, self.key)
