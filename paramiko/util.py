"""
Useful functions used by the rest of paramiko.
"""
import sys
import struct
import traceback
import threading
import logging
from paramiko.common import DEBUG, zero_byte, xffffffff, max_byte, byte_ord, byte_chr
from paramiko.config import SSHConfig

def inflate_long(s, always_positive=False):
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    out = 0
    negative = 0
    if not always_positive and (len(s) > 0) and (byte_ord(s[0]) & 0x80):
        negative = 1
    if len(s) % 4:
        filler = zero_byte * (4 - len(s) % 4)
        s = filler + s
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack('>I', s[i:i+4])[0]
    if negative:
        out = (1 << (8 * len(s))) - out
        if out == 0:
            out = int(-1)
    return out

def deflate_long(n, add_sign_padding=True):
    """turns a long-int into a normalized byte string
    (adapted from Crypto.Util.number)"""
    # after much testing, this algorithm was deemed to be the fastest
    s = bytes()
    n = int(n)
    while (n != 0) and (n != -1):
        s = struct.pack('>I', n & xffffffff) + s
        n = n >> 32
    # strip off leading zeros, FFs
    for i in range(len(s)):
        if (s[i] != '\000') and (s[i] != '\xff'):
            break
    else:
        # degenerate case, n was either 0 or -1
        s = zero_byte
        if n == 0:
            i = 0
        else:
            i = 1
    s = s[i:]
    if add_sign_padding:
        if (n == 0) and (len(s) > 0) and (byte_ord(s[0]) & 0x80):
            s = zero_byte + s
        if (n < 0) and (len(s) > 0) and not (byte_ord(s[0]) & 0x80):
            s = max_byte + s
    return s

def generate_key_bytes(hash_alg, salt, key, nbytes):
    """
    Given a password, passphrase, or other human-source key, scramble it
    through a secure hash into some keyworthy bytes.  This specific algorithm
    is used for encrypting/decrypting private key files.

    :param function hash_alg: A function which creates a new hash object, such
        as ``hashlib.sha256``.
    :param salt: data to salt the hash with.
    :type bytes salt: Hash salt bytes.
    :param str key: human-entered password or passphrase.
    :param int nbytes: number of bytes to generate.
    :return: Key data, as `bytes`.
    """
    keydata = b""
    digest = b""
    if len(salt) > 8:
        salt = salt[:8]
    while nbytes > 0:
        hash_obj = hash_alg()
        if len(digest) > 0:
            hash_obj.update(digest)
        hash_obj.update(b(key))
        hash_obj.update(salt)
        digest = hash_obj.digest()
        size = min(nbytes, len(digest))
        keydata += digest[:size]
        nbytes -= size
    return keydata

def load_host_keys(filename):
    """
    Read a file of known SSH host keys, in the format used by openssh, and
    return a compound dict of ``hostname -> keytype ->`` `PKey
    <paramiko.pkey.PKey>`. The hostname may be an IP address or DNS name.  The
    keytype will be either ``"ssh-rsa"`` or ``"ssh-dss"``.

    This type of file unfortunately doesn't exist on Windows, but on posix,
    it will usually be stored in ``os.path.expanduser("~/.ssh/known_hosts")``.

    Since 1.5.3, this is just a wrapper around `.HostKeys`.

    :param str filename: name of the file to read host keys from
    :return:
        nested dict of `.PKey` objects, indexed by hostname and then keytype
    """
    from paramiko.hostkeys import HostKeys

    return HostKeys(filename)

def parse_ssh_config(file_obj):
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.

    .. deprecated:: 2.7
        Use `SSHConfig.from_file` instead.
    """
    return SSHConfig.from_file(file_obj)

def lookup_ssh_host_config(hostname, config):
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.
    """
    return config.lookup(hostname)
_g_thread_data = threading.local()
_g_thread_counter = 0
_g_thread_lock = threading.Lock()

def log_to_file(filename, level=DEBUG):
    """send paramiko logs to a logfile,
    if they're not already going somewhere"""
    l = logging.getLogger("paramiko")
    if len(l.handlers) > 0:
        return
    l.setLevel(level)
    handler = logging.FileHandler(filename)
    handler.setFormatter(
        logging.Formatter('%(levelname)-.3s [%(asctime)s.%(msecs)03d] thr=%(_threadid)-3d %(name)s: %(message)s',
                          '%Y%m%d-%H:%M:%S')
    )
    l.addHandler(handler)

class PFilter:
    pass
_pfilter = PFilter()

class ClosingContextManager:

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

def asbytes(s):
    """
    Coerce to bytes if possible or return unchanged.
    """
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('utf-8')
    else:
        return s

def b(s, encoding='utf8'):
    """cast unicode or bytes to bytes"""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode(encoding)
    else:
        raise TypeError("Expected unicode or bytes, got %r" % s)

def u(s, encoding='utf8'):
    """cast bytes or unicode to unicode"""
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode(encoding)
    else:
        raise TypeError("Expected unicode or bytes, got %r" % s)
