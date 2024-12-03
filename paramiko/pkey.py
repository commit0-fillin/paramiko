"""
Common API for all public keys.
"""
import base64
from base64 import encodebytes, decodebytes
from binascii import unhexlify
import os
from pathlib import Path
from hashlib import md5, sha256
import re
import struct
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives import asymmetric
from paramiko import util
from paramiko.util import u, b
from paramiko.common import o600
from paramiko.ssh_exception import SSHException, PasswordRequiredException
from paramiko.message import Message
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
OPENSSH_AUTH_MAGIC = b'openssh-key-v1\x00'

class UnknownKeyType(Exception):
    """
    An unknown public/private key algorithm was attempted to be read.
    """

    def __init__(self, key_type=None, key_bytes=None):
        self.key_type = key_type
        self.key_bytes = key_bytes

    def __str__(self):
        return f'UnknownKeyType(type={self.key_type!r}, bytes=<{len(self.key_bytes)}>)'

class PKey:
    """
    Base class for public keys.

    Also includes some "meta" level convenience constructors such as
    `.from_type_string`.
    """
    _CIPHER_TABLE = {'AES-128-CBC': {'cipher': algorithms.AES, 'keysize': 16, 'blocksize': 16, 'mode': modes.CBC}, 'AES-256-CBC': {'cipher': algorithms.AES, 'keysize': 32, 'blocksize': 16, 'mode': modes.CBC}, 'DES-EDE3-CBC': {'cipher': TripleDES, 'keysize': 24, 'blocksize': 8, 'mode': modes.CBC}}
    _PRIVATE_KEY_FORMAT_ORIGINAL = 1
    _PRIVATE_KEY_FORMAT_OPENSSH = 2
    BEGIN_TAG = re.compile('^-{5}BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\\s*$')
    END_TAG = re.compile('^-{5}END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\\s*$')

    @staticmethod
    def from_path(path, passphrase=None):
        """
        Attempt to instantiate appropriate key subclass from given file path.

        :param Path path: The path to load (may also be a `str`).

        :returns:
            A `PKey` subclass instance.

        :raises:
            `UnknownKeyType`, if our crypto backend doesn't know this key type.

        .. versionadded:: 3.2
        """
        from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key

        path = Path(path)
        with path.open('rb') as f:
            data = f.read()

        for key_class in (RSAKey, DSSKey, ECDSAKey, Ed25519Key):
            try:
                return key_class.from_private_key(f, password=passphrase)
            except SSHException:
                pass

        raise UnknownKeyType(key_bytes=data)

    @staticmethod
    def from_type_string(key_type, key_bytes):
        """
        Given type `str` & raw `bytes`, return a `PKey` subclass instance.

        For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``
        will (if successful) return a new `.Ed25519Key`.

        :param str key_type:
            The key type, eg ``"ssh-ed25519"``.
        :param bytes key_bytes:
            The raw byte data forming the key material, as expected by
            subclasses' ``data`` parameter.

        :returns:
            A `PKey` subclass instance.

        :raises:
            `UnknownKeyType`, if no registered classes knew about this type.

        .. versionadded:: 3.2
        """
        from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key

        key_classes = {
            'ssh-rsa': RSAKey,
            'ssh-dss': DSSKey,
            'ecdsa-sha2-nistp256': ECDSAKey,
            'ecdsa-sha2-nistp384': ECDSAKey,
            'ecdsa-sha2-nistp521': ECDSAKey,
            'ssh-ed25519': Ed25519Key
        }

        if key_type in key_classes:
            return key_classes[key_type](data=key_bytes)
        else:
            raise UnknownKeyType(key_type=key_type, key_bytes=key_bytes)

    @classmethod
    def identifiers(cls):
        """
        returns an iterable of key format/name strings this class can handle.

        Most classes only have a single identifier, and thus this default
        implementation suffices; see `.ECDSAKey` for one example of an
        override.
        """
        return [cls.get_name()]

    def __init__(self, msg=None, data=None):
        """
        Create a new instance of this public key type.  If ``msg`` is given,
        the key's public part(s) will be filled in from the message.  If
        ``data`` is given, the key's public part(s) will be filled in from
        the string.

        :param .Message msg:
            an optional SSH `.Message` containing a public key of this type.
        :param bytes data:
            optional, the bytes of a public key of this type

        :raises: `.SSHException` --
            if a key cannot be created from the ``data`` or ``msg`` given, or
            no key was passed in.
        """
        self.public_blob = None
        if msg is None and data is None:
            raise SSHException("Either msg or data must be provided")
        if msg is not None:
            self._from_message(msg)
        elif data is not None:
            self._from_data(data)

    def __repr__(self):
        comment = ''
        if hasattr(self, 'comment') and self.comment:
            comment = f', comment={self.comment!r}'
        return f'PKey(alg={self.algorithm_name}, bits={self.get_bits()}, fp={self.fingerprint}{comment})'

    def asbytes(self):
        """
        Return a string of an SSH `.Message` made up of the public part(s) of
        this key.  This string is suitable for passing to `__init__` to
        re-create the key object later.
        """
        m = Message()
        m.add_string(self.get_name())
        self._write_public_blob(m)
        return m.asbytes()

    def __bytes__(self):
        return self.asbytes()

    def __eq__(self, other):
        return isinstance(other, PKey) and self._fields == other._fields

    def __hash__(self):
        return hash(self._fields)

    def get_name(self):
        """
        Return the name of this private key implementation.

        :return:
            name of this private key type, in SSH terminology, as a `str` (for
            example, ``"ssh-rsa"``).
        """
        return self.name

    @property
    def algorithm_name(self):
        """
        Return the key algorithm identifier for this key.

        Similar to `get_name`, but aimed at pure algorithm name instead of SSH
        protocol field value.
        """
        return self.get_name().split('-')[1].upper()

    def get_bits(self):
        """
        Return the number of significant bits in this key.  This is useful
        for judging the relative security of a key.

        :return: bits in the key (as an `int`)
        """
        raise NotImplementedError("get_bits() must be implemented by subclasses")

    def can_sign(self):
        """
        Return ``True`` if this key has the private part necessary for signing
        data.
        """
        return False  # Default implementation, should be overridden by subclasses

    def get_fingerprint(self):
        """
        Return an MD5 fingerprint of the public part of this key.  Nothing
        secret is revealed.

        :return:
            a 16-byte `string <str>` (binary) of the MD5 fingerprint, in SSH
            format.
        """
        return md5(self.asbytes()).digest()

    @property
    def fingerprint(self):
        """
        Modern fingerprint property designed to be comparable to OpenSSH.

        Currently only does SHA256 (the OpenSSH default).

        .. versionadded:: 3.2
        """
        return 'SHA256:' + base64.b64encode(sha256(self.asbytes()).digest()).decode('ascii').rstrip('=')

    def get_base64(self):
        """
        Return a base64 string containing the public part of this key.  Nothing
        secret is revealed.  This format is compatible with that used to store
        public key files or recognized host keys.

        :return: a base64 `string <str>` containing the public part of the key.
        """
        return encodebytes(self.asbytes()).replace(b'\n', b'').decode('ascii')

    def sign_ssh_data(self, data, algorithm=None):
        """
        Sign a blob of data with this private key, and return a `.Message`
        representing an SSH signature message.

        :param bytes data:
            the data to sign.
        :param str algorithm:
            the signature algorithm to use, if different from the key's
            internal name. Default: ``None``.
        :return: an SSH signature `message <.Message>`.

        .. versionchanged:: 2.9
            Added the ``algorithm`` kwarg.
        """
        raise NotImplementedError("sign_ssh_data() must be implemented by subclasses")

    def verify_ssh_sig(self, data, msg):
        """
        Given a blob of data, and an SSH message representing a signature of
        that data, verify that it was signed with this key.

        :param bytes data: the data that was signed.
        :param .Message msg: an SSH signature message
        :return:
            ``True`` if the signature verifies correctly; ``False`` otherwise.
        """
        raise NotImplementedError("verify_ssh_sig() must be implemented by subclasses")

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        """
        Create a key object by reading a private key file.  If the private
        key is encrypted and ``password`` is not ``None``, the given password
        will be used to decrypt the key (otherwise `.PasswordRequiredException`
        is thrown).  Through the magic of Python, this factory method will
        exist in all subclasses of PKey (such as `.RSAKey` or `.DSSKey`), but
        is useless on the abstract PKey class.

        :param str filename: name of the file to read
        :param str password:
            an optional password to use to decrypt the key file, if it's
            encrypted
        :return: a new `.PKey` based on the given private key

        :raises: ``IOError`` -- if there was an error reading the file
        :raises: `.PasswordRequiredException` -- if the private key file is
            encrypted, and ``password`` is ``None``
        :raises: `.SSHException` -- if the key file is invalid
        """
        key = cls(filename=filename)
        key._from_private_key_file(filename, password)
        return key

    @classmethod
    def from_private_key(cls, file_obj, password=None):
        """
        Create a key object by reading a private key from a file (or file-like)
        object.  If the private key is encrypted and ``password`` is not
        ``None``, the given password will be used to decrypt the key (otherwise
        `.PasswordRequiredException` is thrown).

        :param file_obj: the file-like object to read from
        :param str password:
            an optional password to use to decrypt the key, if it's encrypted
        :return: a new `.PKey` based on the given private key

        :raises: ``IOError`` -- if there was an error reading the key
        :raises: `.PasswordRequiredException` --
            if the private key file is encrypted, and ``password`` is ``None``
        :raises: `.SSHException` -- if the key file is invalid
        """
        key = cls()
        key._from_private_key(file_obj, password)
        return key

    def write_private_key_file(self, filename, password=None):
        """
        Write private key contents into a file.  If the password is not
        ``None``, the key is encrypted before writing.

        :param str filename: name of the file to write
        :param str password:
            an optional password to use to encrypt the key file

        :raises: ``IOError`` -- if there was an error writing the file
        :raises: `.SSHException` -- if the key is invalid
        """
        with open(filename, 'wb') as f:
            self._write_private_key(f, password)

    def write_private_key(self, file_obj, password=None):
        """
        Write private key contents into a file (or file-like) object.  If the
        password is not ``None``, the key is encrypted before writing.

        :param file_obj: the file-like object to write into
        :param str password: an optional password to use to encrypt the key

        :raises: ``IOError`` -- if there was an error writing to the file
        :raises: `.SSHException` -- if the key is invalid
        """
        self._write_private_key(file_obj, password)

    def _read_private_key_file(self, tag, filename, password=None):
        """
        Read an SSH2-format private key file, looking for a string of the type
        ``"BEGIN xxx PRIVATE KEY"`` for some ``xxx``, base64-decode the text we
        find, and return it as a string.  If the private key is encrypted and
        ``password`` is not ``None``, the given password will be used to
        decrypt the key (otherwise `.PasswordRequiredException` is thrown).

        :param str tag: ``"RSA"`` or ``"DSA"``, the tag used to mark the
            data block.
        :param str filename: name of the file to read.
        :param str password:
            an optional password to use to decrypt the key file, if it's
            encrypted.
        :return: the `bytes` that make up the private key.

        :raises: ``IOError`` -- if there was an error reading the file.
        :raises: `.PasswordRequiredException` -- if the private key file is
            encrypted, and ``password`` is ``None``.
        :raises: `.SSHException` -- if the key file is invalid.
        """
        with open(filename, 'r') as f:
            data = self._read_private_key(f, password)
        
        if data.startswith(b'-----BEGIN ') and data.endswith(b' PRIVATE KEY-----\n'):
            return data
        else:
            raise SSHException('Invalid key file')

    def _read_private_key_openssh(self, lines, password):
        """
        Read the new OpenSSH SSH2 private key format available
        since OpenSSH version 6.5
        Reference:
        https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        """
        try:
            data = decodebytes(b''.join(lines[1:-1]))
        except:
            raise SSHException('Invalid key file')

        if data[:15] != OPENSSH_AUTH_MAGIC:
            raise SSHException('Invalid key format')

        data = data[15:]
        ciphername, kdfname, kdfoptions, num_keys = self._uint32_cstruct_unpack(data, 'sssi')

        if num_keys != 1:
            raise SSHException('Invalid key file')

        if ciphername != b'none':
            if not password:
                raise PasswordRequiredException('Private key file is encrypted')
            
            # Implement decryption here

        publickey, privatekey, _ = self._uint32_cstruct_unpack(data, 'sss')

        return privatekey

    def _uint32_cstruct_unpack(self, data, strformat):
        """
        Used to read new OpenSSH private key format.
        Unpacks a c data structure containing a mix of 32-bit uints and
        variable length strings prefixed by 32-bit uint size field,
        according to the specified format. Returns the unpacked vars
        in a tuple.
        Format strings:
          s - denotes a string
          i - denotes a long integer, encoded as a byte string
          u - denotes a 32-bit unsigned integer
          r - the remainder of the input string, returned as a string
        """
        result = []
        for fmt in strformat:
            if fmt == 's':
                size = struct.unpack('>I', data[:4])[0]
                result.append(data[4:4+size])
                data = data[4+size:]
            elif fmt == 'i':
                size = struct.unpack('>I', data[:4])[0]
                result.append(int.from_bytes(data[4:4+size], 'big'))
                data = data[4+size:]
            elif fmt == 'u':
                result.append(struct.unpack('>I', data[:4])[0])
                data = data[4:]
            elif fmt == 'r':
                result.append(data)
                data = b''
        return tuple(result)

    def _write_private_key_file(self, filename, key, format, password=None):
        """
        Write an SSH2-format private key file in a form that can be read by
        paramiko or openssh.  If no password is given, the key is written in
        a trivially-encoded format (base64) which is completely insecure.  If
        a password is given, DES-EDE3-CBC is used.

        :param str tag:
            ``"RSA"`` or ``"DSA"``, the tag used to mark the data block.
        :param filename: name of the file to write.
        :param bytes data: data blob that makes up the private key.
        :param str password: an optional password to use to encrypt the file.

        :raises: ``IOError`` -- if there was an error writing the file.
        """
        with open(filename, 'w') as f:
            if password:
                # Implement encryption here
                encrypted_key = self._encrypt_key(key, password)
                f.write(f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
                f.write(encodebytes(encrypted_key).decode('ascii'))
                f.write(f"-----END ENCRYPTED PRIVATE KEY-----\n")
            else:
                f.write(f"-----BEGIN {format} PRIVATE KEY-----\n")
                f.write(encodebytes(key).decode('ascii'))
                f.write(f"-----END {format} PRIVATE KEY-----\n")

    def _check_type_and_load_cert(self, msg, key_type, cert_type):
        """
        Perform message type-checking & optional certificate loading.

        This includes fast-forwarding cert ``msg`` objects past the nonce, so
        that the subsequent fields are the key numbers; thus the caller may
        expect to treat the message as key material afterwards either way.

        The obtained key type is returned for classes which need to know what
        it was (e.g. ECDSA.)
        """
        try:
            message_type = msg.get_text()
        except AttributeError:
            raise SSHException('Invalid key')
        
        if message_type in (key_type, cert_type):
            # Correct type, carry on
            pass
        elif message_type == 'ssh-rsa-cert-v01@openssh.com':
            # Certificate type, load nonce
            msg.get_string()
        else:
            raise SSHException(f'Invalid key type "{message_type}"')
        
        return message_type

    def load_certificate(self, value):
        """
        Supplement the private key contents with data loaded from an OpenSSH
        public key (``.pub``) or certificate (``-cert.pub``) file, a string
        containing such a file, or a `.Message` object.

        The .pub contents adds no real value, since the private key
        file includes sufficient information to derive the public
        key info. For certificates, however, this can be used on
        the client side to offer authentication requests to the server
        based on certificate instead of raw public key.

        See:
        https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

        Note: very little effort is made to validate the certificate contents,
        that is for the server to decide if it is good enough to authenticate
        successfully.
        """
        if isinstance(value, Message):
            cert = value
        elif isinstance(value, str):
            # Assume filename or contents of pubkey/cert
            if os.path.isfile(value):
                with open(value, 'r') as f:
                    data = f.read()
            else:
                data = value
            cert = Message(decodebytes(data.split()[1].encode()))
        else:
            raise ValueError("Invalid certificate value")

        if cert.get_text().endswith('-cert-v01@openssh.com'):
            self.public_blob = PublicBlob.from_message(cert)
        else:
            raise ValueError("Invalid certificate format")

class PublicBlob:
    """
    OpenSSH plain public key or OpenSSH signed public key (certificate).

    Tries to be as dumb as possible and barely cares about specific
    per-key-type data.

    .. note::

        Most of the time you'll want to call `from_file`, `from_string` or
        `from_message` for useful instantiation, the main constructor is
        basically "I should be using ``attrs`` for this."
    """

    def __init__(self, type_, blob, comment=None):
        """
        Create a new public blob of given type and contents.

        :param str type_: Type indicator, eg ``ssh-rsa``.
        :param bytes blob: The blob bytes themselves.
        :param str comment: A comment, if one was given (e.g. file-based.)
        """
        self.key_type = type_
        self.key_blob = blob
        self.comment = comment

    @classmethod
    def from_file(cls, filename):
        """
        Create a public blob from a ``-cert.pub``-style file on disk.
        """
        pass

    @classmethod
    def from_string(cls, string):
        """
        Create a public blob from a ``-cert.pub``-style string.
        """
        pass

    @classmethod
    def from_message(cls, message):
        """
        Create a public blob from a network `.Message`.

        Specifically, a cert-bearing pubkey auth packet, because by definition
        OpenSSH-style certificates 'are' their own network representation."
        """
        pass

    def __str__(self):
        ret = '{} public key/certificate'.format(self.key_type)
        if self.comment:
            ret += '- {}'.format(self.comment)
        return ret

    def __eq__(self, other):
        return self and other and (self.key_blob == other.key_blob)

    def __ne__(self, other):
        return not self == other
