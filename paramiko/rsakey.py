"""
RSA keys.
"""
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

class RSAKey(PKey):
    """
    Representation of an RSA key which can be used to sign and verify SSH2
    data.
    """
    name = 'ssh-rsa'
    HASHES = {'ssh-rsa': hashes.SHA1, 'ssh-rsa-cert-v01@openssh.com': hashes.SHA1, 'rsa-sha2-256': hashes.SHA256, 'rsa-sha2-256-cert-v01@openssh.com': hashes.SHA256, 'rsa-sha2-512': hashes.SHA512, 'rsa-sha2-512-cert-v01@openssh.com': hashes.SHA512}

    def __init__(self, msg=None, data=None, filename=None, password=None, key=None, file_obj=None):
        self.key = None
        self.public_blob = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if msg is None and data is not None:
            msg = Message(data)
        if key is not None:
            self.key = key
        else:
            if msg is not None:
                self._check_type_and_load_cert(msg=msg, key_type=self.name, cert_type='ssh-rsa-cert-v01@openssh.com')
                e = msg.get_mpint()
                n = msg.get_mpint()
                self.key = rsa.RSAPublicNumbers(e=e, n=n).public_key(default_backend())
            else:
                raise SSHException("Either msg, data, filename, or key must be provided")

    def __str__(self):
        return self.asbytes().decode('utf8', errors='ignore')

    @staticmethod
    def generate(bits, progress_func=None):
        """
        Generate a new private RSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param progress_func: Unused
        :return: new `.RSAKey` private key
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        return RSAKey(key=private_key)
