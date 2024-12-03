"""
DSS keys.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from paramiko import util
from paramiko.common import zero_byte
from paramiko.ssh_exception import SSHException
from paramiko.message import Message
from paramiko.ber import BER, BERException
from paramiko.pkey import PKey

class DSSKey(PKey):
    """
    Representation of a DSS key which can be used to sign an verify SSH2
    data.
    """
    name = 'ssh-dss'

    def __init__(self, msg=None, data=None, filename=None, password=None, vals=None, file_obj=None):
        self.p = None
        self.q = None
        self.g = None
        self.y = None
        self.x = None
        self.public_blob = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if msg is None and data is not None:
            msg = Message(data)
        if vals is not None:
            self.p, self.q, self.g, self.y = vals
        else:
            if msg is None:
                raise SSHException("Key object may not be empty")
            self._check_type_and_load_cert(msg=msg, key_type=self.name, cert_type=f'{self.name}-cert-v01@openssh.com')
            self.p = msg.get_mpint()
            self.q = msg.get_mpint()
            self.g = msg.get_mpint()
            self.y = msg.get_mpint()
        self.size = util.bit_length(self.p)

    def __str__(self):
        return self.asbytes()

    @staticmethod
    def generate(bits=1024, progress_func=None):
        """
        Generate a new private DSS key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param progress_func: Unused
        :return: new `.DSSKey` private key
        """
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend

        private_key = dsa.generate_private_key(
            key_size=bits,
            backend=default_backend()
        )
        numbers = private_key.private_numbers()
        public_numbers = numbers.public_numbers

        key = DSSKey(vals=(public_numbers.parameter_numbers.p,
                           public_numbers.parameter_numbers.q,
                           public_numbers.parameter_numbers.g,
                           public_numbers.y))
        key.x = numbers.x
        return key
