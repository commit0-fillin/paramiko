"""
ECDSA keys
"""
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from paramiko.common import four_byte
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException
from paramiko.util import deflate_long

class _ECDSACurve:
    """
    Represents a specific ECDSA Curve (nistp256, nistp384, etc).

    Handles the generation of the key format identifier and the selection of
    the proper hash function. Also grabs the proper curve from the 'ecdsa'
    package.
    """

    def __init__(self, curve_class, nist_name):
        self.nist_name = nist_name
        self.key_length = curve_class.key_size
        self.key_format_identifier = 'ecdsa-sha2-' + self.nist_name
        if self.key_length <= 256:
            self.hash_object = hashes.SHA256
        elif self.key_length <= 384:
            self.hash_object = hashes.SHA384
        else:
            self.hash_object = hashes.SHA512
        self.curve_class = curve_class

class _ECDSACurveSet:
    """
    A collection to hold the ECDSA curves. Allows querying by oid and by key
    format identifier. The two ways in which ECDSAKey needs to be able to look
    up curves.
    """

    def __init__(self, ecdsa_curves):
        self.ecdsa_curves = ecdsa_curves

class ECDSAKey(PKey):
    """
    Representation of an ECDSA key which can be used to sign and verify SSH2
    data.
    """
    _ECDSA_CURVES = _ECDSACurveSet([_ECDSACurve(ec.SECP256R1, 'nistp256'), _ECDSACurve(ec.SECP384R1, 'nistp384'), _ECDSACurve(ec.SECP521R1, 'nistp521')])

    def __init__(self, msg=None, data=None, filename=None, password=None, vals=None, file_obj=None, validate_point=True):
        self.verifying_key = None
        self.signing_key = None
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
            self.signing_key, self.verifying_key = vals
            c_class = self.signing_key.curve.__class__
            self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(c_class)
        else:
            key_type = msg.get_text()
            suffix = '-cert-v01@openssh.com'
            if key_type.endswith(suffix):
                key_type = key_type[:-len(suffix)]
            self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(key_type)
            key_types = self._ECDSA_CURVES.get_key_format_identifier_list()
            cert_types = ['{}-cert-v01@openssh.com'.format(x) for x in key_types]
            self._check_type_and_load_cert(msg=msg, key_type=key_types, cert_type=cert_types)
            curvename = msg.get_text()
            if curvename != self.ecdsa_curve.nist_name:
                raise SSHException("Can't handle curve of type {}".format(curvename))
            pointinfo = msg.get_binary()
            try:
                key = ec.EllipticCurvePublicKey.from_encoded_point(self.ecdsa_curve.curve_class(), pointinfo)
                self.verifying_key = key
            except ValueError:
                raise SSHException('Invalid public key')
        
        super(ECDSAKey, self).__init__(msg, data)

    def __str__(self):
        return self.asbytes()

    @classmethod
    def generate(cls, curve=ec.SECP256R1(), progress_func=None, bits=None):
        """
        Generate a new private ECDSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param curve: The curve to use for key generation (default: SECP256R1)
        :param progress_func: Not used for this type of key.
        :param bits: Not used for ECDSA keys.
        :returns: A new private key (`.ECDSAKey`) object
        """
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return cls(vals=(private_key, public_key))
