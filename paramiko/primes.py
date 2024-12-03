"""
Utility functions for dealing with primes.
"""
import os
from paramiko import util
from paramiko.common import byte_mask
from paramiko.ssh_exception import SSHException

def _roll_random(n):
    """returns a random # from 0 to N-1"""
    return int.from_bytes(os.urandom(4), byteorder='big') % n

class ModulusPack:
    """
    convenience object for holding the contents of the /etc/ssh/moduli file,
    on systems that have such a file.
    """

    def __init__(self):
        self.pack = {}
        self.discarded = []

    def read_file(self, filename):
        """
        :raises IOError: passed from any file operations that fail.
        """
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        time, mod, gen, key = line.split()
                        mod = int(mod)
                        gen = int(gen)
                        key = int(key)
                        self.pack.setdefault(mod, []).append((gen, key))
                    except ValueError:
                        self.discarded.append(line)
