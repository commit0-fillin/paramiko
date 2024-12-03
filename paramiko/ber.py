from paramiko.common import max_byte, zero_byte, byte_ord, byte_chr
import paramiko.util as util
from paramiko.util import b, deflate_long
from paramiko.sftp import int64

class BERException(Exception):
    pass

class BER:
    """
    Robey's tiny little attempt at a BER decoder.
    """

    def __init__(self, content=bytes()):
        self.content = b(content)
        self.idx = 0

    def __str__(self):
        return self.content.decode('utf-8', errors='replace')

    def __repr__(self):
        return f"BER({repr(self.content)})"

    def asbytes(self):
        return self.content

    def decode(self):
        if self.idx >= len(self.content):
            return None
        ident = byte_ord(self.content[self.idx])
        self.idx += 1
        if (ident & 31) == 31:
            ident = 0
            while self.idx < len(self.content):
                t = byte_ord(self.content[self.idx])
                self.idx += 1
                ident = (ident << 7) | (t & 0x7f)
                if not (t & 0x80):
                    break
        if self.idx >= len(self.content):
            return None
        size = byte_ord(self.content[self.idx])
        self.idx += 1
        if size & 0x80:
            # length is coded on multiple bytes
            nb = size & 0x7f
            size = 0
            for i in range(nb):
                if self.idx >= len(self.content):
                    return None
                size = (size << 8) | byte_ord(self.content[self.idx])
                self.idx += 1
        if self.idx + size > len(self.content):
            # can't parse this tag
            return None
        data = self.content[self.idx:self.idx + size]
        self.idx += size
        return (ident, data)

    def decode_seq(self):
        seq = []
        while True:
            item = self.decode()
            if item is None:
                break
            seq.append(item)
        return seq

    def encode_tlv(self, ident, value):
        self.content += byte_chr(ident)
        if len(value) > 127:
            lenBytes = deflate_long(len(value))
            self.content += byte_chr(0x80 | len(lenBytes)) + lenBytes
        else:
            self.content += byte_chr(len(value))
        self.content += value

    def encode_seq(self, seq):
        for item in seq:
            self.encode_tlv(*item)
