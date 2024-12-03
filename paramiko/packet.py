"""
Packet handling
"""
import errno
import os
import socket
import struct
import threading
import time
from hmac import HMAC
from paramiko import util
from paramiko.common import linefeed_byte, cr_byte_value, MSG_NAMES, DEBUG, xffffffff, zero_byte, byte_ord
from paramiko.util import u
from paramiko.ssh_exception import SSHException, ProxyCommandFailure
from paramiko.message import Message

class NeedRekeyException(Exception):
    """
    Exception indicating a rekey is needed.
    """
    pass

class Packetizer:
    """
    Implementation of the base SSH packet protocol.
    """
    REKEY_PACKETS = pow(2, 29)
    REKEY_BYTES = pow(2, 29)
    REKEY_PACKETS_OVERFLOW_MAX = pow(2, 29)
    REKEY_BYTES_OVERFLOW_MAX = pow(2, 29)

    def __init__(self, socket):
        self.__socket = socket
        self.__logger = None
        self.__closed = False
        self.__dump_packets = False
        self.__need_rekey = False
        self.__init_count = 0
        self.__remainder = bytes()
        self._initial_kex_done = False
        self.__sent_bytes = 0
        self.__sent_packets = 0
        self.__received_bytes = 0
        self.__received_packets = 0
        self.__received_bytes_overflow = 0
        self.__received_packets_overflow = 0
        self.__block_size_out = 8
        self.__block_size_in = 8
        self.__mac_size_out = 0
        self.__mac_size_in = 0
        self.__block_engine_out = None
        self.__block_engine_in = None
        self.__sdctr_out = False
        self.__mac_engine_out = None
        self.__mac_engine_in = None
        self.__mac_key_out = bytes()
        self.__mac_key_in = bytes()
        self.__compress_engine_out = None
        self.__compress_engine_in = None
        self.__sequence_number_out = 0
        self.__sequence_number_in = 0
        self.__etm_out = False
        self.__etm_in = False
        self.__write_lock = threading.RLock()
        self.__keepalive_interval = 0
        self.__keepalive_last = time.time()
        self.__keepalive_callback = None
        self.__timer = None
        self.__handshake_complete = False
        self.__timer_expired = False

    def set_log(self, log):
        """
        Set the Python log object to use for logging.
        """
        self.__logger = log

    def set_outbound_cipher(self, block_engine, block_size, mac_engine, mac_size, mac_key, sdctr=False, etm=False):
        """
        Switch outbound data cipher.
        :param etm: Set encrypt-then-mac from OpenSSH
        """
        self.__block_engine_out = block_engine
        self.__block_size_out = block_size
        self.__mac_engine_out = mac_engine
        self.__mac_size_out = mac_size
        self.__mac_key_out = mac_key
        self.__sdctr_out = sdctr
        self.__etm_out = etm

    def set_inbound_cipher(self, block_engine, block_size, mac_engine, mac_size, mac_key, etm=False):
        """
        Switch inbound data cipher.
        :param etm: Set encrypt-then-mac from OpenSSH
        """
        self.__block_engine_in = block_engine
        self.__block_size_in = block_size
        self.__mac_engine_in = mac_engine
        self.__mac_size_in = mac_size
        self.__mac_key_in = mac_key
        self.__etm_in = etm

    def need_rekey(self):
        """
        Returns ``True`` if a new set of keys needs to be negotiated.  This
        will be triggered during a packet read or write, so it should be
        checked after every read or write, or at least after every few.
        """
        return (
            self.__need_rekey or
            (self.__sent_bytes >= self.REKEY_BYTES) or
            (self.__sent_packets >= self.REKEY_PACKETS)
        )

    def set_keepalive(self, interval, callback):
        """
        Turn on/off the callback keepalive.  If ``interval`` seconds pass with
        no data read from or written to the socket, the callback will be
        executed and the timer will be reset.
        """
        self.__keepalive_interval = interval
        self.__keepalive_callback = callback
        self.__keepalive_last = time.time()

    def start_handshake(self, timeout):
        """
        Tells `Packetizer` that the handshake process started.
        Starts a book keeping timer that can signal a timeout in the
        handshake process.

        :param float timeout: amount of seconds to wait before timing out
        """
        self.__handshake_complete = False
        self.__timer = threading.Timer(timeout, self.__handshake_timed_out)
        self.__timer.start()

    def handshake_timed_out(self):
        """
        Checks if the handshake has timed out.

        If `start_handshake` wasn't called before the call to this function,
        the return value will always be `False`. If the handshake completed
        before a timeout was reached, the return value will be `False`

        :return: handshake time out status, as a `bool`
        """
        return self.__timer_expired and not self.__handshake_complete

    def complete_handshake(self):
        """
        Tells `Packetizer` that the handshake has completed.
        """
        self.__handshake_complete = True
        if self.__timer:
            self.__timer.cancel()

    def read_all(self, n, check_rekey=False):
        """
        Read as close to N bytes as possible, blocking as long as necessary.

        :param int n: number of bytes to read
        :return: the data read, as a `str`

        :raises:
            ``EOFError`` -- if the socket was closed before all the bytes could
            be read
        """
        out = bytes()
        while len(out) < n:
            buf = self.__socket.recv(n - len(out))
            if len(buf) == 0:
                raise EOFError()
            out += buf
        if check_rekey and self.need_rekey():
            raise NeedRekeyException()
        return out

    def readline(self, timeout):
        """
        Read a line from the socket.  We assume no data is pending after the
        line, so it's okay to attempt large reads.
        """
        buf = bytes()
        start = time.time()
        while True:
            buf += self.__socket.recv(1)
            if buf.endswith(b'\n'):
                break
            if timeout is not None and time.time() - start > timeout:
                raise socket.timeout()
        return buf

    def send_message(self, data):
        """
        Write a block of data using the current cipher, as an SSH block.
        """
        payload = self.__block_engine_out.encrypt(data)
        mac = self.__mac_engine_out.digest(self.__mac_key_out, self.__sequence_number_out, payload)
        packet = struct.pack('>I', len(payload)) + payload + mac
        self.__sequence_number_out = (self.__sequence_number_out + 1) & 0xffffffff
        self.__socket.sendall(packet)
        self.__sent_bytes += len(packet)
        self.__sent_packets += 1

    def read_message(self):
        """
        Only one thread should ever be in this function (no other locking is
        done).

        :raises: `.SSHException` -- if the packet is mangled
        :raises: `.NeedRekeyException` -- if the transport should rekey
        """
        header = self.read_all(self.__block_size_in, check_rekey=True)
        packet_size = struct.unpack('>I', header[:4])[0]
        leftover = header[4:]
        if (packet_size - len(leftover)) % self.__block_size_in != 0:
            raise SSHException('Invalid packet blocking')
        buf = self.read_all(packet_size + self.__mac_size_in - len(leftover))
        packet = leftover + buf[:-self.__mac_size_in]
        mac = buf[-self.__mac_size_in:]
        if self.__mac_size_in > 0:
            mac_payload = struct.pack('>I', self.__sequence_number_in) + packet
            my_mac = self.__mac_engine_in.digest(self.__mac_key_in, mac_payload)
            if my_mac != mac:
                raise SSHException('Mismatched MAC')
        padding = byte_ord(packet[0])
        payload = packet[1:packet_size - padding]
        self.__sequence_number_in = (self.__sequence_number_in + 1) & 0xffffffff
        self.__received_bytes += packet_size + self.__mac_size_in + 4
        self.__received_packets += 1
        if self.need_rekey():
            raise NeedRekeyException()
        return payload
