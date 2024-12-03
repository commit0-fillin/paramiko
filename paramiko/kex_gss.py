"""
This module provides GSS-API / SSPI Key Exchange as defined in :rfc:`4462`.

.. note:: Credential delegation is not supported in server mode.

.. note::
    `RFC 4462 Section 2.2
    <https://tools.ietf.org/html/rfc4462.html#section-2.2>`_ says we are not
    required to implement GSS-API error messages. Thus, in many methods within
    this module, if an error occurs an exception will be thrown and the
    connection will be terminated.

.. seealso:: :doc:`/api/ssh_gss`

.. versionadded:: 1.15
"""
import os
from hashlib import sha1
from paramiko.common import DEBUG, max_byte, zero_byte, byte_chr, byte_mask, byte_ord
from paramiko import util
from paramiko.message import Message
from paramiko.ssh_exception import SSHException
MSG_KEXGSS_INIT, MSG_KEXGSS_CONTINUE, MSG_KEXGSS_COMPLETE, MSG_KEXGSS_HOSTKEY, MSG_KEXGSS_ERROR = range(30, 35)
MSG_KEXGSS_GROUPREQ, MSG_KEXGSS_GROUP = range(40, 42)
c_MSG_KEXGSS_INIT, c_MSG_KEXGSS_CONTINUE, c_MSG_KEXGSS_COMPLETE, c_MSG_KEXGSS_HOSTKEY, c_MSG_KEXGSS_ERROR = [byte_chr(c) for c in range(30, 35)]
c_MSG_KEXGSS_GROUPREQ, c_MSG_KEXGSS_GROUP = [byte_chr(c) for c in range(40, 42)]

class KexGSSGroup1:
    """
    GSS-API / SSPI Authenticated Diffie-Hellman Key Exchange as defined in `RFC
    4462 Section 2 <https://tools.ietf.org/html/rfc4462.html#section-2>`_
    """
    P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
    G = 2
    b7fffffffffffffff = byte_chr(127) + max_byte * 7
    b0000000000000000 = zero_byte * 8
    NAME = 'gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g=='

    def __init__(self, transport):
        self.transport = transport
        self.kexgss = self.transport.kexgss_ctxt
        self.gss_host = None
        self.x = 0
        self.e = 0
        self.f = 0

    def start_kex(self):
        """
        Start the GSS-API / SSPI Authenticated Diffie-Hellman Key Exchange.
        """
        self._generate_x()
        self.e = pow(self.G, self.x, self.P)
        m = Message()
        m.add_byte(c_MSG_KEXGSS_INIT)
        m.add_string(self.kexgss.ssh_init_sec_context(target=self.gss_host))
        m.add_mpint(self.e)
        self.transport._send_message(m)

    def parse_next(self, ptype, m):
        """
        Parse the next packet.

        :param ptype: The (string) type of the incoming packet
        :param `.Message` m: The packet content
        """
        if ptype == MSG_KEXGSS_HOSTKEY:
            self._parse_kexgss_hostkey(m)
        elif ptype == MSG_KEXGSS_CONTINUE:
            self._parse_kexgss_continue(m)
        elif ptype == MSG_KEXGSS_COMPLETE:
            self._parse_kexgss_complete(m)
        elif ptype == MSG_KEXGSS_ERROR:
            self._parse_kexgss_error(m)
        else:
            raise SSHException('GSS KexGroup1 asked to handle packet type %d' % ptype)

    def _generate_x(self):
        """
        generate an "x" (1 < x < q), where q is (p-1)/2.
        p is a 128-byte (1024-bit) number, where the first 64 bits are 1.
        therefore q can be approximated as a 2^1023.  we drop the subset of
        potential x where the first 63 bits are 1, because some of those will
        be larger than q (but this is a tiny tiny subset of potential x).
        """
        top = b'\x7f' + os.urandom(127)
        self.x = util.inflate_long(top, True)

    def _parse_kexgss_hostkey(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_HOSTKEY message (client mode).

        :param `.Message` m: The content of the SSH2_MSG_KEXGSS_HOSTKEY message
        """
        host_key = m.get_string()
        self.transport._set_remote_host_key(host_key)

    def _parse_kexgss_continue(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_CONTINUE message.

        :param `.Message` m: The content of the SSH2_MSG_KEXGSS_CONTINUE
            message
        """
        token = m.get_string()
        srv_token = self.kexgss.ssh_init_sec_context(target=self.gss_host, recv_token=token)
        m = Message()
        m.add_byte(c_MSG_KEXGSS_CONTINUE)
        m.add_string(srv_token)
        self.transport._send_message(m)

    def _parse_kexgss_complete(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_COMPLETE message (client mode).

        :param `.Message` m: The content of the
            SSH2_MSG_KEXGSS_COMPLETE message
        """
        self.f = m.get_mpint()
        mic_token = m.get_string()
        self.kexgss.ssh_check_mic(mic_token, self.transport.session_id)
        K = pow(self.f, self.x, self.P)
        self.transport._set_K_H(K, self.transport.kex_engine.compute_key(K, self.transport.H))
        self.transport._activate_outbound()

    def _parse_kexgss_init(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_INIT message (server mode).

        :param `.Message` m: The content of the SSH2_MSG_KEXGSS_INIT message
        """
        client_token = m.get_string()
        self.e = m.get_mpint()
        self.x = util.generate_random_int(2, self.P - 1)
        self.f = pow(self.G, self.x, self.P)
        K = pow(self.e, self.x, self.P)
        self.transport._set_K_H(K, self.transport.kex_engine.compute_key(K, self.transport.H))
        srv_token = self.kexgss.ssh_accept_sec_context(client_token)
        m = Message()
        m.add_byte(c_MSG_KEXGSS_COMPLETE)
        m.add_mpint(self.f)
        m.add_string(srv_token)
        self.transport._send_message(m)
        self.transport._activate_outbound()

    def _parse_kexgss_error(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_ERROR message (client mode).
        The server may send a GSS-API error message. if it does, we display
        the error by throwing an exception (client mode).

        :param `.Message` m: The content of the SSH2_MSG_KEXGSS_ERROR message
        :raise SSHException: Contains GSS-API major and minor status as well as
                             the error message and the language tag of the
                             message
        """
        maj_status = m.get_int()
        min_status = m.get_int()
        err_msg = m.get_string()
        m.get_string()  # Language tag (discarded)
        raise SSHException(f"GSS-API Error: Major Status: {maj_status}, Minor Status: {min_status}, Error: {err_msg}")

class KexGSSGroup14(KexGSSGroup1):
    """
    GSS-API / SSPI Authenticated Diffie-Hellman Group14 Key Exchange as defined
    in `RFC 4462 Section 2
    <https://tools.ietf.org/html/rfc4462.html#section-2>`_
    """
    P = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
    G = 2
    NAME = 'gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g=='

class KexGSSGex:
    """
    GSS-API / SSPI Authenticated Diffie-Hellman Group Exchange as defined in
    `RFC 4462 Section 2 <https://tools.ietf.org/html/rfc4462.html#section-2>`_
    """
    NAME = 'gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g=='
    min_bits = 1024
    max_bits = 8192
    preferred_bits = 2048

    def __init__(self, transport):
        self.transport = transport
        self.kexgss = self.transport.kexgss_ctxt
        self.gss_host = None
        self.p = None
        self.q = None
        self.g = None
        self.x = None
        self.e = None
        self.f = None
        self.old_style = False

    def start_kex(self):
        """
        Start the GSS-API / SSPI Authenticated Diffie-Hellman Group Exchange
        """
        if self.transport.server_mode:
            self.transport._expect_packet(MSG_KEXGSS_GROUPREQ)
        else:
            m = Message()
            m.add_byte(c_MSG_KEXGSS_GROUPREQ)
            m.add_int(self.min_bits)
            m.add_int(self.preferred_bits)
            m.add_int(self.max_bits)
            self.transport._send_message(m)
            self.transport._expect_packet(MSG_KEXGSS_GROUP)

    def parse_next(self, ptype, m):
        """
        Parse the next packet.

        :param ptype: The (string) type of the incoming packet
        :param `.Message` m: The packet content
        """
        if ptype == MSG_KEXGSS_GROUPREQ:
            self._parse_kexgss_groupreq(m)
        elif ptype == MSG_KEXGSS_GROUP:
            self._parse_kexgss_group(m)
        elif ptype == MSG_KEXGSS_INIT:
            self._parse_kexgss_gex_init(m)
        elif ptype == MSG_KEXGSS_HOSTKEY:
            self._parse_kexgss_hostkey(m)
        elif ptype == MSG_KEXGSS_CONTINUE:
            self._parse_kexgss_continue(m)
        elif ptype == MSG_KEXGSS_COMPLETE:
            self._parse_kexgss_complete(m)
        elif ptype == MSG_KEXGSS_ERROR:
            self._parse_kexgss_error(m)
        else:
            raise SSHException('GSS KexGex asked to handle packet type %d' % ptype)

    def _parse_kexgss_groupreq(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_GROUPREQ message (server mode).

        :param `.Message` m: The content of the
            SSH2_MSG_KEXGSS_GROUPREQ message
        """
        min_bits = m.get_int()
        preferred_bits = m.get_int()
        max_bits = m.get_int()
        
        # Here, you would typically choose appropriate DH parameters
        # based on the requested bit sizes. For this example, we'll
        # use fixed parameters.
        self.p = self.P
        self.g = self.G
        
        m = Message()
        m.add_byte(c_MSG_KEXGSS_GROUP)
        m.add_mpint(self.p)
        m.add_mpint(self.g)
        self.transport._send_message(m)

    def _parse_kexgss_group(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_GROUP message (client mode).

        :param `Message` m: The content of the SSH2_MSG_KEXGSS_GROUP message
        """
        self.p = m.get_mpint()
        self.g = m.get_mpint()
        
        # Generate client's private key
        self.x = util.generate_random_int(2, self.p - 1)
        
        # Calculate client's public key
        self.e = pow(self.g, self.x, self.p)
        
        m = Message()
        m.add_byte(c_MSG_KEXGSS_INIT)
        m.add_string(self.kexgss.ssh_init_sec_context(target=self.gss_host))
        m.add_mpint(self.e)
        self.transport._send_message(m)

    def _parse_kexgss_gex_init(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_INIT message (server mode).

        :param `Message` m: The content of the SSH2_MSG_KEXGSS_INIT message
        """
        client_token = m.get_string()
        self.e = m.get_mpint()
        
        # Generate server's private key
        self.x = util.generate_random_int(2, self.p - 1)
        
        # Calculate server's public key
        self.f = pow(self.g, self.x, self.p)
        
        # Calculate shared secret
        K = pow(self.e, self.x, self.p)
        
        self.transport._set_K_H(K, self.transport.kex_engine.compute_key(K, self.transport.H))
        
        srv_token = self.kexgss.ssh_accept_sec_context(client_token)
        
        m = Message()
        m.add_byte(c_MSG_KEXGSS_COMPLETE)
        m.add_mpint(self.f)
        m.add_string(srv_token)
        self.transport._send_message(m)
        self.transport._activate_outbound()

    def _parse_kexgss_hostkey(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_HOSTKEY message (client mode).

        :param `Message` m: The content of the SSH2_MSG_KEXGSS_HOSTKEY message
        """
        host_key = m.get_string()
        self.transport._set_remote_host_key(host_key)

    def _parse_kexgss_continue(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_CONTINUE message.

        :param `Message` m: The content of the SSH2_MSG_KEXGSS_CONTINUE message
        """
        pass

    def _parse_kexgss_complete(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_COMPLETE message (client mode).

        :param `Message` m: The content of the SSH2_MSG_KEXGSS_COMPLETE message
        """
        pass

    def _parse_kexgss_error(self, m):
        """
        Parse the SSH2_MSG_KEXGSS_ERROR message (client mode).
        The server may send a GSS-API error message. if it does, we display
        the error by throwing an exception (client mode).

        :param `Message` m:  The content of the SSH2_MSG_KEXGSS_ERROR message
        :raise SSHException: Contains GSS-API major and minor status as well as
                             the error message and the language tag of the
                             message
        """
        pass

class NullHostKey:
    """
    This class represents the Null Host Key for GSS-API Key Exchange as defined
    in `RFC 4462 Section 5
    <https://tools.ietf.org/html/rfc4462.html#section-5>`_
    """

    def __init__(self):
        self.key = ''

    def __str__(self):
        return self.key
