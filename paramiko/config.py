"""
Configuration file (aka ``ssh_config``) support.
"""
import fnmatch
import getpass
import os
import re
import shlex
import socket
from hashlib import sha1
from io import StringIO
from functools import partial
invoke, invoke_import_error = (None, None)
try:
    import invoke
except ImportError as e:
    invoke_import_error = e
from .ssh_exception import CouldNotCanonicalize, ConfigParseError
SSH_PORT = 22

class SSHConfig:
    """
    Representation of config information as stored in the format used by
    OpenSSH. Queries can be made via `lookup`. The format is described in
    OpenSSH's ``ssh_config`` man page. This class is provided primarily as a
    convenience to posix users (since the OpenSSH format is a de-facto
    standard on posix) but should work fine on Windows too.

    .. versionadded:: 1.6
    """
    SETTINGS_REGEX = re.compile('(\\w+)(?:\\s*=\\s*|\\s+)(.+)')
    TOKENS_BY_CONFIG_KEY = {'controlpath': ['%C', '%h', '%l', '%L', '%n', '%p', '%r', '%u'], 'hostname': ['%h'], 'identityfile': ['%C', '~', '%d', '%h', '%l', '%u', '%r'], 'proxycommand': ['~', '%h', '%p', '%r'], 'proxyjump': ['%h', '%p', '%r'], 'match-exec': ['%C', '%d', '%h', '%L', '%l', '%n', '%p', '%r', '%u']}

    def __init__(self):
        """
        Create a new OpenSSH config object.

        Note: the newer alternate constructors `from_path`, `from_file` and
        `from_text` are simpler to use, as they parse on instantiation. For
        example, instead of::

            config = SSHConfig()
            config.parse(open("some-path.config")

        you could::

            config = SSHConfig.from_file(open("some-path.config"))
            # Or more directly:
            config = SSHConfig.from_path("some-path.config")
            # Or if you have arbitrary ssh_config text from some other source:
            config = SSHConfig.from_text("Host foo\\n\\tUser bar")
        """
        self._config = []

    @classmethod
    def from_text(cls, text):
        """
        Create a new, parsed `SSHConfig` from ``text`` string.

        .. versionadded:: 2.7
        """
        config = cls()
        config.parse(StringIO(text))
        return config

    @classmethod
    def from_path(cls, path):
        """
        Create a new, parsed `SSHConfig` from the file found at ``path``.

        .. versionadded:: 2.7
        """
        with open(path, 'r') as f:
            return cls.from_file(f)

    @classmethod
    def from_file(cls, flo):
        """
        Create a new, parsed `SSHConfig` from file-like object ``flo``.

        .. versionadded:: 2.7
        """
        config = cls()
        config.parse(flo)
        return config

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        :param file_obj: a file-like object to read the config file from
        """
        host = {"host": ['*'], "config": {}}
        for line in file_obj:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('host '):
                self._config.append(host)
                host = {"host": self._get_hosts(line.split()[1:]), "config": {}}
            elif line.lower().startswith('match '):
                self._config.append(host)
                host = {"host": ['*'], "config": {}, "match": self._get_matches(line)}
            else:
                key, value = self.SETTINGS_REGEX.match(line).groups()
                host['config'][key.lower()] = value
        self._config.append(host)

    def lookup(self, hostname):
        """
        Return a dict (`SSHConfigDict`) of config options for a given hostname.

        The host-matching rules of OpenSSH's ``ssh_config`` man page are used:
        For each parameter, the first obtained value will be used.  The
        configuration files contain sections separated by ``Host`` and/or
        ``Match`` specifications, and that section is only applied for hosts
        which match the given patterns or keywords

        Since the first obtained value for each parameter is used, more host-
        specific declarations should be given near the beginning of the file,
        and general defaults at the end.

        The keys in the returned dict are all normalized to lowercase (look for
        ``"port"``, not ``"Port"``. The values are processed according to the
        rules for substitution variable expansion in ``ssh_config``.

        Finally, please see the docs for `SSHConfigDict` for deeper info on
        features such as optional type conversion methods, e.g.::

            conf = my_config.lookup('myhost')
            assert conf['passwordauthentication'] == 'yes'
            assert conf.as_bool('passwordauthentication') is True

        .. note::
            If there is no explicitly configured ``HostName`` value, it will be
            set to the being-looked-up hostname, which is as close as we can
            get to OpenSSH's behavior around that particular option.

        :param str hostname: the hostname to lookup

        .. versionchanged:: 2.5
            Returns `SSHConfigDict` objects instead of dict literals.
        .. versionchanged:: 2.7
            Added canonicalization support.
        .. versionchanged:: 2.7
            Added ``Match`` support.
        .. versionchanged:: 3.3
            Added ``Match final`` support.
        """
        matches = [x for x in self._config if self._host_match(x, hostname)]
        ret = SSHConfigDict()
        for m in matches:
            for k, v in m.get('config', {}).items():
                if k not in ret:
                    ret[k] = v
        ret = self._expand_variables(ret, hostname)
        if 'hostname' not in ret:
            ret['hostname'] = hostname
        return ret

    def canonicalize(self, hostname, options, domains):
        """
        Return canonicalized version of ``hostname``.

        :param str hostname: Target hostname.
        :param options: An `SSHConfigDict` from a previous lookup pass.
        :param domains: List of domains (e.g. ``["paramiko.org"]``).

        :returns: A canonicalized hostname if one was found, else ``None``.

        .. versionadded:: 2.7
        """
        pass

    def get_hostnames(self):
        """
        Return the set of literal hostnames defined in the SSH config (both
        explicit hostnames and wildcard entries).
        """
        pass

    def _tokenize(self, config, target_hostname, key, value):
        """
        Tokenize a string based on current config/hostname data.

        :param config: Current config data.
        :param target_hostname: Original target connection hostname.
        :param key: Config key being tokenized (used to filter token list).
        :param value: Config value being tokenized.

        :returns: The tokenized version of the input ``value`` string.
        """
        pass

    def _allowed_tokens(self, key):
        """
        Given config ``key``, return list of token strings to tokenize.

        .. note::
            This feels like it wants to eventually go away, but is used to
            preserve as-strict-as-possible compatibility with OpenSSH, which
            for whatever reason only applies some tokens to some config keys.
        """
        pass

    def _expand_variables(self, config, target_hostname):
        """
        Return a dict of config options with expanded substitutions
        for a given original & current target hostname.

        Please refer to :doc:`/api/config` for details.

        :param dict config: the currently parsed config
        :param str hostname: the hostname whose config is being looked up
        """
        pass

    def _get_hosts(self, host):
        """
        Return a list of host_names from host value.
        """
        pass

    def _get_matches(self, match):
        """
        Parse a specific Match config line into a list-of-dicts for its values.

        Performs some parse-time validation as well.
        """
        pass

def _addressfamily_host_lookup(hostname, options):
    """
    Try looking up ``hostname`` in an IPv4 or IPv6 specific manner.

    This is an odd duck due to needing use in two divergent use cases. It looks
    up ``AddressFamily`` in ``options`` and if it is ``inet`` or ``inet6``,
    this function uses `socket.getaddrinfo` to perform a family-specific
    lookup, returning the result if successful.

    In any other situation -- lookup failure, or ``AddressFamily`` being
    unspecified or ``any`` -- ``None`` is returned instead and the caller is
    expected to do something situation-appropriate like calling
    `socket.gethostbyname`.

    :param str hostname: Hostname to look up.
    :param options: `SSHConfigDict` instance w/ parsed options.
    :returns: ``getaddrinfo``-style tuples, or ``None``, depending.
    """
    pass

class LazyFqdn:
    """
    Returns the host's fqdn on request as string.
    """

    def __init__(self, config, host=None):
        self.fqdn = None
        self.config = config
        self.host = host

    def __str__(self):
        if self.fqdn is None:
            fqdn = None
            results = _addressfamily_host_lookup(self.host, self.config)
            if results is not None:
                for res in results:
                    af, socktype, proto, canonname, sa = res
                    if canonname and '.' in canonname:
                        fqdn = canonname
                        break
            if fqdn is None:
                fqdn = socket.getfqdn()
            self.fqdn = fqdn
        return self.fqdn

class SSHConfigDict(dict):
    """
    A dictionary wrapper/subclass for per-host configuration structures.

    This class introduces some usage niceties for consumers of `SSHConfig`,
    specifically around the issue of variable type conversions: normal value
    access yields strings, but there are now methods such as `as_bool` and
    `as_int` that yield casted values instead.

    For example, given the following ``ssh_config`` file snippet::

        Host foo.example.com
            PasswordAuthentication no
            Compression yes
            ServerAliveInterval 60

    the following code highlights how you can access the raw strings as well as
    usefully Python type-casted versions (recalling that keys are all
    normalized to lowercase first)::

        my_config = SSHConfig()
        my_config.parse(open('~/.ssh/config'))
        conf = my_config.lookup('foo.example.com')

        assert conf['passwordauthentication'] == 'no'
        assert conf.as_bool('passwordauthentication') is False
        assert conf['compression'] == 'yes'
        assert conf.as_bool('compression') is True
        assert conf['serveraliveinterval'] == '60'
        assert conf.as_int('serveraliveinterval') == 60

    .. versionadded:: 2.5
    """

    def as_bool(self, key):
        """
        Express given key's value as a boolean type.

        Typically, this is used for ``ssh_config``'s pseudo-boolean values
        which are either ``"yes"`` or ``"no"``. In such cases, ``"yes"`` yields
        ``True`` and any other value becomes ``False``.

        .. note::
            If (for whatever reason) the stored value is already boolean in
            nature, it's simply returned.

        .. versionadded:: 2.5
        """
        pass

    def as_int(self, key):
        """
        Express given key's value as an integer, if possible.

        This method will raise ``ValueError`` or similar if the value is not
        int-appropriate, same as the builtin `int` type.

        .. versionadded:: 2.5
        """
        pass
