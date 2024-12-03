"""
Modern, adaptable authentication machinery.

Replaces certain parts of `.SSHClient`. For a concrete implementation, see the
``OpenSSHAuthStrategy`` class in `Fabric <https://fabfile.org>`_.
"""
from collections import namedtuple
from .agent import AgentKey
from .util import get_logger
from .ssh_exception import AuthenticationException

class AuthSource:
    """
    Some SSH authentication source, such as a password, private key, or agent.

    See subclasses in this module for concrete implementations.

    All implementations must accept at least a ``username`` (``str``) kwarg.
    """

    def __init__(self, username):
        self.username = username
        self.log = get_logger(__name__)

    def __repr__(self):
        return f"{self.__class__.__name__}(username={self.username!r})"

    def authenticate(self, transport):
        """
        Perform authentication.
        """
        raise NotImplementedError("Subclasses must implement this method")

class NoneAuth(AuthSource):
    """
    Auth type "none", ie https://www.rfc-editor.org/rfc/rfc4252#section-5.2 .
    """

class Password(AuthSource):
    """
    Password authentication.

    :param callable password_getter:
        A lazy callable that should return a `str` password value at
        authentication time, such as a `functools.partial` wrapping
        `getpass.getpass`, an API call to a secrets store, or similar.

        If you already know the password at instantiation time, you should
        simply use something like ``lambda: "my literal"`` (for a literal, but
        also, shame on you!) or ``lambda: variable_name`` (for something stored
        in a variable).
    """

    def __init__(self, username, password_getter):
        super().__init__(username=username)
        self.password_getter = password_getter

    def __repr__(self):
        return super()._repr(user=self.username)

class PrivateKey(AuthSource):
    """
    Essentially a mixin for private keys.

    Knows how to auth, but leaves key material discovery/loading/decryption to
    subclasses.

    Subclasses **must** ensure that they've set ``self.pkey`` to a decrypted
    `.PKey` instance before calling ``super().authenticate``; typically
    either in their ``__init__``, or in an overridden ``authenticate`` prior to
    its `super` call.
    """

class InMemoryPrivateKey(PrivateKey):
    """
    An in-memory, decrypted `.PKey` object.
    """

    def __init__(self, username, pkey):
        super().__init__(username=username)
        self.pkey = pkey

    def __repr__(self):
        rep = super()._repr(pkey=self.pkey)
        if isinstance(self.pkey, AgentKey):
            rep += ' [agent]'
        return rep

class OnDiskPrivateKey(PrivateKey):
    """
    Some on-disk private key that needs opening and possibly decrypting.

    :param str source:
        String tracking where this key's path was specified; should be one of
        ``"ssh-config"``, ``"python-config"``, or ``"implicit-home"``.
    :param Path path:
        The filesystem path this key was loaded from.
    :param PKey pkey:
        The `PKey` object this auth source uses/represents.
    """

    def __init__(self, username, source, path, pkey):
        super().__init__(username=username)
        self.source = source
        allowed = ('ssh-config', 'python-config', 'implicit-home')
        if source not in allowed:
            raise ValueError(f'source argument must be one of: {allowed!r}')
        self.path = path
        self.pkey = pkey

    def __repr__(self):
        return self._repr(key=self.pkey, source=self.source, path=str(self.path))
SourceResult = namedtuple('SourceResult', ['source', 'result'])

class AuthResult(list):
    """
    Represents a partial or complete SSH authentication attempt.

    This class conceptually extends `AuthStrategy` by pairing the former's
    authentication **sources** with the **results** of trying to authenticate
    with them.

    `AuthResult` is a (subclass of) `list` of `namedtuple`, which are of the
    form ``namedtuple('SourceResult', 'source', 'result')`` (where the
    ``source`` member is an `AuthSource` and the ``result`` member is either a
    return value from the relevant `.Transport` method, or an exception
    object).

    .. note::
        Transport auth method results are always themselves a ``list`` of "next
        allowable authentication methods".

        In the simple case of "you just authenticated successfully", it's an
        empty list; if your auth was rejected but you're allowed to try again,
        it will be a list of string method names like ``pubkey`` or
        ``password``.

        The ``__str__`` of this class represents the empty-list scenario as the
        word ``success``, which should make reading the result of an
        authentication session more obvious to humans.

    Instances also have a `strategy` attribute referencing the `AuthStrategy`
    which was attempted.
    """

    def __init__(self, strategy, *args, **kwargs):
        self.strategy = strategy
        super().__init__(*args, **kwargs)

    def __str__(self):
        return '\n'.join((f'{x.source} -> {x.result or 'success'}' for x in self))

class AuthFailure(AuthenticationException):
    """
    Basic exception wrapping an `AuthResult` indicating overall auth failure.

    Note that `AuthFailure` descends from `AuthenticationException` but is
    generally "higher level"; the latter is now only raised by individual
    `AuthSource` attempts and should typically only be seen by users when
    encapsulated in this class. It subclasses `AuthenticationException`
    primarily for backwards compatibility reasons.
    """

    def __init__(self, result):
        self.result = result

    def __str__(self):
        return '\n' + str(self.result)

class AuthStrategy:
    """
    This class represents one or more attempts to auth with an SSH server.

    By default, subclasses must at least accept an ``ssh_config``
    (`.SSHConfig`) keyword argument, but may opt to accept more as needed for
    their particular strategy.
    """

    def __init__(self, ssh_config):
        self.ssh_config = ssh_config
        self.log = get_logger(__name__)

    def get_sources(self):
        """
        Generator yielding `AuthSource` instances, in the order to try.

        This is the primary override point for subclasses: you figure out what
        sources you need, and ``yield`` them.

        Subclasses _of_ subclasses may find themselves wanting to do things
        like filtering or discarding around a call to `super`.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def authenticate(self, transport):
        """
        Handles attempting `AuthSource` instances yielded from `get_sources`.

        You *normally* won't need to override this, but it's an option for
        advanced users.
        """
        result = AuthResult(self)
        for source in self.get_sources():
            try:
                auth_result = source.authenticate(transport)
                result.append(SourceResult(source, auth_result))
                if not auth_result:  # Empty list means success
                    return result
            except AuthenticationException as e:
                result.append(SourceResult(source, e))
                self.log.warning(f"Authentication failed for {source}: {str(e)}")
        
        raise AuthFailure(result)
