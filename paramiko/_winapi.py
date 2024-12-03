"""
Windows API functions implemented as ctypes functions and classes as found
in jaraco.windows (3.4.1).

If you encounter issues with this module, please consider reporting the issues
in jaraco.windows and asking the author to port the fixes back here.
"""
import builtins
import ctypes.wintypes
from paramiko.util import u

def format_system_message(errno):
    """
    Call FormatMessage with a system error number to retrieve
    the descriptive error message.
    """
    # Get a buffer for the error message
    buffer = ctypes.create_unicode_buffer(0)
    size = ctypes.windll.kernel32.FormatMessageW(
        0x00001000,  # FORMAT_MESSAGE_FROM_SYSTEM
        None,
        errno,
        0,  # Default language
        ctypes.byref(buffer),
        0,  # Size of buffer (0 to allocate)
        None
    )
    
    if size:
        return buffer.value
    else:
        return f"Unknown error ({errno})"

class WindowsError(builtins.WindowsError):
    """more info about errors at
    http://msdn.microsoft.com/en-us/library/ms681381(VS.85).aspx"""

    def __init__(self, value=None):
        if value is None:
            value = ctypes.windll.kernel32.GetLastError()
        strerror = format_system_message(value)
        args = (0, strerror, None, value)
        super().__init__(*args)

    def __str__(self):
        return self.message

    def __repr__(self):
        return '{self.__class__.__name__}({self.winerror})'.format(**vars())
GMEM_MOVEABLE = 2
GlobalAlloc = ctypes.windll.kernel32.GlobalAlloc
GlobalAlloc.argtypes = (ctypes.wintypes.UINT, ctypes.c_size_t)
GlobalAlloc.restype = ctypes.wintypes.HANDLE
GlobalLock = ctypes.windll.kernel32.GlobalLock
GlobalLock.argtypes = (ctypes.wintypes.HGLOBAL,)
GlobalLock.restype = ctypes.wintypes.LPVOID
GlobalUnlock = ctypes.windll.kernel32.GlobalUnlock
GlobalUnlock.argtypes = (ctypes.wintypes.HGLOBAL,)
GlobalUnlock.restype = ctypes.wintypes.BOOL
GlobalSize = ctypes.windll.kernel32.GlobalSize
GlobalSize.argtypes = (ctypes.wintypes.HGLOBAL,)
GlobalSize.restype = ctypes.c_size_t
CreateFileMapping = ctypes.windll.kernel32.CreateFileMappingW
CreateFileMapping.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.LPWSTR]
CreateFileMapping.restype = ctypes.wintypes.HANDLE
MapViewOfFile = ctypes.windll.kernel32.MapViewOfFile
MapViewOfFile.restype = ctypes.wintypes.HANDLE
UnmapViewOfFile = ctypes.windll.kernel32.UnmapViewOfFile
UnmapViewOfFile.argtypes = (ctypes.wintypes.HANDLE,)
RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
RtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
ctypes.windll.kernel32.LocalFree.argtypes = (ctypes.wintypes.HLOCAL,)

class MemoryMap:
    """
    A memory map object which can have security attributes overridden.
    """

    def __init__(self, name, length, security_attributes=None):
        self.name = name
        self.length = length
        self.security_attributes = security_attributes
        self.pos = 0

    def __enter__(self):
        p_SA = ctypes.byref(self.security_attributes) if self.security_attributes else None
        INVALID_HANDLE_VALUE = -1
        PAGE_READWRITE = 4
        FILE_MAP_WRITE = 2
        filemap = ctypes.windll.kernel32.CreateFileMappingW(INVALID_HANDLE_VALUE, p_SA, PAGE_READWRITE, 0, self.length, u(self.name))
        handle_nonzero_success(filemap)
        if filemap == INVALID_HANDLE_VALUE:
            raise Exception('Failed to create file mapping')
        self.filemap = filemap
        self.view = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0)
        return self

    def read(self, n):
        """
        Read n bytes from mapped view.
        """
        if self.pos >= self.length:
            return b''
        
        remaining = self.length - self.pos
        to_read = min(n, remaining)
        
        # Create a buffer to read into
        buffer = ctypes.create_string_buffer(to_read)
        
        # Copy memory from the mapped view to our buffer
        ctypes.memmove(buffer, self.view + self.pos, to_read)
        
        # Update position
        self.pos += to_read
        
        return buffer.raw

    def __exit__(self, exc_type, exc_val, tb):
        ctypes.windll.kernel32.UnmapViewOfFile(self.view)
        ctypes.windll.kernel32.CloseHandle(self.filemap)
READ_CONTROL = 131072
STANDARD_RIGHTS_REQUIRED = 983040
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
STANDARD_RIGHTS_EXECUTE = READ_CONTROL
STANDARD_RIGHTS_ALL = 2031616
POLICY_VIEW_LOCAL_INFORMATION = 1
POLICY_VIEW_AUDIT_INFORMATION = 2
POLICY_GET_PRIVATE_INFORMATION = 4
POLICY_TRUST_ADMIN = 8
POLICY_CREATE_ACCOUNT = 16
POLICY_CREATE_SECRET = 32
POLICY_CREATE_PRIVILEGE = 64
POLICY_SET_DEFAULT_QUOTA_LIMITS = 128
POLICY_SET_AUDIT_REQUIREMENTS = 256
POLICY_AUDIT_LOG_ADMIN = 512
POLICY_SERVER_ADMIN = 1024
POLICY_LOOKUP_NAMES = 2048
POLICY_NOTIFICATION = 4096
POLICY_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | POLICY_VIEW_LOCAL_INFORMATION | POLICY_VIEW_AUDIT_INFORMATION | POLICY_GET_PRIVATE_INFORMATION | POLICY_TRUST_ADMIN | POLICY_CREATE_ACCOUNT | POLICY_CREATE_SECRET | POLICY_CREATE_PRIVILEGE | POLICY_SET_DEFAULT_QUOTA_LIMITS | POLICY_SET_AUDIT_REQUIREMENTS | POLICY_AUDIT_LOG_ADMIN | POLICY_SERVER_ADMIN | POLICY_LOOKUP_NAMES
POLICY_READ = STANDARD_RIGHTS_READ | POLICY_VIEW_AUDIT_INFORMATION | POLICY_GET_PRIVATE_INFORMATION
POLICY_WRITE = STANDARD_RIGHTS_WRITE | POLICY_TRUST_ADMIN | POLICY_CREATE_ACCOUNT | POLICY_CREATE_SECRET | POLICY_CREATE_PRIVILEGE | POLICY_SET_DEFAULT_QUOTA_LIMITS | POLICY_SET_AUDIT_REQUIREMENTS | POLICY_AUDIT_LOG_ADMIN | POLICY_SERVER_ADMIN
POLICY_EXECUTE = STANDARD_RIGHTS_EXECUTE | POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES

class TokenAccess:
    TOKEN_QUERY = 8

class TokenInformationClass:
    TokenUser = 1

class TOKEN_USER(ctypes.Structure):
    num = 1
    _fields_ = [('SID', ctypes.c_void_p), ('ATTRIBUTES', ctypes.wintypes.DWORD)]

class SECURITY_DESCRIPTOR(ctypes.Structure):
    """
    typedef struct _SECURITY_DESCRIPTOR
        {
        UCHAR Revision;
        UCHAR Sbz1;
        SECURITY_DESCRIPTOR_CONTROL Control;
        PSID Owner;
        PSID Group;
        PACL Sacl;
        PACL Dacl;
        }   SECURITY_DESCRIPTOR;
    """
    SECURITY_DESCRIPTOR_CONTROL = ctypes.wintypes.USHORT
    REVISION = 1
    _fields_ = [('Revision', ctypes.c_ubyte), ('Sbz1', ctypes.c_ubyte), ('Control', SECURITY_DESCRIPTOR_CONTROL), ('Owner', ctypes.c_void_p), ('Group', ctypes.c_void_p), ('Sacl', ctypes.c_void_p), ('Dacl', ctypes.c_void_p)]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    """
    typedef struct _SECURITY_ATTRIBUTES {
        DWORD  nLength;
        LPVOID lpSecurityDescriptor;
        BOOL   bInheritHandle;
    } SECURITY_ATTRIBUTES;
    """
    _fields_ = [('nLength', ctypes.wintypes.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p), ('bInheritHandle', ctypes.wintypes.BOOL)]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
ctypes.windll.advapi32.SetSecurityDescriptorOwner.argtypes = (ctypes.POINTER(SECURITY_DESCRIPTOR), ctypes.c_void_p, ctypes.wintypes.BOOL)

def GetTokenInformation(token, information_class):
    """
    Given a token, get the token information for it.
    """
    # First, determine the necessary buffer size
    buffer_size = ctypes.wintypes.DWORD()
    ctypes.windll.advapi32.GetTokenInformation(
        token,
        information_class,
        None,
        0,
        ctypes.byref(buffer_size)
    )
    
    # Allocate the buffer
    buffer = ctypes.create_string_buffer(buffer_size.value)
    
    # Now, get the actual token information
    success = ctypes.windll.advapi32.GetTokenInformation(
        token,
        information_class,
        buffer,
        buffer_size,
        ctypes.byref(buffer_size)
    )
    
    if not success:
        raise WindowsError()
    
    return buffer.raw

def get_current_user():
    """
    Return a TOKEN_USER for the owner of this process.
    """
    # Get the current process token
    token = ctypes.wintypes.HANDLE()
    success = ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        TokenAccess.TOKEN_QUERY,
        ctypes.byref(token)
    )
    if not success:
        raise WindowsError()

    try:
        # Get the TOKEN_USER structure
        token_user_buffer = GetTokenInformation(token, TokenInformationClass.TokenUser)
        return ctypes.cast(token_user_buffer, ctypes.POINTER(TOKEN_USER)).contents
    finally:
        ctypes.windll.kernel32.CloseHandle(token)

def get_security_attributes_for_user(user=None):
    """
    Return a SECURITY_ATTRIBUTES structure with the SID set to the
    specified user (uses current user if none is specified).
    """
    if user is None:
        user = get_current_user()

    # Create and initialize a security descriptor
    sd = SECURITY_DESCRIPTOR()
    ctypes.windll.advapi32.InitializeSecurityDescriptor(ctypes.byref(sd), SECURITY_DESCRIPTOR.REVISION)

    # Set the owner in the security descriptor
    ctypes.windll.advapi32.SetSecurityDescriptorOwner(ctypes.byref(sd), user.SID, False)

    # Create and initialize a security attributes structure
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.bInheritHandle = True
    sa.lpSecurityDescriptor = ctypes.addressof(sd)

    return sa
