"""
Functions for communicating with Pageant, the basic windows ssh agent program.
"""
import array
import ctypes.wintypes
import platform
import struct
from paramiko.common import zero_byte
from paramiko.util import b
import _thread as thread
from . import _winapi
_AGENT_COPYDATA_ID = 2152616122
_AGENT_MAX_MSGLEN = 8192
win32con_WM_COPYDATA = 74

def can_talk_to_agent():
    """
    Check to see if there is a "Pageant" agent we can talk to.

    This checks both if we have the required libraries (win32all or ctypes)
    and if there is a Pageant currently running.
    """
    try:
        import ctypes

        # Try to find the Pageant window
        hwnd = ctypes.windll.user32.FindWindowA(b"Pageant", b"Pageant")
        if hwnd == 0:
            return False
        
        # We found a Pageant window, so we can talk to the agent
        return True
    except ImportError:
        # If we can't import ctypes, we can't talk to Pageant
        return False
if platform.architecture()[0] == '64bit':
    ULONG_PTR = ctypes.c_uint64
else:
    ULONG_PTR = ctypes.c_uint32

class COPYDATASTRUCT(ctypes.Structure):
    """
    ctypes implementation of
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms649010%28v=vs.85%29.aspx
    """
    _fields_ = [('num_data', ULONG_PTR), ('data_size', ctypes.wintypes.DWORD), ('data_loc', ctypes.c_void_p)]

def _query_pageant(msg):
    """
    Communication with the Pageant process is done through a shared
    memory-mapped file.
    """
    import ctypes
    from . import _winapi

    hwnd = ctypes.windll.user32.FindWindowA(b"Pageant", b"Pageant")
    if hwnd == 0:
        raise Exception("Pageant not found")

    # Allocate some memory
    size = len(msg)
    mem = _winapi.GlobalAlloc(_winapi.GMEM_MOVEABLE, size)
    if mem == 0:
        raise _winapi.WindowsError()

    try:
        # Lock the memory and copy the message into it
        ptr = _winapi.GlobalLock(mem)
        if ptr == 0:
            raise _winapi.WindowsError()
        try:
            ctypes.memmove(ptr, msg, size)
        finally:
            _winapi.GlobalUnlock(mem)

        # Prepare the COPYDATASTRUCT
        cds = _winapi.COPYDATASTRUCT()
        cds.num_data = _AGENT_COPYDATA_ID
        cds.data_size = size
        cds.data_loc = mem

        # Send the message
        response = ctypes.c_long()
        r = ctypes.windll.user32.SendMessageA(
            hwnd, win32con_WM_COPYDATA, 0, ctypes.byref(cds)
        )
        if r == 0:
            raise Exception("Pageant failed to respond")

        # Retrieve the response
        rsize = _winapi.GlobalSize(mem)
        response = (ctypes.c_byte * rsize)()
        ctypes.memmove(response, ptr, rsize)

        return bytes(response)

    finally:
        _winapi.GlobalFree(mem)

class PageantConnection:
    """
    Mock "connection" to an agent which roughly approximates the behavior of
    a unix local-domain socket (as used by Agent).  Requests are sent to the
    pageant daemon via special Windows magick, and responses are buffered back
    for subsequent reads.
    """

    def __init__(self):
        self._response = None
