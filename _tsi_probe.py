# -*- coding: utf-8 -*-
import ctypes, os, sys, time, subprocess, uuid
from ctypes import (wintypes, byref, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_longlong,
                    Structure, POINTER, WINFUNCTYPE, sizeof, create_string_buffer, cast, c_byte)
adv = ctypes.windll.advapi32; k32 = ctypes.windll.kernel32
adv.EnableTraceEx2.argtypes = [c_ulonglong, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_ulonglong, c_ulong, c_void_p]
adv.StartTraceW.argtypes = [POINTER(c_ulonglong), wintypes.LPCWSTR, c_void_p]
adv.TraceSetInformation.restype = c_ulong
adv.TraceSetInformation.argtypes = [c_ulonglong, c_ulong, c_void_p, c_ulong]

class WNODE_HEADER(Structure):
    _fields_ = [("BufferSize", c_ulong), ("ProviderId", c_ulong), ("HistoricalContext", c_ulonglong),
                ("TimeStamp", c_longlong), ("Guid", c_byte*16), ("ClientContext", c_ulong), ("Flags", c_ulong)]
class ETP(Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong),
                ("MaximumBuffers", c_ulong), ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong),
                ("FlushTimer", c_ulong), ("EnableFlags", c_ulong), ("AgeLimit", c_ulong),
                ("NumberOfBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                ("BuffersWritten", c_ulong), ("LogBuffersLost", c_ulong), ("RealTimeBuffersLost", c_ulong),
                ("LoggerThreadId", c_void_p), ("LogFileNameOffset", c_ulong), ("LoggerNameOffset", c_ulong)]

SESSION = "SevenEtwTsiProbe"
def start():
    size = sizeof(ETP) + 2*1024
    buf = create_string_buffer(size)
    p = cast(buf, POINTER(ETP)).contents
    p.Wnode.BufferSize = size; p.Wnode.Flags = 0x00020000; p.Wnode.ClientContext = 1
    p.LogFileMode = 0x00000100 | 0x02000000
    p.BufferSize = 64; p.MinimumBuffers = 16; p.MaximumBuffers = 64; p.FlushTimer = 1
    p.LoggerNameOffset = sizeof(ETP)
    nb = SESSION.encode('utf-16-le') + b'\x00\x00'
    ctypes.memmove(byref(buf, p.LoggerNameOffset), nb, len(nb))
    h = c_ulonglong(0)
    rc = adv.StartTraceW(byref(h), SESSION, byref(buf))
    return h, rc, buf

ok_classes = []
h, rc, buf = start()
print('start rc', rc, flush=True)
if rc == 0:
    for v in range(0, 41):
        r = adv.TraceSetInformation(h, v, None, 0)
        if r == 0:
            ok_classes.append(v)
    print('TraceSetInformation success classes:', ok_classes, flush=True)
    adv.ControlTraceW(h.value, SESSION, byref(buf), 1)
