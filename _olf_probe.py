# -*- coding: utf-8 -*-
"""穷举 EVENT_TRACE_LOGFILEW 的 EVENT_TRACE/TRACE_LOGFILE_HEADER 尺寸组合,
找出 EventRecordCallback 真实偏移(端到端回调>0即正确)。需管理员。"""
import ctypes, os, sys, struct, threading, time, subprocess, uuid
from ctypes import (wintypes, byref, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_longlong,
                    c_char, Structure, POINTER, WINFUNCTYPE, sizeof, create_string_buffer, cast, c_byte)
adv = ctypes.windll.advapi32; k32 = ctypes.windll.kernel32
adv.EnableTraceEx2.argtypes = [c_ulonglong, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_ulonglong, c_ulong, c_void_p]
adv.StartTraceW.argtypes = [POINTER(c_ulonglong), wintypes.LPCWSTR, c_void_p]
adv.OpenTraceW.restype = c_ulonglong
adv.OpenTraceW.argtypes = [c_void_p]
adv.ProcessTrace.restype = c_ulong
adv.ProcessTrace.argtypes = [POINTER(c_ulonglong), c_ulong, c_void_p, c_void_p]
adv.CloseTrace.restype = c_ulong
adv.CloseTrace.argtypes = [c_ulonglong]
adv.ControlTraceW.argtypes = [c_ulonglong, wintypes.LPCWSTR, c_void_p, c_ulong]

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

SESSION = "SevenEtwOlfProbe"
PROC_GUID = uuid.UUID("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")

size = sizeof(ETP) + 2*1024
sbuf = create_string_buffer(size)
p = cast(sbuf, POINTER(ETP)).contents
p.Wnode.BufferSize = size; p.Wnode.Flags = 0x00020000; p.Wnode.ClientContext = 1
p.LogFileMode = 0x00000100 | 0x02000000
p.BufferSize = 64; p.MinimumBuffers = 16; p.MaximumBuffers = 64; p.FlushTimer = 1
p.LoggerNameOffset = sizeof(ETP)
nb = SESSION.encode('utf-16-le') + b'\x00\x00'
ctypes.memmove(byref(sbuf, p.LoggerNameOffset), nb, len(nb))
h = c_ulonglong(0)
rc = adv.StartTraceW(byref(h), SESSION, byref(sbuf))
if rc == 183:
    adv.ControlTraceW(0, SESSION, byref(sbuf), 1)
    time.sleep(1)
    rc = adv.StartTraceW(byref(h), SESSION, byref(sbuf))
print('start rc', rc, flush=True)
g = (c_byte*16).from_buffer_copy(PROC_GUID.bytes_le)
adv.EnableTraceEx2(h.value, cast(g, c_void_p), 1, 5, 0, 0, 0, None)

count = [0]
def on_record(ptr):
    count[0] += 1
CB_TYPE = WINFUNCTYPE(None, c_void_p)

def try_combo(ev_size, lf_size, legacy=False):
    count[0] = 0
    ptrc = [0]
    cb = CB_TYPE(on_record)
    name_buf = ctypes.create_unicode_buffer(SESSION)
    name_addr = ctypes.addressof(name_buf)
    total = 32 + ev_size + lf_size + 8 + 12 + 8 + 8 + 64
    buf = bytearray(total)
    struct.pack_into('<Q', buf, 0, name_addr)                 # LogFileName
    struct.pack_into('<Q', buf, 8, name_addr)                 # LoggerName
    struct.pack_into('<I', buf, 24, 0)                        # BuffersRead
    struct.pack_into('<I', buf, 28, 0x00000100 | (0 if legacy else 0x10000000))
    cb_off = 32 + ev_size + lf_size + 8 + 12                  # BufferCallback(8) + BufferSize/Filled/EventsLost(12)
    struct.pack_into('<Q', buf, cb_off, ctypes.cast(cb, c_void_p).value)
    lfb = (c_char * len(buf)).from_buffer(buf)
    hlog = adv.OpenTraceW(byref(lfb))
    if hlog in (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0):
        print(f'ev={ev_size} lf={lf_size}: OpenTrace失败({hlog & 0xFFFFFFFFFFFFFFFF})', flush=True)
        return
    def _pt():
        try:
            ptrc[0] = adv.ProcessTrace((c_ulonglong*1)(hlog), 1, None, None)
        except Exception as e:
            print('pt exc', e, flush=True)
    t = threading.Thread(target=_pt, daemon=True)
    t.start()
    end = time.time() + 4
    while time.time() < end:
        subprocess.run(['cmd', '/c', 'echo probe'], capture_output=True, creationflags=0x08000000)
        time.sleep(0.4)
    adv.CloseTrace(hlog)
    t.join(timeout=2)
    tag = 'legacy' if legacy else 'record'
    print(f'ev={ev_size} lf={lf_size} {tag}: events={count[0]} ptrc={ptrc[0]}', flush=True)

if not ctypes.windll.shell32.IsUserAnAdmin():
    print('need admin'); sys.exit(1)
for ev in (152, 88):
    for lf in (384, 392):
        try_combo(ev, lf, legacy=False)
        try_combo(ev, lf, legacy=True)
