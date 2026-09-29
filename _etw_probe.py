# -*- coding: utf-8 -*-
"""ETW内核会话探针: 哪种配置能真实交付Kernel-Process事件?
P1: 生产同款(REAL_TIME|SYSTEM_LOGGER, 具名)  P2: +显式Wnode.Guid  P3: 不写LoggerName
每配置5秒, 期间spawn子进程, 统计回调数与ProviderId。需管理员。"""
import ctypes, os, subprocess, sys, threading, time, uuid
from ctypes import (wintypes, byref, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_longlong,
                    Structure, POINTER, WINFUNCTYPE, sizeof, create_string_buffer, cast, c_byte)

adv = ctypes.windll.advapi32
k32 = ctypes.windll.kernel32
adv.EnableTraceEx2.restype = c_ulong
adv.EnableTraceEx2.argtypes = [c_ulonglong, c_void_p, c_ulong, c_ubyte, c_ulonglong, c_ulonglong, c_ulong, c_void_p]
adv.StartTraceW.argtypes = [POINTER(c_ulonglong), wintypes.LPCWSTR, c_void_p]
adv.ControlTraceW.argtypes = [c_ulonglong, wintypes.LPCWSTR, c_void_p, c_ulong]
SESSION = "SevenEtwProbe"
SELF = os.getpid()
PROC_GUID = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"

class WNODE_HEADER(Structure):
    _fields_ = [("BufferSize", c_ulong), ("Flags", c_ulong), ("HistoricalContext", c_ulonglong),
                ("TimeStamp", c_longlong), ("Guid", c_byte * 16), ("ClientContext", c_ulong),
                ("ClientData", c_ulong)]

class ETP(Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong),
                ("MaximumBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                ("FlushTimer", c_ulong), ("SessionHandle", c_ulong), ("LogFileNameOffset", c_ulong),
                ("LoggerNameOffset", c_ulong)]

def gbytes(s):
    return (c_byte * 16).from_buffer_copy(uuid.UUID(s).bytes_le)

def run(tag, mode, set_guid, with_name):
    n = [0]; guids = {}
    size = sizeof(ETP) + 2 * 1024
    buf = create_string_buffer(size)
    p = cast(buf, POINTER(ETP)).contents
    p.Wnode.BufferSize = size
    p.Wnode.Flags = 0x00020000
    p.Wnode.ClientContext = 1
    p.LogfileMode = mode
    p.BufferSize = 64; p.MinimumBuffers = 16; p.MaximumBuffers = 64; p.FlushTimer = 1
    p.LoggerNameOffset = sizeof(ETP)
    if set_guid:
        ctypes.memmove(byref(p.Wnode.Guid), gbytes("a7f5b1c2-1111-2222-3333-444455556666"), 16)
    if with_name:
        nb = SESSION.encode('utf-16-le') + b'\x00\x00'
        ctypes.memmove(byref(buf, p.LoggerNameOffset), nb, len(nb))
    h = c_ulonglong(0)
    adv.StartTraceW(byref(h), SESSION if with_name else None, byref(buf))
    serr = k32.GetLastError()
    g = gbytes(PROC_GUID)
    rc_en = adv.EnableTraceEx2(h.value, cast(g, c_void_p), 1, 5, 0, 0, 0, None)

    def on_ev(ptr):
        n[0] += 1
        raw = ctypes.string_at(ptr, 48)
        pg = str(uuid.UUID(bytes_le=raw[32:48])).upper()
        guids[pg] = guids.get(pg, 0) + 1
    cb = WINFUNCTYPE(None, c_void_p)(on_ev)

    def _run():
        harr = (c_ulonglong * 1)(h)
        adv.ProcessTrace(harr, 1, None, None)
    threading.Thread(target=_run, daemon=True).start()
    end = time.time() + 5
    while time.time() < end:
        subprocess.run(['cmd', '/c', 'echo probe'], capture_output=True, creationflags=0x08000000)
        time.sleep(0.5)
    adv.ControlTraceW(h.value, SESSION, byref(buf), 1)
    time.sleep(0.5)
    print(f"{tag}: events={n[0]} start_err={serr} enable_rc={rc_en} providers={list(guids.items())[:3]}", flush=True)

RT, SYS = 0x00000100, 0x02000000
if not ctypes.windll.shell32.IsUserAnAdmin():
    print('need admin'); sys.exit(1)
subprocess.run(['logman', '-ets', 'stop', SESSION], capture_output=True, creationflags=0x08000000)
run('P1 生产同款+SYSTEM_LOGGER+具名', RT | SYS, False, True)
run('P2 +显式Wnode.Guid', RT | SYS, True, True)
run('P3 SYSTEM_LOGGER+匿名', RT | SYS, False, False)
run('P4 仅REAL_TIME(生产原样)', RT, False, True)
