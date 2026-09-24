# -*- coding: utf-8 -*-
"""探针: 复现 _process_loop 对新进程的处理链路, 定位 hello.exe 为何不被快速拦截。"""
import ctypes, os, sys, time, subprocess

k32 = ctypes.windll.kernel32
TH32CS_SNAPPROCESS = 0x00000002


class PE32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeap", ctypes.c_void_p),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260)]


def snapshot():
    h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
    out = {}
    if h and k32.Process32FirstW(h, ctypes.byref(pe)):
        while True:
            out[pe.th32ProcessID] = (pe.szExeFile, pe.th32ParentProcessID)
            if not k32.Process32NextW(h, ctypes.byref(pe)):
                break
    k32.CloseHandle(h)
    return out


def get_path(pid):
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return "<OpenProcess failed>"
    buf = ctypes.create_unicode_buffer(260)
    size = ctypes.c_ulong(260)
    ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
    k32.CloseHandle(h)
    return buf.value if ok else "<QueryImageName failed>"


hello = os.path.abspath(os.path.join("EDRTest", "hello.exe"))
before = set(snapshot().keys())
p = subprocess.Popen([hello], cwd="EDRTest")
time.sleep(0.3)
after = snapshot()
new = set(after.keys()) - before
print("new pids after launch:", [(pid, after[pid][0]) for pid in new])
for pid in new:
    nm = after[pid][0]
    if nm.lower() in ("hello.exe",):
        print("  pid", pid, nm, "path ->", get_path(pid))
# 找hello相关全部进程
for pid, (nm, pp) in after.items():
    if 'hello' in nm.lower():
        print("found:", pid, nm, "ppid", pp, "path ->", get_path(pid))
time.sleep(2)
p.kill()
subprocess.run(["taskkill", "/f", "/im", "hello.exe"], capture_output=True)
print("done")
