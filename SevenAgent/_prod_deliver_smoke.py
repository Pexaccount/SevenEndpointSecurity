# -*- coding: utf-8 -*-
"""Product-directory smoke: run the DEPLOYED SevenAgent.exe --test elevated,
spawn a harmless malicious-rule trigger child, and verify over the named pipe
that the real PID alert (family=malicious, action=terminate) is delivered and
written to the product agent_alerts.log."""
import ctypes, json, os, socket, subprocess, sys, threading, time
from ctypes import wintypes

PROD = r"C:\Program Files\SevenEndpointSecurity\SevenAgent"
EXE = os.path.join(PROD, "SevenAgent.exe")
PIPE_NAME = r"\\.\pipe\SevenAgentIPC"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateNamedPipeW.restype = wintypes.HANDLE
k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, ctypes.c_void_p]
k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE

adv = ctypes.WinDLL("advapi32", use_last_error=True)
sd = ctypes.c_void_p()
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
    ctypes.create_unicode_buffer("D:(A;;GA;;;WD)"), 1, ctypes.byref(sd), None)
class SA(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]
sa = SA(nLength=ctypes.sizeof(SA), lpSecurityDescriptor=sd, bInheritHandle=False)

msgs = []
lock = threading.Lock()
stop = [False]

def server():
    while not stop[0]:
        h = k32.CreateNamedPipeW(PIPE_NAME, 3, 0, 255, 8192, 8192, 0,
                                 ctypes.byref(sa))
        if not h or (int(h) & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF:
            time.sleep(0.1); continue
        ok = k32.ConnectNamedPipe(h, None)
        if not ok and ctypes.get_last_error() != 535:
            k32.CloseHandle(h); continue
        buf = ctypes.create_string_buffer(4096); n = wintypes.DWORD(0); acc = b""
        while not stop[0]:
            if not k32.ReadFile(h, buf, 4096, ctypes.byref(n), None) or n.value == 0:
                break
            acc += buf.raw[:n.value]
            if b"\n" in acc:
                break
        if acc.strip():
            with lock:
                msgs.append(acc.decode("utf-8", "replace"))
        k32.DisconnectNamedPipe(h)
        k32.CloseHandle(h)

def run_elev(text, wait):
    bat = os.path.join(os.environ["TEMP"], "_prod_smoke_step.bat")
    open(bat, "w").write(text)
    sh = ctypes.WinDLL("shell32")
    sh.ShellExecuteW.restype = ctypes.c_void_p
    r = sh.ShellExecuteW(None, "runas", "cmd.exe", '/c ""%s""' % bat, PROD, 0)
    time.sleep(wait)
    return int(r or 0) > 32

alert_p = os.path.join(PROD, "agent_alerts.log")
diag_p = os.path.join(PROD, "agent_diag.log")
a0 = os.path.getsize(alert_p) if os.path.exists(alert_p) else 0
d0 = os.path.getsize(diag_p) if os.path.exists(diag_p) else 0

t = threading.Thread(target=server, daemon=True); t.start(); time.sleep(0.5)
run_elev('logman stop "SevenAgent-Process" -ets >nul 2>&1\r\n'
         'taskkill /F /IM SevenAgent.exe >nul 2>&1\r\n'
         'cd /d "%s"\r\n"%s" --test > "%s\\_prod_smoke_out.log" 2>&1\r\n'
         % (PROD, EXE, PROD), 6)

child = subprocess.Popen(
    ["cmd.exe", "/c", "echo NET STOP WINDEFEND & ping -n 6 127.0.0.1 >nul"],
    cwd=PROD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
cpid = child.pid

expected = None
deadline = time.time() + 30
while time.time() < deadline:
    with lock:
        for m in list(msgs):
            try: jj = json.loads(m)
            except Exception: continue
            if jj.get("rule") == "Agent.Cmdline.Malicious" and jj.get("pid") == cpid:
                expected = jj; break
    if expected: break
    time.sleep(0.5)
try: child.wait(timeout=5)
except Exception: child.kill()
time.sleep(1)
stop[0] = True
try:
    h = k32.CreateFileW(PIPE_NAME, 0x80000000, 0, None, 3, 0, None, None)
    if h and (int(h) & 0xFFFFFFFFFFFFFFFF) != 0xFFFFFFFFFFFFFFFF:
        k32.CloseHandle(h)
except Exception: pass
run_elev('taskkill /F /IM SevenAgent.exe >nul 2>&1\r\n'
         'logman stop "SevenAgent-Process" -ets >nul 2>&1\r\nexit\r\n', 3)

ok = True
def check(name, cond, detail=""):
    global ok
    print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                        ("  [%s]" % str(detail)[:200]) if not cond else ""))
    if not cond: ok = False

check("S1 malicious-rule alert with real child PID received via pipe",
      expected is not None, "child=%d msgs=%s" % (cpid, [m[:100] for m in msgs][:5]))
if expected:
    check("S2 fields family=malicious action=terminate pid>0 score=100",
          expected.get("family") == "malicious" and expected.get("action") == "terminate"
          and expected.get("pid", 0) > 0 and expected.get("score") == 100,
          json.dumps(expected, ensure_ascii=False))
tail_alert = ""
if os.path.exists(alert_p) and os.path.getsize(alert_p) > a0:
    with open(alert_p, "r", encoding="utf-8", errors="replace") as f:
        f.seek(a0); tail_alert = f.read()
check("S3 product agent_alerts.log got the alert line", "Agent.Cmdline.Malicious" in tail_alert)
tail_diag = ""
if os.path.exists(diag_p) and os.path.getsize(diag_p) > d0:
    with open(diag_p, "r", encoding="utf-8", errors="replace") as f:
        f.seek(d0); tail_diag = f.read()
check("S4 diag: HIT + DELIVER sent", ("HIT pid=%d" % cpid) in tail_diag and "DELIVER sent" in tail_diag)
check("S5 WMI source active", ("WMI mode=PULL" in tail_diag) or ("PUSH mode" in tail_diag))
sys.exit(0 if ok else 1)
