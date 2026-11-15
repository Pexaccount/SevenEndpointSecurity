# -*- coding: utf-8 -*-
"""End-to-end PID delivery verification for SevenAgent v4 dual-channel delivery.

Verifies the user-facing contract "alert 必须有日志、必须发送 PID":
  P1  pipe PRIMARY  : LoopbackTest JSON arrives via \\\\.\\pipe\\SevenAgentIPC
                      AND agent_alerts.log still gets the same line (file ALWAYS)
  P2  TCP FALLBACK  : with no pipe server, the same message arrives via 127.0.0.1:47821
  P3  REAL DETECTION (elevated --test): WMI source sees a live child whose cmdline
      matches rule Agent.Cmdline.Malicious ("NET STOP WINDEFEND"); the pipe server
      receives family=malicious / action=terminate / pid=<real child pid> / score=100,
      diag shows HIT + DELIVER sent, alerts file gets the local copy.

No destructive action: the trigger is `cmd /c echo NET STOP WINDEFEND & ping`
(echo only - the service is never touched).
Run non-elevated; elevation for P3 uses ShellExecuteW runas (UAC silent consent).
"""
import ctypes, json, os, re, shutil, socket, subprocess, sys, threading, time
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "SevenAgent.c")
SMOKE = os.path.join(HERE, "_deliver_smoke")
TCC = r"D:\wend\UsingLang\backend\tcc\tcc.exe"
EMBED = r"C:\Users\Administrator\WorkBuddy\2026-11-14-11-51-27\_embed_manifest.py"
PIPE_NAME = r"\\.\pipe\SevenAgentIPC"
TCP_PORT = 47821

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond), str(detail)[:300]))

# ---------- ctypes: named pipe server ----------
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32.CreateNamedPipeW.restype = wintypes.HANDLE
k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, ctypes.c_void_p]
k32.ConnectNamedPipe.restype = wintypes.BOOL
k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.ReadFile.restype = wintypes.BOOL
k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, ctypes.c_void_p]

sd = ctypes.c_void_p()
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
    ctypes.create_unicode_buffer("D:(A;;GA;;;WD)"), 1, ctypes.byref(sd), None)
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]
SA = SECURITY_ATTRIBUTES(nLength=ctypes.sizeof(SECURITY_ATTRIBUTES),
                         lpSecurityDescriptor=sd, bInheritHandle=False)
k32.CloseHandle.argtypes = [wintypes.HANDLE]

class PipeServer(threading.Thread):
    """Multi-instance byte-mode server; records every complete '\n'-terminated line."""
    def __init__(self):
        super().__init__(daemon=True)
        self.stop_flag = False
        self.messages = []
        self.lock = threading.Lock()
    def run(self):
        while not self.stop_flag:
            h = k32.CreateNamedPipeW(PIPE_NAME, 3, 0, 255, 8192, 8192, 0,
                                     ctypes.byref(SA))
            if not h or (int(h) & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF:
                time.sleep(0.1); continue
            ok = k32.ConnectNamedPipe(h, None)
            err = ctypes.get_last_error()
            if not ok and err != 535:  # ERROR_PIPE_CONNECTED
                k32.CloseHandle(h); continue
            buf = ctypes.create_string_buffer(4096); n = wintypes.DWORD(0)
            acc = b""
            while not self.stop_flag:
                if not k32.ReadFile(h, buf, 4096, ctypes.byref(n), None) or n.value == 0:
                    break
                acc += buf.raw[:n.value]
                if b"\n" in acc:
                    break
            if acc.strip():
                with self.lock:
                    self.messages.append(acc.decode("utf-8", "replace"))
            k32.DisconnectNamedPipe(h)
            k32.CloseHandle(h)
    def stop(self):
        self.stop_flag = True
        try:  # wake the blocked accept with a throwaway client connection
            h = k32.CreateFileW(PIPE_NAME, 0x80000000, 0, None, 3, 0, None, None)
            if h and (int(h) & 0xFFFFFFFFFFFFFFFF) != 0xFFFFFFFFFFFFFFFF:
                k32.CloseHandle(h)
        except Exception:
            pass
        self.join(3)

class TcpServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.stop_flag = False
        self.messages = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", TCP_PORT))
        self.sock.listen(4)
    def run(self):
        self.sock.settimeout(1.0)
        while not self.stop_flag:
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            c.settimeout(10.0)
            acc = b""
            try:
                while b"\n" not in acc:
                    d = c.recv(4096)
                    if not d: break
                    acc += d
            except OSError:
                pass
            c.close()
            if acc.strip():
                self.messages.append(acc.decode("utf-8", "replace"))
    def stop(self):
        self.stop_flag = True
        try: self.sock.close()
        except Exception: pass
        self.join(3)

def tail(path, offset):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        return f.read()

def size_of(path):
    return os.path.getsize(path) if os.path.exists(path) else 0

def run_elevated_bat(text, wait):
    bat = os.path.join(SMOKE, "_step.bat")
    open(bat, "w").write(text)
    sh = ctypes.WinDLL("shell32")
    sh.ShellExecuteW.restype = ctypes.c_void_p
    r = sh.ShellExecuteW(None, "runas", "cmd.exe", '/c ""%s""' % bat, SMOKE, 0)
    time.sleep(wait)
    return int(r or 0) > 32

# ---------- build fresh binaries ----------
os.makedirs(SMOKE, exist_ok=True)
for f in ("agent_diag.log", "agent_alerts.log", "smoke_stdout.log"):
    p = os.path.join(SMOKE, f)
    if os.path.exists(p): os.remove(p)
shutil.copy2(os.path.join(HERE, "agent_rules.json"), SMOKE)

r = subprocess.run([TCC, "-o", os.path.join(SMOKE, "SevenAgent_testbare.exe"), SRC,
                    "-ladvapi32", "-lkernel32", "-luser32", "-lshell32", "-lole32",
                    "-lws2_32"], capture_output=True, text=True)
check("P0a fresh bare build (zero errors)",
      r.returncode == 0 and "error" not in (r.stderr or ""), (r.stderr or "")[:200])
if r.returncode != 0:
    print("BUILD FAILED"); sys.exit(1)

BARE = os.path.join(SMOKE, "SevenAgent_testbare.exe")
EXE = os.path.join(SMOKE, "SevenAgent.exe")
diag_p = os.path.join(SMOKE, "agent_diag.log")
alert_p = os.path.join(SMOKE, "agent_alerts.log")

# ---------- P1: pipe primary + local file ----------
ps = PipeServer(); ps.start(); time.sleep(0.5)
a0 = size_of(alert_p)
lb = subprocess.run([BARE, "--LoopbackTest"], capture_output=True, text=True,
                    cwd=SMOKE, timeout=60)
time.sleep(0.5)
p1_msgs = list(ps.messages); ps.stop()
p1_json = [m for m in p1_msgs if m.strip()]
try:
    j = json.loads(p1_json[-1]) if p1_json else {}
except Exception:
    j = {}
check("P1a LoopbackTest exit 0", lb.returncode == 0, lb.returncode)
check("P1b JSON arrived via named pipe",
      j.get("behavior") == "Loopback.Test" and "pid" in j and "chain_key" in j,
      p1_json[-1][:200] if p1_json else "no message")
check("P1c local agent_alerts.log also written (file ALWAYS)",
      size_of(alert_p) > a0 and "Loopback.Test" in tail(alert_p, a0))
d1 = tail(diag_p, 0)
check("P1d diag shows DELIVER sent pipe=1",
      "DELIVER sent pipe=1" in d1 and "ALERT {\"pid\"" in d1, d1[-300:])

# ---------- P2: TCP fallback (no pipe server) ----------
time.sleep(1.0)  # let P1 instances die
ts = TcpServer(); ts.start(); time.sleep(0.5)
a1 = size_of(alert_p); d1sz = size_of(diag_p)
lb2 = subprocess.run([BARE, "--LoopbackTest"], capture_output=True, text=True,
                     cwd=SMOKE, timeout=60)
deadline = time.time() + 5
while not ts.messages and time.time() < deadline:
    time.sleep(0.2)
ts.stop()
try:
    j2 = json.loads(ts.messages[-1]) if ts.messages else {}
except Exception:
    j2 = {}
check("P2a LoopbackTest exit 0 (TCP path)", lb2.returncode == 0, lb2.returncode)
check("P2b JSON arrived via TCP 47821 fallback",
      j2.get("behavior") == "Loopback.Test" and "pid" in j2,
      (ts.messages[-1][:200] if ts.messages else "no message"))
d2 = tail(diag_p, d1sz)
check("P2c diag shows TCP fallback used (pipe=0 tcp=1)",
      "DELIVER sent pipe=0 tcp=1" in d2, d2[-300:])
check("P2d local agent_alerts.log also written",
      size_of(alert_p) > a1 and "Loopback.Test" in tail(alert_p, a1))

# ---------- P3: real detection, elevated --test, PID over pipe ----------
r = subprocess.run([TCC, "-o", EXE, SRC, "-ladvapi32", "-lkernel32", "-luser32",
                    "-lshell32", "-lole32", "-lws2_32"], capture_output=True, text=True)
check("P3a fresh manifest-exe build", r.returncode == 0, (r.stderr or "")[:200])
import importlib.util
spec = importlib.util.spec_from_file_location("em", EMBED)
em = importlib.util.module_from_spec(spec); spec.loader.exec_module(em)
em.embed(EXE)

ps3 = PipeServer(); ps3.start(); time.sleep(0.5)
d2sz = size_of(diag_p); a2 = size_of(alert_p)
run_elevated_bat(
    'logman stop "SevenAgent-Process" -ets >nul 2>&1\r\n'
    'taskkill /F /IM SevenAgent.exe >nul 2>&1\r\n'
    'cd /d "%s"\r\n'
    '"%s" --test > "%s\\smoke_stdout.log" 2>&1\r\n' % (SMOKE, EXE, SMOKE), 6)

child = subprocess.Popen(
    ["cmd.exe", "/c", "echo NET STOP WINDEFEND & ping -n 5 127.0.0.1 >nul"],
    cwd=SMOKE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
child_pid = child.pid

expected = None
deadline = time.time() + 30
while time.time() < deadline:
    with ps3.lock:
        for m in list(ps3.messages):
            try:
                jj = json.loads(m)
            except Exception:
                continue
            if (jj.get("rule") == "Agent.Cmdline.Malicious" and
                    jj.get("pid") == child_pid):
                expected = jj; break
    if expected:
        break
    time.sleep(0.5)

try:
    child.wait(timeout=5)
except Exception:
    child.kill()
time.sleep(1.0)
ps3.stop()
run_elevated_bat('taskkill /F /IM SevenAgent.exe >nul 2>&1\r\n'
                 'logman stop "SevenAgent-Process" -ets >nul 2>&1\r\nexit\r\n', 3)
d3 = tail(diag_p, d2sz)

check("P3b malicious-rule message with REAL child PID via pipe",
      expected is not None,
      "child=%d msgs=%s" % (child_pid, [m[:120] for m in ps3.messages][:6]))
if expected:
    check("P3c message fields: family=malicious action=terminate score=100",
          expected.get("family") == "malicious" and
          expected.get("action") == "terminate" and
          expected.get("score") == 100 and expected.get("pid") > 0,
          json.dumps(expected, ensure_ascii=False)[:300])
check("P3d diag shows rule HIT for the child pid",
      ("HIT pid=%d rule=Agent.Cmdline.Malicious" % child_pid) in d3, d3[-400:])
check("P3e diag shows DELIVER sent",
      "DELIVER sent pipe=" in d3, d3[-400:])
check("P3f WMI event source active (PUSH or PULL)",
      ("WMI mode=PULL" in d3) or ("PUSH mode" in d3), "")
check("P3g alert also in local agent_alerts.log",
      size_of(alert_p) > a2 and "Agent.Cmdline.Malicious" in tail(alert_p, a2))

# ---------- summary ----------
npass = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name,
                        ("  [%s]" % detail) if (detail and not ok) else ""))
print("== %d/%d PASS ==" % (npass, len(results)))
sys.exit(0 if npass == len(results) else 1)
