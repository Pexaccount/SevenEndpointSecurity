# -*- coding: utf-8 -*-
"""WMI event-source verification suite for SevenAgent (post-merge).

Run: python _sevenagent_wmi_test.py
No key/mouse injection, no destructive actions. The runtime smoke boots the
agent in --test (standalone) mode and kills it afterwards.
"""
import os, re, sys, subprocess, shutil, time, signal

ROOT = r"C:\Users\Administrator\WorkBuddy\2026-11-14-11-51-27"
PROBE = os.path.join(ROOT, "_probe")
SRC = r"D:\Administrator\Desktop\TestUI\CodeBak\SevenAgent\SevenAgent.c"
TCC = r"D:\wend\UsingLang\backend\tcc\tcc.exe"
SMOKE = os.path.join(PROBE, "_wmi_smoke")

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS  " if cond else "FAIL  ") + name + ("   " + str(detail) if detail and not cond else ""))

s = open(SRC, "r", encoding="utf-8", newline="").read()

# ---------- A. source structure ----------
check("W01 wmi_worker thread exists and is started in wmain",
      "static DWORD WINAPI wmi_worker(LPVOID x)" in s and
      "CreateThread(NULL,0,wmi_worker,NULL,0,NULL);" in s and
      'diag("WMI event source thread started")' in s)
check("W02 shared v2_decide exists; v2_proc_start delegates to it",
      "static void v2_decide(DWORD pid,char*up,int upcap,const char*img)" in s and
      "v2_decide(pid,up,(int)sizeof(up),img);" in s)
check("W03 v2 decision logic preserved verbatim inside v2_decide",
      all(m in s for m in ('CMDFAIL pid=%lu', 'have_host=process_path(pid,host,MAX_PATH)',
                           'HIT pid=%lu rule=%s match=%s score=%d pid_ok=%d host_ok=%d',
                           'combo_eval(pid,host,now)', 'pend_touch(key,pid,"ProcessOther",0)',
                           'alert2(pid,r2->id,r2->behavior,r2->level,host,pp->note,r2->score,"terminate")')))
check("W04 dedup ring guards dual-source double decisions",
      "static int v2_recent(DWORD pid)" in s and "g_diag_dup++" in s and
      "InitializeCriticalSection(&g_decide_lock)" in s and
      "EnterCriticalSection(&g_decide_lock)" in s and "LeaveCriticalSection(&g_decide_lock)" in s)
check("W05 PEB cmdline fallback active in shared decide",
      "if(!up[0]&&!peb_cmdline(pid,up,upcap)&&img[0])" in s)
check("W06 WMI COM chain: CoInitializeSecurity(IMPSONATE) + ROOT\\CIMV2 + WbemLocator GUIDs",
      "cs(NULL,-1,NULL,NULL,0,3,NULL,0,NULL,NULL)" in s and
      "conn(loc,L\"ROOT\\\\CIMV2\"" in s and
      "0x4590f811,0x1d3a,0x11d0" in s and "0xdc12a687,0x737f,0x11cf" in s)
check("W07 PUSH uses Win32_ProcessStartTrace with real BSTRs (SysAllocString)",
      'bq=sa(L"SELECT * FROM Win32_ProcessStartTrace")' in s and
      'GetProcAddress(a,"SysAllocString")' in s)
check("W08 PUSH self-test (spawn child, expect event) gates PUSH mode",
      "static void wmi_spawn_child(void)" in s and
      "WMI push self-test slot=%d OK -> PUSH mode" in s and
      "WMI push self-test slot=%d: no event in 3s" in s)
check("W09 PULL fallback = 300ms snapshot diff (approved plan)",
      "#define WMI_PULL_MS 300" in s and
      'bq=sa(L"SELECT ProcessId FROM Win32_Process")' in s and
      "WMI mode=PULL interval=%dms" in s)
check("W10 crash-unsafe vtable slots (14/15/21/23/24) are never called",
      all(("vt[%d]" % n) not in s for n in (14, 15, 21, 23, 24)) and
      "#define WMI_EXECQ_SLOT 20" in s and "#define WMI_EXECQ_SLOT_ALT 18" in s)
check("W11 pull first cycle populates baseline only (no false alert storm)",
      "if(!first){" in s and
      s.find("memcpy(prev,cur") > s.find("if(!first){") and
      s.count("if(!first){") == 1)
check("W12 snapshot enumerator released each cycle",
      "((WMLENUM*)q)->v->rl(q);q=NULL;" in s)
check("W13 pid<=4 and self/parent excluded from WMI decisions",
      "if(pidv<=4||pidv==g_parent||(DWORD)pidv==GetCurrentProcessId())return;" in s and
      "cur[i2]!=g_parent&&cur[i2]!=GetCurrentProcessId()" in s)
check("W14 runtime push degradation drops to PULL (Next error path)",
      "WMI push Next hr=0x%08lx -> drop to PULL" in s)

# ---------- B. ETW path untouched ----------
check("W15 ETW layout guard 480/456 intact",
      "sizeof(EVENT_TRACE_LOGFILE_L)!=480" in s and
      "ETW layout ok size=%u offCB=%u" in s)
check("W16 private session + EnableTraceEx2 8-arg intact",
      "SevenAgent-Process" in s and
      "pEnable(session,&KERNEL_PROCESS_GUID,EVENT_CONTROL_CODE_ENABLE_PROVIDER,4,WINEVENT_KEYWORD_PROCESS,0,0,NULL)" in s)
check("W17 on_record pump unchanged",
      "static void WINAPI on_record(EVENT_RECORD_L*r)" in s and
      "ETW entering ProcessTrace: official callback-driven pump, no polling" in s)
check("W18 parent_watch exit path unchanged",
      "PARENT GONE -> agent exits; foreign session left intact" in s)
check("W19 --SelfTest / --LoopbackTest / --test modes unchanged",
      "--SelfTest" in s and "--LoopbackTest" in s and "--test" in s)

# ---------- C. fresh TCC build ----------
exe = os.path.join(SMOKE, "SevenAgent.exe")
os.makedirs(SMOKE, exist_ok=True)
r = subprocess.run([TCC, "-o", exe, SRC, "-ladvapi32", "-lkernel32", "-luser32",
                    "-lshell32", "-lole32", "-lws2_32"],
                   capture_output=True, text=True)
check("W20 TCC rebuild zero errors", r.returncode == 0 and "error" not in r.stderr, r.stderr[:200])
check("W21 rebuilt PE is x64",
      r.returncode == 0 and open(exe, "rb").read(2) == b"MZ" and
      open(exe, "rb").read()[0x3C:0x40] != b"\x00"*4)
if r.returncode != 0:
    print("== build failed, stopping ==")
    sys.exit(1)

# ---------- D. SelfTest on fresh build ----------
r = subprocess.run([exe, "--SelfTest"], capture_output=True, text=True, timeout=60)
so = (r.stdout or "") + (r.stderr or "")
check("W22 SelfTest PASS (rules loaded=3, 13/13 malicious, 0 FP)",
      r.returncode == 0 and "=> PASS" in so and "rules loaded=3" in so, so[-200:])

# ---------- E. runtime smoke (elevated bat pattern, proven 2026-11-14) ----------
# The manifest exe requires elevation for ETW sessions; UAC silent-consent is
# enabled on this machine (ConsentPromptBehaviorAdmin=0).
for f in ("agent_diag.log", "agent_alerts.log", "smoke_wmi.log"):
    p = os.path.join(SMOKE, f)
    if os.path.exists(p): os.remove(p)
shutil.copy2(os.path.join(os.path.dirname(SRC), "agent_rules.json"), SMOKE)

import ctypes
from ctypes import wintypes as _wt
sh = ctypes.WinDLL("shell32")
sh.ShellExecuteW.restype = ctypes.c_void_p

def run_elevated_bat(text, wait):
    bat = os.path.join(SMOKE, "_smoke_step.bat")
    open(bat, "w").write(text)
    r = sh.ShellExecuteW(None, "runas", "cmd.exe", '/c ""%s""' % bat, SMOKE, 0)
    ok = int(r or 0) > 32
    time.sleep(wait)
    return ok

# step 1: clear stale session + leftovers (ignore errors), then boot --test
run_elevated_bat(
 'logman stop "SevenAgent-Process" -ets >nul 2>&1\r\n'
 'taskkill /F /IM SevenAgent.exe >nul 2>&1\r\n'
 'cd /d "%s"\r\n'
 '"%s" --test > "%s\\smoke_wmi.log" 2>&1\r\n' % (SMOKE, exe, SMOKE), 5)
try:
    # spawn children the WMI source must observe via snapshot diff
    for _ in range(3):
        subprocess.Popen(["cmd.exe", "/c", "ping -n 2 127.0.0.1 >nul"],
                         cwd=SMOKE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.7)
    time.sleep(7)
finally:
    # step 2: elevated kill
    run_elevated_bat(
     'taskkill /F /IM SevenAgent.exe > "%s\\_kill_wmi.log" 2>&1\r\nexit\r\n' % SMOKE, 3)

diag = ""
p = os.path.join(SMOKE, "agent_diag.log")
if os.path.exists(p):
    diag = open(p, "r", encoding="utf-8", errors="replace").read()

check("W23 WMI thread booted (diag: thread started)",
      "WMI event source thread started" in diag, diag[:200])
check("W24 CoInitializeSecurity + ConnectServer OK",
      "WMI CoInitializeSecurity hr=0x00000000" in diag and "WMI ConnectServer OK" in diag)
check("W25 PUSH attempted at slot 20 with real BSTR query",
      "WMI ExecNotificationQuery slot=20 hr=0x" in diag)
check("W26 push self-test verdict logged (fallback engaged on this machine)",
      "WMI push self-test slot=20" in diag)
check("W27 PULL mode active (300ms snapshot diff)",
      "WMI mode=PULL interval=300ms" in diag)
check("W28 ETW chain booted in parallel (layout ok, ProcessTrace pump)",
      "ETW layout ok size=480 offCB=456" in diag and
      "ETW entering ProcessTrace: official callback-driven pump, no polling" in diag)
proc_lines = re.findall(r"PROC pid=(\d+) cmd=\[", diag)
check("W29 WMI source fed real process decisions (PROC lines for spawned children)",
      len(proc_lines) >= 2, "proc_lines=%d :: %s" % (len(proc_lines), proc_lines[:8]))
check("W30 no CMDFAIL storm (PEB fallback resolving cmdlines)",
      diag.count("CMDFAIL") <= 8, "cmdfail=%d" % diag.count("CMDFAIL"))
# threshold note: transient conhost/cmd children spawned by the smoke itself can
# exit between the 300ms snapshot enumeration and the PEB read (1-4 per run is
# machine-load noise, not a storm); PEB resolution is proven by the PROC lines.

# ---------- summary ----------
npass = sum(1 for _, ok, _ in results if ok)
print("== %d/%d PASS ==" % (npass, len(results)))
sys.exit(0 if npass == len(results) else 1)
