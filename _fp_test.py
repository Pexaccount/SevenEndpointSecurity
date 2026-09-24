# -*- coding: utf-8 -*-
"""修完误报后的功能测试: python/pyw 不被杀(误报=0), hello.exe 快速拦截+Released 正常。"""
import os, sys, time, subprocess, json

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "Main", "UIdebug.txt")
env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"

def logsize():
    return os.path.getsize(LOG) if os.path.exists(LOG) else 0

def newlog(old):
    with open(LOG, encoding="utf-8", errors="replace") as f:
        f.seek(old)
        return f.read()

# 1) python 子进程误报测试: 子进程 3 秒后写标记, 被杀则无标记
marker_py = os.path.join(os.environ["TEMP"], "edr_fp_python.marker")
script_py = os.path.join(os.environ["TEMP"], "edr_fp_python.py")
if os.path.exists(marker_py):
    os.remove(marker_py)
with open(script_py, "w") as f:
    f.write("import time\nopen(r'%s','w').write('alive')\nprint('child ok')\ntime.sleep(6)\n" % marker_py.replace("\\", "\\\\"))

# 2) pythonw 同理
marker_w = os.path.join(os.environ["TEMP"], "edr_fp_pythonw.marker")
script_w = os.path.join(os.environ["TEMP"], "edr_fp_pythonw.pyw")
if os.path.exists(marker_w):
    os.remove(marker_w)
with open(script_w, "w") as f:
    f.write("import time\nopen(r'%s','w').write('alive')\ntime.sleep(6)\n" % marker_w.replace("\\", "\\\\"))

# 3) hello.exe 放行流程验证
marker_h = os.path.join(os.environ["TEMP"], "edr_hello_relaunched.marker")
if os.path.exists(marker_h):
    os.remove(marker_h)

app = subprocess.Popen([sys.executable, os.path.join(BASE, "SevenEndPoint.py")],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=BASE)
time.sleep(12)   # 等引擎worker预热+防护拉起
logmark = logsize()

print("== TEST1: python 子进程(不应被杀) ==")
c1 = subprocess.Popen([sys.executable, script_py], cwd=BASE)
print("== TEST2: pythonw 子进程(不应被杀) ==")
c2 = subprocess.Popen([os.path.join(os.path.dirname(sys.executable), "pythonw.exe"), script_w], cwd=BASE)
print("== TEST3: hello.exe(应快速拦截+Released+重启) ==")
c3 = subprocess.Popen([os.path.join(BASE, "EDRTest", "hello.exe")], cwd=BASE)
time.sleep(10)

print("python marker:", os.path.exists(marker_py))
print("pythonw marker:", os.path.exists(marker_w))
print("--- 新增日志(关键行) ---")
for line in newlog(logmark).splitlines():
    if any(k in line for k in ("快速拦截", "Process Scan", "Process Scanned", "放行", "重新启动",
                               "端点研判", "hello", "python", "异常", "Worker 就绪")):
        print(line[:170])
for p in (app, c1, c2, c3):
    try:
        p.kill()
    except Exception:
        pass
