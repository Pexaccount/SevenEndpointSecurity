# -*- coding: utf-8 -*-
"""最终实测: C:\EDRTest\hello.exe 应被快速拦截 -> Process Scan -> Released。"""
import os, sys, time, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "Main", "UIdebug.txt")
env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"

def logsize():
    return os.path.getsize(LOG) if os.path.exists(LOG) else 0

app = subprocess.Popen([sys.executable, os.path.join(BASE, "SevenEndPoint.py")],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=BASE)
time.sleep(13)
mark = logsize()
print("== 从 C:\\EDRTest 启动 hello.exe ==")
c = subprocess.Popen([r"C:\EDRTest\hello.exe"])
time.sleep(10)
new = open(LOG, encoding="utf-8", errors="replace").read()[mark:]
print("--- 新增日志 ---")
print("\n".join(l for l in new.splitlines() if any(
    k in l for k in ("快速拦截", "Process Scan", "Process Scanned", "重新启动", "端点研判", "hello"))) or "(无匹配)")
alive = subprocess.run(["tasklist", "/fi", "IMAGENAME eq hello.exe", "/nh"], capture_output=True, text=True)
print("hello still running:", "hello.exe" in alive.stdout)
try:
    c.kill()
except Exception:
    pass
subprocess.run(["taskkill", "/f", "/im", "hello.exe"], capture_output=True)
app.terminate()
