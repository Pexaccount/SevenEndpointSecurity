# -*- coding: utf-8 -*-
"""决定性实验: 循环活着吗? 危险分支 vs 快速拦截分支。"""
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
print("== 启动 reg.exe(危险分支, 应打日志) ==")
subprocess.Popen(["reg.exe", "query", r"HKCU\Software"], cwd=BASE,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print("== 启动 hello.exe(应快速拦截) ==")
subprocess.Popen([os.path.join(BASE, "EDRTest", "hello.exe")], cwd=BASE)
time.sleep(8)
new = open(LOG, encoding="utf-8", errors="replace").read()[mark:]
print("--- 新增日志 ---")
print(new if new.strip() else "(空!循环13秒无任何日志)")
for p in [app]:
    try:
        p.kill()
    except Exception:
        pass
subprocess.run(["taskkill", "/f", "/im", "hello.exe"], capture_output=True)
subprocess.run(["taskkill", "/f", "/im", "reg.exe"], capture_output=True)
