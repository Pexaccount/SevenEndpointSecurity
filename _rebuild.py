# -*- coding: utf-8 -*-
"""重建 SevenEngine.exe + 同步 SevenEP(绕过被AMSI拦的PS profile)。"""
import subprocess, sys, shutil, os

PY = sys.executable
BASE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(BASE, "SevenEngine")
BUILD = os.path.join(ENG, "build")

cmd = [PY, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--noconsole",
       "--name", "SevenEngine",
       "--icon", r"D:\Administrator\Desktop\SevenEndpoint.ico",
       "--distpath", ENG, "--workpath", BUILD, "--specpath", BUILD,
       "--hidden-import", "pda_store",
       "--hidden-import", "lightgbm_engine",
       "--hidden-import", "ONNX.onnx_feature_extractor",
       "--collect-binaries", "lightgbm",
       "--exclude-module", "onnxruntime",
       os.path.join(ENG, "SevenEngine.py")]
r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=BASE)
print("pyinstaller rc =", r.returncode)
if r.returncode != 0:
    print(r.stdout[-1500:])
    print(r.stderr[-1500:])
    sys.exit(1)
print(r.stdout[-300:])

spec_src = os.path.join(BUILD, "SevenEngine.spec")
if os.path.exists(spec_src):
    shutil.move(spec_src, os.path.join(ENG, "SevenEngine.spec"))
shutil.rmtree(BUILD, ignore_errors=True)

dst = r"D:\Administrator\Desktop\SevenEP\SevenEngine\SevenEngine.exe"
try:
    shutil.copyfile(os.path.join(ENG, "SevenEngine.exe"), dst)
    print("synced to SevenEP OK")
except Exception as e:
    print("sync failed:", e)
print("REBUILD DONE")
