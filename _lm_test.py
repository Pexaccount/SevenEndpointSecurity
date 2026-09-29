# -*- coding: utf-8 -*-
import subprocess, time, os
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
flag = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
worker = subprocess.Popen(['python', '_SevenEndPoint_debug.py', '--etw-worker'],
                          stdout=open('dbg_out7.txt', 'w'), stderr=subprocess.DEVNULL, text=True)
time.sleep(8)
def q(f):
    r = subprocess.run(['logman', '-ets', 'query', 'SevenEndPointTelemetry'], capture_output=True, text=True, timeout=20)
    open(f, 'w', encoding='utf-8', errors='ignore').write(r.stdout + '\nERR:' + r.stderr)
q('lm_e1.txt')
for i in range(10):
    subprocess.run(['cmd', '/c', f'echo x{i} > %TEMP%\etw_lm3_{i}.txt'], capture_output=True, creationflags=flag)
    time.sleep(0.5)
time.sleep(4)
q('lm_e2.txt')
worker.terminate()
time.sleep(1)
worker.kill()
