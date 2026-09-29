# -*- coding: utf-8 -*-
import subprocess, time, os, sys
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
flag = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
out = open(sys.argv[1], 'w', encoding='utf-8')
worker = subprocess.Popen(['python', '_SevenEndPoint_debug.py', '--etw-worker'],
                          stdout=out, stderr=subprocess.DEVNULL, text=True)
n = [0]
time.sleep(4)
for i in range(6):
    subprocess.run(['cmd', '/c', f'echo a{i} > %TEMP%\etw_att_{i}.txt'], capture_output=True, creationflags=flag)
    time.sleep(0.6)
out.flush()
worker.terminate(); time.sleep(0.5); worker.kill()
