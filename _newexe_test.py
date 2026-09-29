# -*- coding: utf-8 -*-
import subprocess, time, os
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
worker = subprocess.Popen([r'D:\Administrator\Desktop\TestUI\CodeBak\dist\SevenEndPoint_fixed.exe', '--etw-worker'],
                          stdout=open('newexe_worker.txt', 'w'), stderr=subprocess.DEVNULL, text=True)
end = time.time() + 20
while time.time() < end:
    time.sleep(1)
worker.terminate(); time.sleep(1); worker.kill()
