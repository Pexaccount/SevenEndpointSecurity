# -*- coding: utf-8 -*-
import subprocess, time, os
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
flag = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
worker = subprocess.Popen(['python', '_SevenEndPoint_debug.py', '--etw-worker'],
                          stdout=open('dbg_out8.txt', 'w'), stderr=subprocess.DEVNULL, text=True)
time.sleep(8)
q = subprocess.run(['logman', '-ets', 'query', 'SevenEndPointTelemetry'], capture_output=True, text=True, timeout=20)
open('lm_full.txt', 'w', encoding='utf-8', errors='ignore').write(q.stdout)
# tracerpt 挂到实时会话消费10秒
tp = subprocess.Popen(['tracerpt', '-rt', 'SevenEndPointTelemetry', '-of', 'csv', '-o', 'trace_out.csv'],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=flag)
time.sleep(2)
for i in range(8):
    subprocess.run(['cmd', '/c', f'echo z{i} > %TEMP%\etw_tp_{i}.txt'], capture_output=True, creationflags=flag)
    time.sleep(0.5)
time.sleep(4)
tp.terminate()
try: tp_out = tp.communicate(timeout=5)[0]
except Exception: tp_out = ''
open('tracept_err.txt', 'w', encoding='utf-8', errors='ignore').write(tp_out or '')
worker.terminate(); time.sleep(1); worker.kill()
print('done')
