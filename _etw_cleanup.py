# -*- coding: utf-8 -*-
import subprocess, os, sys
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
out = []
r = subprocess.run(['logman', '-ets', 'query'], capture_output=True, text=True)
for line in r.stdout.splitlines():
    if 'SevenEndPoint' in line or 'SevenEtw' in line:
        name = line.split()[1].strip() if len(line.split()) > 1 else ''
        if name:
            s = subprocess.run(['logman', '-ets', 'stop', name], capture_output=True, text=True)
            out.append(f'stop {name}: {s.returncode}')
# 杀残留worker
k = subprocess.run(['powershell', '-Command',
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'SevenEndPoint|etw-worker' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"],
    capture_output=True, text=True)
open('cleanup_result.txt', 'w', encoding='utf-8').write('\n'.join(out) + '\nDONE')
