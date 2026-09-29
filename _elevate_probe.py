import ctypes, time, os, sys
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
try: os.remove('etw_probe_result.txt')
except OSError: pass
r = ctypes.windll.shell32.ShellExecuteW(None, 'runas', 'python', '_etw_probe.py --out etw_probe_result.txt', r'D:\Administrator\Desktop\TestUI\CodeBak', 0)
print('ShellExecuteW ->', r, flush=True)
# 探针自己不写文件, 改用重定向: 等待退出
for i in range(60):
    time.sleep(2)
    if not os.path.exists('etw_probe_done.txt'):
        pass
print('done-marker-missing, check console capture', flush=True)
