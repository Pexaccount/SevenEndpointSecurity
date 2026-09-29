import ctypes, time, os, sys
os.chdir(r'D:\Administrator\Desktop\TestUI\CodeBak')
try:
    os.remove('etw_result.txt')
except OSError:
    pass
r = ctypes.windll.shell32.ShellExecuteW(None, 'runas', 'python', 'test_etw.py --out etw_result.txt', r'D:\Administrator\Desktop\TestUI\CodeBak', 0)
print('ShellExecuteW ->', r, flush=True)
for i in range(75):
    if os.path.exists('etw_result.txt'):
        time.sleep(3)
        print('RESULT_READY after', i * 2, 's', flush=True)
        sys.exit(0)
    time.sleep(2)
print('TIMEOUT waiting result', flush=True)
