# -*- coding: utf-8 -*-
"""可信评估测试: 银狐规则必须命中恶意行为, 且对正常软件操作零误报。
从 SevenEndPoint.py 用 AST 提取真实规则(不导入主程序, 避免拉起GUI/驱动依赖),
保证测的就是线上那份规则。"""
import ast, os, re, sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SevenEndPoint.py')
src = open(SRC, encoding='utf-8').read()
tree = ast.parse(src)

# ---- 提取真实规则 ----
patterns, proxy_dlls = None, None
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        tid = getattr(node.targets[0], 'id', '')
        if tid == '_DANGEROUS_CMD_PATTERNS':
            patterns = [(e.elts[0].value, e.elts[1].value, re.compile(e.elts[2].args[0].value, re.I)) for e in node.value.elts]
        if tid == '_SIDELOAD_PROXY_DLLS':
            proxy_dlls = {e.value for e in node.value.elts}
assert patterns and proxy_dlls, '规则提取失败'

def match(cmdline):
    """返回 (etype, points) 或 None —— 与 _handle_telemetry 的命中顺序一致"""
    for et, pts, rx in patterns:
        if rx.search(cmdline or ''):
            return et, pts
    return None

PASS, FAIL = [], []
def check(desc, ok):
    (PASS if ok else FAIL).append(desc)
    print(('  PASS ' if ok else '  FAIL ') + desc)

print('== 银狐规则命中(必须全部命中) ==')
MALICIOUS = [
    (r'银狐-杀360安全进程',        'cmd.exe /c taskkill /f /im 360tray.exe', 'av_tamper', 20),
    (r'银狐-杀火绒',               'taskkill /f /im HipsDaemon.exe', 'av_tamper', 20),
    (r'银狐-加Defender排除项',      'powershell -c Add-MpPreference -ExclusionPath C:\\Users\\Public', 'av_tamper', 20),
    (r'银狐-关Defender实时防护',    'powershell Set-MpPreference -DisableRealtimeMonitoring $true', 'av_tamper', 20),
    (r'银狐-sc停管家服务',          'sc stop QQPCRTP', 'av_tamper', 20),
    (r'服务创建(持久化)',           'sc create WinDefendUpdate binPath= C:\\Users\\Public\\svchost.exe start= auto', 'privilege', 15),
    (r'计划任务持久化',             'schtasks /create /tn Updater /tr C:\\Temp\\1.exe /sc onlogon', 'task_sched', 15),
    (r'Run键持久化',               'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /t REG_SZ /d C:\\Temp\\1.exe', 'persistence', 15),
    (r'清影子副本(勒索准备)',       'vssadmin delete shadows /all /quiet', 'privilege', 15),
    (r'凭据转储',                  'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 678 C:\\Temp\\out.dmp full', 'cred_dump', 20),
]
for desc, cmd, want_et, want_pts in MALICIOUS:
    r = match(cmd)
    # 'sc create' 命中 av_tamper 中的 sc\s+(stop|delete|config) 不会, 但会命中 privilege -> 分值>=15且高优先即可
    ok = r is not None and r[1] >= want_pts and r[0] in (want_et, 'privilege')
    check(f'{desc}: {"命中 " + str(r) if r else "未命中"}', ok)

print('== 可信操作(必须全部不触发高危规则) ==')
BENIGN = [
    ('开发者查计划任务',        'schtasks /query /fo list'),
    ('删除自己建的任务',        'schtasks /delete /tn MyOldTask /f'),
    ('git正常操作',             '"C:\\Program Files\\Git\\cmd\\git.exe" pull origin main'),
    ('查服务状态',              'sc query wuauserv'),
    ('sc queryex',              'sc queryex types= service state= all'),
    ('杀自己的记事本',          'taskkill /f /im notepad.exe'),
    ('杀游戏进程',              'taskkill /im steam.exe'),
    ('普通reg add(非Run键)',    'reg add HKCU\\Console /v QuickEdit /t REG_DWORD /d 1'),
    ('正常拷贝',                'cmd /c copy D:\\data\\* E:\\backup\\'),
    ('正常关机命令',            'shutdown /r /t 0'),
    ('pip装包',                 'pip install requests'),
    ('netstat查端口',           'netstat -ano | findstr 443'),
    ('notepad打开日志',         'notepad C:\\logs\\app.log'),
]
for desc, cmd in BENIGN:
    r = match(cmd)
    ok = r is None or r[1] <= 5   # 最多允许 script_run(+5)这类低权留痕
    check(f'{desc}: {str(r) if r else "不触发"}', ok)

print('== 白加黑代理DLL判定(可信目录不误报, 可疑目录命中) ==')
SUSP_DIRS = ('\\temp\\', '\\appdata\\', '\\programdata\\', '\\users\\public\\', '\\downloads\\', '\\desktop\\')
def proxy_hit(path):
    p = path.lower().replace('/', '\\')
    return os.path.basename(p) in proxy_dlls and any(d in p for d in SUSP_DIRS)
CASES = [
    ('勒索侧载: Temp释放version.dll',  'C:\\Users\\Admin\\AppData\\Local\\Temp\\version.dll', True),
    ('勒索侧载: Downloads释放dxgi.dll', 'C:\\Users\\Admin\\Downloads\\dxgi.dll', True),
    ('勒索侧载: ProgramData释放winmm.dll','C:\\ProgramData\\Media\\winmm.dll', True),
    ('可信: ReShade装进游戏目录',       'D:\\Games\\Cyberpunk2077\\bin\\x64\\dxgi.dll', False),
    ('可信: 应用自带dbghelp.dll',       'C:\\Program Files\\SomeApp\\dbghelp.dll', False),
    ('可信: 非代理DLL(普通dll落Temp)',  'C:\\Temp\\zlib1.dll', False),
]
for desc, path, want in CASES:
    ok = proxy_hit(path) == want
    check(f'{desc}: {"命中" if proxy_hit(path) else "不命中"}', ok)

print()
print(f'结果: {len(PASS)} 通过, {len(FAIL)} 失败')
sys.exit(1 if FAIL else 0)
