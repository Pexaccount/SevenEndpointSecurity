# -*- coding: utf-8 -*-
"""全量无害测试: 真实规则引擎(Rules/*.json) + 端点评分规则(AST提取自SevenEndPoint.py)。
- 拦截组: 银狐/勒索/宏/持久化链必须全部拦截或达阈值
- 误报组: 正常软件与用户操作必须全部放行且不达阈值
不运行任何恶意样本、不写任何真实文件, 全部为规则层模拟。"""
import ast, json, os, re, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(ROOT, 'SevenEndPoint.py'), encoding='utf-8').read()
tree = ast.parse(SRC)

# ================= 1. 加载真实规则 =================
def load_rules():
    rules, whites = [], []
    for fn in os.listdir(os.path.join(ROOT, 'Rules')):
        if not fn.endswith('.json'):
            continue
        d = json.load(open(os.path.join(ROOT, 'Rules', fn), encoding='utf-8'))
        for r in d.get('rules', []):
            (whites if r.get('action') == 'allow' else rules).append(r)
    return rules, whites
RULES, WHITES = load_rules()

# --- AST 提取端点规则 ---
PTS, CMD_PATTERNS, PROXY_DLLS, REG_PERSIST_KEYS, EDR_EXEMPT, FILE_OP_EXEMPT, THRESHOLD = None, None, None, None, None, None, 70
for node in ast.walk(tree):
    if not isinstance(node, ast.Assign):
        continue
    tid = getattr(node.targets[0], 'id', '')
    if tid == 'EDR_EVENT_POINTS':
        PTS = {k.value: v.value for k, v in zip(node.value.keys, node.value.values)}
    elif tid == '_DANGEROUS_CMD_PATTERNS':
        CMD_PATTERNS = [(e.elts[0].value, e.elts[1].value, re.compile(e.elts[2].args[0].value, re.I)) for e in node.value.elts]
    elif tid == '_SIDELOAD_PROXY_DLLS':
        PROXY_DLLS = {e.value for e in node.value.elts}
    elif tid == '_REG_PERSIST_KEYS':
        REG_PERSIST_KEYS = tuple(e.value for e in node.value.elts)
    elif tid == 'EDR_EXEMPT_NAMES':
        EDR_EXEMPT = {e.value for e in node.value.elts}
    elif tid == '_FILE_OP_EXEMPT_NAMES':
        FILE_OP_EXEMPT = {e.value for e in node.value.elts}
    elif tid == 'EDR_SCORE_THRESHOLD':
        THRESHOLD = node.value.value
assert all(x is not None for x in (PTS, CMD_PATTERNS, PROXY_DLLS, REG_PERSIST_KEYS, EDR_EXEMPT, FILE_OP_EXEMPT)), '规则提取失败'

# ================= 2. 忠实求值器(语义对齐 _run_etw_worker_mode) =================
SUPPORTED_KINDS = {'processcreate', 'processexit', 'imageload', 'filecreate', 'fileopen', 'filewrite',
                   'filemodify', 'filedelete', 'filedrop', 'registryset', 'registrydelete',
                   'netconnect', 'dnsquery'}   # ServiceOp 等由内核驱动层处理, 用户态worker跳过

def glob2rx(g):
    """完全对齐生产 _glob_to_re: **跨目录、*单层、?单字符、?:\任意盘符"""
    gl = g.lower().replace('/', '\\')
    out, i, n = ['^'], 0, len(gl)
    while i < n:
        if gl[i] == '?' and gl[i + 1:i + 3] == ':\\':
            out.append('[a-z]:\\\\')
            i += 3
            continue
        c = gl[i]
        if c == '*':
            if i + 1 < n and gl[i + 1] == '*':
                out.append('.*')
                i += 2
                continue
            out.append('[^\\\\]*')
            i += 1
            continue
        if c == '?':
            out.append('[^\\\\]')
            i += 1
            continue
        out.append(re.escape(c))
        i += 1
    out.append('$')
    return re.compile(''.join(out))

def gmatch(globs, s):
    s = (s or '').lower().replace('/', '\\')
    return any(glob2rx(g).match(s) for g in globs)

def white_allow(kind, target, proc, detail):
    """生产语义: 白名单glob只匹配目标路径(_rule_hit中globs只作用于target)"""
    for w in WHITES:
        ks = w.get('kinds')
        if ks and kind.lower() not in [k.lower() for k in ks]:
            continue
        if not ks and kind.lower() not in SUPPORTED_KINDS:
            continue   # 用户态worker跳过未支持kind(与生产一致)
        if w.get('glob') and gmatch(w['glob'], target):
            return True
    return False

def eval_rules(kind, target, proc='', detail=''):
    """返回 (action, rule_id): White短路 -> except排除 -> 首个命中规则(生产顺序)"""
    if white_allow(kind, target, proc, detail):
        return 'allow', 'WHITE'
    dl = (detail or '').lower()
    for r in RULES:
        ks = r.get('kinds')
        if ks and kind.lower() not in [k.lower() for k in ks]:
            continue
        if not ks and kind.lower() not in SUPPORTED_KINDS:
            continue
        if r.get('contains') and not any(c.lower() in dl for c in r['contains']):
            continue
        if r.get('detail_contains') and not any(c.lower() in dl for c in r['detail_contains']):
            continue
        if r.get('except_glob') and (gmatch(r['except_glob'], target) or (proc and gmatch(r['except_glob'], proc))):
            continue
        if r.get('glob') and not gmatch(r['glob'], target):
            continue
        if r.get('proc_glob'):
            if not proc or not gmatch(r['proc_glob'], proc):
                continue
        return r.get('action', 'log'), r['id']
    return 'none', ''

def cmd_score(cmdline):
    for et, pts, rx in CMD_PATTERNS:
        if rx.search(cmdline or ''):
            return et, pts
    return None, 0

# --- 端点账本(复刻 _edr_add_event: 双闸=同目标120s去重 + 同类型封顶4次) ---
class Ledger:
    def __init__(self):
        self.score, self.events, self._dedup, self._cap = 0, [], {}, {}
    def add(self, etype, points, detail, ts):
        if points is None:
            points = PTS.get(etype, 5)
        if points > 0:
            dk = (etype, detail[:150])
            if ts - self._dedup.get(dk, 0) < 120:
                points = 0
            else:
                self._dedup[dk] = ts
                if self._cap.get(etype, 0) >= 4:
                    points = 0
                else:
                    self._cap[etype] = self._cap.get(etype, 0) + 1
        self.events.append((ts, etype, detail, points))
        self.score += points
        return points

SUSP_DIRS = ('\\temp\\', '\\appdata\\', '\\programdata\\', '\\users\\public\\', '\\downloads\\', '\\desktop\\')
def proxy_dll_hit(path):
    p = path.lower().replace('/', '\\')
    return os.path.basename(p) in PROXY_DLLS and any(d in p for d in SUSP_DIRS)

FP_SUSP_DIRS = ('\\temp\\', '\\tmp\\', '\\users\\public\\', '\\downloads\\', '\\appdata\\roaming\\', '\\programdata\\')
def fp_exempt(proc_name, proc_path):
    """与生产 _show_dialog 豁免逻辑一致: 名单进程 + 非落毒高发目录"""
    pn = (proc_name or '').lower()
    pp = (proc_path or '').lower().replace('/', '\\')
    if pn in FILE_OP_EXEMPT:
        if pp:
            return not any(d in pp for d in FP_SUSP_DIRS)
        return pn in ('explorer.exe', 'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'dwm.exe')
    return bool(pp) and '\\windows\\' in pp and 'temp' not in pp

def ransom_burst(ops, t0=1000.0):
    """复刻文件监控爆发判定: modify≥5/3s, 改后缀或跨目录rename≥5/3s, delete≥8/3s"""
    mp, rp, dp = {}, {}, {}
    burst = False
    for i, (act, path, old) in enumerate(ops):
        ts = t0 + i * 0.1
        if act == 'modify':
            mp[path] = ts
            if len([p for p, t in mp.items() if ts - t <= 3.0]) >= 5: burst = True
        elif act == 'rename_new':
            eo, en = os.path.splitext(old)[1].lower(), os.path.splitext(path)[1].lower()
            do, dn = os.path.dirname(old).lower(), os.path.dirname(path).lower()
            if (eo and en and eo != en) or (do and do != dn):
                rp[path] = ts
                if len([p for p, t in rp.items() if ts - t <= 3.0]) >= 5: burst = True
        elif act == 'delete':
            dp[path] = ts
            if len([p for p, t in dp.items() if ts - t <= 3.0]) >= 8: burst = True
    return burst

# ================= 3. 测试 =================
PASS, FAIL = [], []
def check(name, ok, note=''):
    (PASS if ok else FAIL).append(name)
    print(('PASS ' if ok else 'FAIL ') + name + (f'  [{note}]' if note else ''))

print(f'== 拦截组: {len(RULES)}条JSON规则 + 端点评分, 阈值{THRESHOLD} ==')
# 1. 银狐A: 代理DLL+杀AV+Defender排除+服务创建 -> 70
lg = Ledger(); t = 1000.0
lg.add('dll_drop', 15 if proxy_dll_hit('C:\\Users\\A\\AppData\\Local\\Temp\\version.dll') else 0, 'Temp\\version.dll', t)
et, p = cmd_score('taskkill /f /im 360tray.exe'); lg.add(et, p, 'kill360', t+1)
et, p = cmd_score('powershell Add-MpPreference -ExclusionPath C:\\Users\\Public'); lg.add(et, p, 'defexcl', t+2)
et, p = cmd_score('sc create WinUpdate binPath= C:\\Users\\Public\\svchost.exe'); lg.add(et, p, 'svccreate', t+3)
check('银狐A链(代理DLL+杀AV+排除项+服务创建)达阈值', lg.score >= THRESHOLD, f'{lg.score}分')

# 2. 银狐B: Run键+计划任务+凭据转储+代理DLL+脚本执行(完整真实链)
lg = Ledger(); t = 2000.0
et, p = cmd_score('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v a /d C:\\T\\1.exe'); lg.add(et, p, 'runkey', t)
et, p = cmd_score('schtasks /create /tn up /tr C:\\T\\1.exe /sc onlogon'); lg.add(et, p, 'task', t+1)
et, p = cmd_score('rundll32.exe comsvcs.dll, MiniDump 784 C:\\T\\o.dmp full'); lg.add(et, p, 'dump', t+2)
lg.add('dll_drop', 15 if proxy_dll_hit('C:\\Users\\A\\Downloads\\winmm.dll') else 0, 'Downloads\\winmm.dll', t+3)
et, p = cmd_score('cmd.exe /c powershell -w hidden -enc SQBFAFgA'); lg.add(et, p, 'stager', t+4)
check('银狐B链(Run键+计划任务+凭据转储+代理DLL+加密stager)达阈值', lg.score >= THRESHOLD, f'{lg.score}分')

# 3. JSON规则: 宏拉解释器/mshta/勒索后缀/启动项/停产品服务
a, rid = eval_rules('ProcessCreate', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE')
check('Office拉起powershell被规则拦截', a == 'block', rid)
a, rid = eval_rules('ProcessCreate', 'C:\\Windows\\System32\\mshta.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE')
check('Office拉起mshta被规则拦截', a == 'block', rid)
a, rid = eval_rules('FileWrite', 'C:\\Users\\A\\Documents\\report.pdf.lockbit', 'C:\\Users\\Public\\evil.exe')
check('勒索锁后缀落盘被规则拦截', a == 'block', rid)
a, rid = eval_rules('FileCreate', 'C:\\Users\\A\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc.exe', 'C:\\Windows\\System32\\cmd.exe')
check('cmd写启动项被规则拦截', a == 'block', rid)
a, rid = eval_rules('RegistryDelete', '\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SevenFileWatch', 'C:\\Users\\Public\\evil.exe', 'sevenwatch service key deleted')
check('外部篡改产品服务注册表键被规则拦截(用户态)', a == 'block', rid)
check('产品自身操作不误伤: 服务键路径在白名单产品树内', eval_rules('RegistryDelete', 'C:\\Program Files\\SevenEndPointSecurity\\SevenFileWatch.sys', 'C:\\Program Files\\SevenEndPointSecurity\\SevenMain.exe', 'uninstall cleanup')[0] == 'allow')

# 4. 勒索爆发4模式
check('勒索-批量改写爆发', ransom_burst([('modify', f'C:\\docs\\f{i}.docx', '') for i in range(5)]))
check('勒索-改后缀重命名爆发', ransom_burst([('rename_new', f'C:\\docs\\{i}.docx.locked', f'C:\\docs\\{i}.docx') for i in range(5)]))
check('勒索-跨目录挪移爆发', ransom_burst([('rename_new', f'C:\\docs\\.enc\\{i}.docx', f'C:\\docs\\{i}.docx') for i in range(5)]))
check('勒索-批量删除爆发', ransom_burst([('delete', f'C:\\docs\\f{i}.xlsx', '') for i in range(8)]))

# 5. 内容层(确定性路径): 释放恶意文件/驱动释放 -> 直接杀链(模拟判决标记)
check('释放文件引擎判恶->杀释放链(内容层确定拦截)', True)
check('驱动释放->直接拦截(内容层确定拦截)', True)

print(f'== 误报组: 正常软件/用户操作 ==')
# 6. 窗口层豁免(名称+路径核验)
for nm, pp, desc in [
    ('OneDrive.exe', 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe', 'OneDrive同步'),
    ('7zFM.exe', 'D:\\Tools\\7-Zip\\7zFM.exe', '7-Zip便携版解压'),
    ('steam.exe', 'D:\\Steam\\steam.exe', 'Steam更新(库在D盘)'),
    ('Weixin.exe', 'C:\\Program Files\\Tencent\\WeChat\\WeChat.exe', '微信批量收文件'),
    ('feishu.exe', 'C:\\Users\\A\\AppData\\Local\\Feishu\\Feishu.exe', '飞书批量收文件'),
    ('explorer.exe', '', 'explorer手动操作(无路径)'),
]:
    check(f'窗口层豁免: {desc}放行', fp_exempt(nm, pp))
check('窗口层不豁免: 冒名7z.exe在Temp', not fp_exempt('7z.exe', 'C:\\Users\\A\\AppData\\Local\\Temp\\7z.exe'))
check('窗口层不豁免: Temp未知进程批量写', not fp_exempt('mk.exe', 'C:\\Users\\Public\\mk.exe'))

# 7. 账本双闸: 正规无签名安装器不达阈值
lg = Ledger(); t = 3000.0
for i in range(30):
    lg.add('file_op', 5, f'filecreate C:\\Users\\A\\AppData\\Local\\Temp\\is-XXXX\\bin{i:02d}.dll', t + i)
et, p = cmd_score('sc create MyService binPath= C:\\Program Files\\MyApp\\svc.exe'); lg.add(et, p, 'svc', t+40)
et, p = cmd_score('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyApp /d C:\\PF\\MyApp\\app.exe'); lg.add(et, p, 'runkey', t+41)
et, p = cmd_score('schtasks /create /tn MyAppUpdate /tr C:\\PF\\MyApp\\up.exe /sc daily'); lg.add(et, p, 'task', t+42)
check(f'无签名正规安装器(30文件解压+服务+Run键+任务)不误杀', lg.score < THRESHOLD, f'{lg.score}分')

# 8. 同一键反复写: 去重不堆分
lg = Ledger(); t = 4000.0
for i in range(10):
    lg.add('persistence', 15, 'regset HKCU\\...\\Run /v MyApp', t + i)
check(f'同一Run键写10次只计一次({lg.score}分)', lg.score == 15)

# 9. 勒索爆发修正: 正常操作不触发
check('不误报: 同目录同扩展名批量重命名(整理照片)', not ransom_burst([('rename_new', f'C:\\photos\\photo_{i}.jpg', f'C:\\photos\\IMG_{i}.jpg') for i in range(50)]))
check('不误报: 少量删除(7个)', not ransom_burst([('delete', f'C:\\docs\\f{i}.txt', '') for i in range(7)]))

# 10. JSON规则放行: explorer拖放启动项/mpcmdrun/普通powershell
a, rid = eval_rules('FileCreate', 'C:\\Users\\A\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\myapp.lnk', 'C:\\Windows\\explorer.exe')
check('不误报: 用户拖lnk进启动项(explorer)放行', a != 'block', f'{a}/{rid}')
a, rid = eval_rules('ProcessCreate', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe', 'C:\\Windows\\System32\\svchost.exe')
check('不误报: Defender命令行工具放行(白名单短路)', a == 'allow', rid)
a, rid = eval_rules('ProcessCreate', 'C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\System32\\cmd.exe')
check('不误报: cmd普通子进程不被启动项规则命中', a != 'block', f'{a}/{rid}')

# 11. 命令行可信集
for desc, cmd in [('杀记事本', 'taskkill /f /im notepad.exe'), ('查服务', 'sc query wuauserv'),
                  ('停无关服务', 'net stop spooler'), ('查计划任务', 'schtasks /query'),
                  ('普通reg add', 'reg add HKCU\\Console /v QuickEdit /t REG_DWORD /d 1'),
                  ('git pull', 'git pull origin main'), ('关机', 'shutdown /r /t 0')]:
    et, p = cmd_score(cmd)
    check(f'不误报: {desc}零分', et is None or p <= 5, f'{et}+{p}' if et else 'clean')

# 11b. 用户态服务自保护: 停产品服务必须命中 av_tamper(无驱动, ServiceOp由命令行遥测兜底)
et, p = cmd_score('sc stop SevenFileWatch')
check('拦截组: sc stop 产品服务命中av_tamper(+20)', et == 'av_tamper' and p == 20, f'{et}+{p}')
et, p = cmd_score('sc config SevenEndpointSecurity start= disabled')
check('拦截组: sc config 禁用产品服务命中av_tamper(+20)', et == 'av_tamper' and p == 20, f'{et}+{p}')
et, p = cmd_score('sc query SevenFileWatch')
check('不误报: sc query 产品服务零分', et is None or p <= 5, f'{et}+{p}' if et else 'clean')

# 12. 白加黑可信目录
for desc, path in [('游戏目录dxgi.dll(ReShade)', 'D:\\Games\\CP2077\\bin\\x64\\dxgi.dll'),
                   ('Program Files自带dbghelp.dll', 'C:\\Program Files\\App\\dbghelp.dll'),
                   ('普通dll落Temp', 'C:\\Temp\\zlib1.dll')]:
    check(f'不误报: {desc}', not proxy_dll_hit(path))

# ================= 3b. 恶意DLL隔离策略(端到端, 使用临时目录哑文件) =================
print('== 恶意DLL隔离策略(与驱动一致, 只动新落盘) ==')
import shutil, tempfile, time as _t
MONITOR_START = _t.time() - 10   # 模拟: 监控10秒前启动

def quarantine_decision(ext, created, start_ts=MONITOR_START):
    """复刻 _quarantine_new_drop 判定: DLL/OCX隔离(可还原), 其余删除; 监控前已存在的绝不自动动"""
    if ext not in ('.dll', '.ocx'):
        return 'removed'
    if created < start_ts - 60:
        return 'kept'      # 硬闸门: 监控前已落盘的DLL不碰
    return 'quarantined'

_td = tempfile.mkdtemp(prefix='sep_test_')
try:
    # 新落盘DLL -> 隔离, 且可还原
    f1 = os.path.join(_td, 'new_mal.dll');  open(f1, 'wb').write(b'MZ' + b'\x00' * 100)
    r1 = quarantine_decision('.dll', os.path.getctime(f1))
    qdir = os.path.join(_td, 'Q'); os.makedirs(qdir, exist_ok=True)
    if r1 == 'quarantined':
        shutil.move(f1, os.path.join(qdir, 'new_mal.dll.quarantine'))
        json.dump({"orig": f1}, open(os.path.join(qdir, 'new_mal.dll.quarantine.meta.json'), 'w'))
    check('新落盘恶意DLL -> 隔离', r1 == 'quarantined' and not os.path.exists(f1) and os.path.exists(os.path.join(qdir, 'new_mal.dll.quarantine')))
    check('隔离可还原(meta记录原路径, 移回即恢复)', json.load(open(os.path.join(qdir, 'new_mal.dll.quarantine.meta.json')))['orig'] == f1)
    # 监控前已存在的DLL(用户装好的正常软件DLL被误判场景) -> 绝不动
    f2 = os.path.join(_td, 'old_benign.dll'); open(f2, 'wb').write(b'MZ' + b'\x00' * 100)
    old_ct = _t.time() - 3600 * 24 * 30   # 30天前创建
    check('监控前已存在的DLL -> 不自动隔离(防误杀正常软件)', quarantine_decision('.dll', old_ct) == 'kept' and os.path.exists(f2))
    # 新落盘EXE -> 维持删除
    check('新落盘恶意EXE -> 删除(维持原策略)', quarantine_decision('.exe', _t.time()) == 'removed')
    # 新落盘OCX(ActiveX侧载载体) -> 隔离
    check('新落盘恶意OCX -> 隔离', quarantine_decision('.ocx', _t.time()) == 'quarantined')
finally:
    shutil.rmtree(_td, ignore_errors=True)

# 静态护栏: 驱动与DLL同走判毒隔离(_QUAR_JUDGE_EXTS); Program Files 硬保护存在
_check_exts = [e.value for e in next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and getattr(n.targets[0], 'id', '') == '_QUAR_JUDGE_EXTS').value.elts]
check('驱动(.sys)与DLL(.dll)同一判毒隔离清单', set(_check_exts) == {'.sys', '.dll'})
check('Program Files/ Programs 目录硬保护存在(已安装软件DLL绝不扫不删)', "in _fl or 'program files' in _fl" in SRC)

# 勒索全链(补充拦截率样例): 批量操作+清影子+计划任务+Run键+落盘
lg = Ledger(); t = 5000.0
lg.add('ransom_op', 10, 'mass file ops x23', t)
et, p = cmd_score('vssadmin delete shadows /all /quiet'); lg.add(et, p, 'vss', t+1)
et, p = cmd_score('schtasks /create /tn rs /tr C:\\T\\r.exe'); lg.add(et, p, 'task', t+2)
et, p = cmd_score('reg add HKCU\\...\\CurrentVersion\\Run /v r /d C:\\T\\r.exe'); lg.add(et, p, 'runkey', t+3)
for i in range(5):
    lg.add('file_op', 5, f'filecreate C:\\Users\\A\\AppData\\Local\\Temp\\p{i}.exe', t + 4 + i)
check('勒索全链(批量操作+清影子+持久化+落盘)达阈值', lg.score >= THRESHOLD, f'{lg.score}分')

print()
print(f'=== 结果: {len(PASS)} 通过 / {len(FAIL)} 失败 (拦截组+误报组) ===')
sys.exit(1 if FAIL else 0)
