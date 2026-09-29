# -*- coding: utf-8 -*-
"""ETW 全功能测试:
  A. 静态: Rules/*.json 加载/ glob 可编译/ kinds 支持面/ 历史回归(White短路等5个已修bug)
  B. 运行时: 拉起真实 ETW worker 子进程 → 会话启动/提供者/结构体自检 →
     logman 会话在位 → 良性风暴零误报 → 受控 .lockbit 写入触发 block 告警(端到端) → 会话清理
需管理员权限(内核 ETW 提供者)。支持源码运行与 PyInstaller 打包后运行。"""
import json, os, re, subprocess, sys, threading, time, glob as _glob

# --out <file>: 结果同时写入文件(供提权重启后取回)
if '--out' in sys.argv:
    _of = sys.argv[sys.argv.index('--out') + 1]
    sys.stdout = open(_of, 'w', encoding='utf-8', buffering=1)
    sys.stderr = sys.stdout

IS_FROZEN = getattr(sys, 'frozen', False)
BASE = os.path.dirname(sys.executable) if IS_FROZEN else os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE, 'Rules')):
    BASE = os.getcwd()
PASS, FAIL = [], []

def check(name, ok, note=''):
    (PASS if ok else FAIL).append(name)
    print(('PASS ' if ok else 'FAIL ') + name + (f'  [{note}]' if note else ''))

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

import ctypes
print(f'== ETW 全功能测试 (BASE={BASE}, 管理员={is_admin()}) ==')

# ---------- A. 静态规则测试 ----------
SUPPORTED_KINDS = {'processcreate', 'processexit', 'imageload', 'filecreate', 'fileopen', 'filewrite',
                   'filemodify', 'filedelete', 'filedrop', 'registryset', 'registrydelete',
                   'netconnect', 'dnsquery'}

def glob2rx(g):
    """与生产 _glob_to_re 逐字一致"""
    gl = g.lower().replace('/', '\\')
    out, i, n = ['^'], 0, len(gl)
    while i < n:
        if gl[i] == '?' and gl[i + 1:i + 3] == ':\\':
            out.append('[a-z]:\\\\'); i += 3; continue
        c = gl[i]
        if c == '*':
            if i + 1 < n and gl[i + 1] == '*':
                out.append('.*'); i += 2; continue
            out.append('[^\\\\]*'); i += 1; continue
        if c == '?':
            out.append('[^\\\\]'); i += 1; continue
        out.append(re.escape(c)); i += 1
    out.append('$')
    return re.compile(''.join(out))

rules_dir = os.path.join(BASE, 'Rules')
white_n, match_n, unsupported = 0, 0, set()
glob_ok = True
rules_by_id = {}
for fn in sorted(os.listdir(rules_dir)):
    if not fn.endswith('.json'):
        continue
    try:
        d = json.load(open(os.path.join(rules_dir, fn), encoding='utf-8'))
    except Exception as e:
        check(f'规则文件JSON有效: {fn}', False, str(e)); continue
    for r in d.get('rules', []):
        kinds = {k.lower() for k in r.get('kinds', [])}
        for g in r.get('glob', []) + r.get('proc_glob', []) + r.get('except_glob', []):
            try:
                glob2rx(g)
            except Exception as e:
                glob_ok = False; print(f'  glob编译失败 {r.get("id")}: {g} {e}')
        rules_by_id[r.get('id', '?')] = (fn, r)
        if r.get('action') == 'allow':
            white_n += 1
        elif kinds:
            sup = kinds & SUPPORTED_KINDS
            if sup:
                match_n += 1
            else:
                unsupported |= kinds
        else:
            match_n += 1   # 无kinds且非白名单: 主进程侧也计入拦截/记录
check('A1 全部规则文件JSON有效且glob可编译', glob_ok and len(rules_by_id) >= 20, f'{len(rules_by_id)}条规则')
check('A2 回归: White树状白名单已限kinds(进程类不短路)',
      'kinds' in rules_by_id.get('White_Windows_Tree', ('', {}))[1])
check('A3 回归: Proc_Lolbin except 不含 program files(Office父进程可达)',
      not any('program files' in e for e in rules_by_id.get('Proc_Lolbin_Suspicious_Launch', ('', {}))[1].get('except_glob', [])))
check('A4 回归: File_Drop_To_Startup 主体不含 explorer(用户拖放不误报)',
      not any('explorer' in p for p in rules_by_id.get('File_Drop_To_Startup', ('', {}))[1].get('proc_glob', [])))
check('A5 回归: White_Common_Runtimes 仅 mpcmdrun(宏链规则可达)',
      len(rules_by_id.get('White_Common_Runtimes', ('', {}))[1].get('glob', [])) == 1)

# ---------- B. 运行时测试 ----------
if not is_admin():
    print('\nFAIL B0 需要管理员权限(内核ETW提供者), 请以管理员运行')
    sys.exit(1)

worker_exe = os.path.join(BASE, 'SevenEndPoint.exe')
if os.path.isfile(worker_exe):
    cmd = [worker_exe, '--etw-worker']
elif os.path.isfile(os.path.join(BASE, 'SevenEndPoint.py')):
    cmd = [sys.executable if not IS_FROZEN else 'python',
           os.path.join(BASE, 'SevenEndPoint.py'), '--etw-worker']
else:
    print('FAIL B0 找不到 SevenEndPoint.exe / SevenEndPoint.py'); sys.exit(1)

# 先确保没有残留会话
subprocess.run(['logman', '-ets', 'stop', 'SevenEndPointTelemetry'],
               capture_output=True, creationflags=0x08000000)
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True, encoding='utf-8',
                        errors='replace', cwd=BASE,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
lines_q, errs = [], []
def _reader():
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                try:
                    lines_q.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
threading.Thread(target=_reader, daemon=True).start()

def wait_for(pred, timeout):
    end = time.time() + timeout
    idx = 0
    while time.time() < end:
        while idx < len(lines_q):
            m = lines_q[idx]; idx += 1
            if pred(m):
                return m, idx
        time.sleep(0.2)
    return None, idx

def alerts_since(idx):
    return [m for m in lines_q[idx:] if m.get('type') == 'etw_alert']

try:
    # B1 规则加载 + 会话启动
    m, idx1 = wait_for(lambda x: x.get('type') == 'etw_status' and '规则就绪' in x.get('msg', ''), 30)
    check('B1 ETW worker拉起并完成规则加载', m is not None, m and m.get('msg', '')[:70])
    if m:
        mm = re.search(r'(\d+)白名单 (\d+)拦截/记录, 未支持类别: \[([^\]]*)\]', m['msg'])
        if mm:
            w, r_, un = int(mm.group(1)), int(mm.group(2)), mm.group(3)
            un_set = set(filter(None, un.replace("'", '').replace(' ', '').split(',')))
            check('B2 规则计数与静态计算一致', w == white_n and r_ == match_n, f'worker: {w}白名单/{r_}拦截 静态: {white_n}/{match_n}')
            check('B3 未支持类别=驱动遗留三类(serviceop已转注册表遥测)', un_set ==
                  {'memthreat', 'processinject', 'processopen'}, un)
    m2, idx2 = wait_for(lambda x: x.get('type') == 'etw_status' and '会话已启动' in x.get('msg', ''), 30)
    providers_ok = m2 is not None and all(p in m2.get('msg', '') for p in ("'process'", "'file'", "'registry'", "'network'", "'dns'"))
    check('B4 ETW会话已启动且5个提供者全开', providers_ok, m2 and m2.get('msg', '')[:90])
    errs_now = [x for x in lines_q[:idx2] if x.get('type') == 'etw_error']
    check('B5 结构体自检通过(无sizeof/OpenTrace错误)', not any('sizeof' in x.get('msg', '') or 'OpenTrace' in x.get('msg', '') for x in errs_now),
          '; '.join(x.get('msg', '')[:60] for x in errs_now[:2]))
    lm = subprocess.run(['logman', '-ets', 'query', 'SevenEndPointTelemetry'],
                        capture_output=True, text=True, creationflags=0x08000000)
    check('B6 logman确认会话在系统层运行', 'SevenEndPointTelemetry' in (lm.stdout or ''), '')

    # B7 良性风暴: 零误报
    tmp = os.environ.get('TEMP', BASE)
    tdir = os.path.join(tmp, 'etw_benign_test')
    os.makedirs(tdir, exist_ok=True)
    idx_b = len(lines_q)
    for i in range(5):
        subprocess.run(['cmd', '/c', f'echo benign {i} > "{tdir}\\b{i}.txt"'], capture_output=True, creationflags=0x08000000)
        subprocess.run(['reg', 'add', f'HKCU\\Software\\SevenEtwTest', '/v', f'b{i}', '/t', 'REG_DWORD', '/d', '1', '/f'],
                       capture_output=True, creationflags=0x08000000)
    for i in range(3):
        subprocess.run(['cmd', '/c', 'echo x'], capture_output=True, creationflags=0x08000000)
    time.sleep(8)
    blocks = [a for a in alerts_since(idx_b) if a.get('action') == 'block']
    check('B7 良性风暴(建文件/reg写/子进程)零block告警', not blocks,
          '; '.join(f"{a.get('rule')}:{a.get('path', '')[:40]}" for a in blocks[:3]))
    for i in range(5):
        try: os.remove(os.path.join(tdir, f'b{i}.txt'))
        except Exception: pass
    subprocess.run(['reg', 'delete', 'HKCU\\Software\\SevenEtwTest', '/f'], capture_output=True, creationflags=0x08000000)

    # B8 受控block触发: 写 *.lockbit (勒索标志扩展名, File_Ransom_Encrypt_Ext_Spike, 任何主体都命中)
    tdh_ok = any('TDH属性布局校准成功' in x.get('msg', '') for x in lines_q)
    tdh_fail = any('TDH属性布局校准失败' in x.get('msg', '') for x in lines_q)
    idx_c = len(lines_q)
    tfile = os.path.join(tmp, f'etw_test_{os.getpid()}_{int(time.time())}.lockbit')
    with open(tfile, 'w') as f:
        f.write('harmless trigger content')
    m3, _ = wait_for(lambda x: x.get('type') == 'etw_alert' and x.get('action') == 'block'
                     and x.get('rule') == 'File_Ransom_Encrypt_Ext_Spike' and 'etw_test_' in x.get('path', ''), 25)
    if m3:
        check('B8 端到端: 写.lockbit触发block告警(规则/动作/路径全对)', True,
              f"kind={m3.get('kind')} sev={m3.get('severity')} pid={m3.get('pid')}")
    elif tdh_fail:
        # 环境降级: 属性解析不可用→路径型规则无法匹配, worker有明确自检告警即视为符合设计
        check('B8 端到端block触发', False, 'TDH属性解析不可用, 路径型规则无法匹配(见B8a)')
        check('B8a 降级自检: worker明确上报TDH校准失败', True)
    else:
        check('B8 端到端: 写.lockbit触发block告警(规则/动作/路径全对)', False,
              f'tdh_ok={tdh_ok} 全部status: ' + ' | '.join(x.get("msg", "")[:50] for x in lines_q if x.get("type") == "etw_status")[:200])
    check('B7b 良性阶段无log告警噪音', not [a for a in lines_q[idx_b:idx_c] if a.get('type') == 'etw_alert'],
          '')
    try: os.remove(tfile)
    except Exception: pass
finally:
    proc.terminate()
    time.sleep(2)
    lm = subprocess.run(['logman', '-ets', 'query', 'SevenEndPointTelemetry'], capture_output=True, text=True, creationflags=0x08000000)
    if 'SevenEndPointTelemetry' in (lm.stdout or ''):
        subprocess.run(['logman', '-ets', 'stop', 'SevenEndPointTelemetry'], capture_output=True, creationflags=0x08000000)
        check('B9 会话清理(worker被硬杀, logman兜底停止)', True, '残留会话已由logman清理')
    else:
        check('B9 会话清理(worker退出即清理, 无泄漏)', True)

print()
print(f'=== ETW测试结果: {len(PASS)} 通过 / {len(FAIL)} 失败 ===')
sys.exit(1 if FAIL else 0)
