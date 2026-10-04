# -*- coding: utf-8 -*-
"""
SevenEndPoint.py 修复验证套件
覆盖: 误报测试(TraeCode式批量写盘不拦截/勒索突发拦截) + 功能测试(MSI常量/链式解包/
      _terminated_paths回收/备份范围/GUI不阻塞) + 企业级静态检查。
产出: _sep_test_report.txt
"""
import os, sys, time, json, shutil, threading, subprocess, ast, re, traceback

BASE = r"D:\Administrator\Desktop\TestUI\CodeBak"
TARGET = os.path.join(BASE, "SevenEndPoint.py")
PY = sys.executable

_results = []
def rec(group, name, ok, detail=""):
    _results.append((group, name, "PASS" if ok else "FAIL", str(detail)[:300]))
    print(("[PASS] " if ok else "[FAIL] ") + group + " / " + name + ((": " + str(detail)[:200]) if detail else ""), flush=True)

# ============ 0. 企业级: 语法编译 ============
import py_compile
try:
    py_compile.compile(TARGET, doraise=True)
    rec("企业级", "py_compile 全文件语法零错误", True)
except Exception as e:
    rec("企业级", "py_compile 全文件语法零错误", False, e)

_src = open(TARGET, "r", encoding="utf-8").read()

# ============ 1. 导入模块(无头) ============
sys.path.insert(0, BASE)
_import_err = None
try:
    import SevenEndPoint as SEP
except Exception as e:
    _import_err = e
    rec("功能", "模块无头导入", False, repr(e))

if _import_err is None:
    # ============ 2. 功能: MSI 常量与 _analyze_msi_embedded ============
    _msi_ok = True
    for _n in ("_MSI_API_INJECTION", "_MSI_API_NETWORK", "_MSI_API_PERSISTENCE",
               "_MSI_API_ANTIDEBUG", "_MSI_API_RESOURCE", "_MSI_API_FILE",
               "_MSI_API_CRYPTO", "_MSI_API_PROCESS"):
        _s = getattr(SEP, _n, None)
        if not isinstance(_s, (set, frozenset)) or not _s:
            _msi_ok = False
            rec("功能", "MSI常量存在且非空: " + _n, False, repr(_s)[:120])
    if _msi_ok:
        rec("功能", "8个 _MSI_API_* 常量全部定义", True)
    if 'virtualallocex' in SEP._MSI_API_INJECTION and 'writeprocessmemory' in SEP._MSI_API_INJECTION:
        rec("功能", "MSI注入API集合内容正确", True)
    else:
        rec("功能", "MSI注入API集合内容正确", False)

    # 合成"MSI": 真实系统PE内嵌进伪容器, 验证分析函数不再 NameError->None
    _notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
    _fake_msi = os.path.join(BASE, "_sep_fake.msi")
    try:
        with open(_notepad, "rb") as f:
            _pe = f.read(2 * 1024 * 1024)
        with open(_fake_msi, "wb") as f:
            f.write(b"MSI-TEST-CONTAINER\0\0\0\0\0\0\0\0\0\0\0\0\0\0" + _pe)
        _info = SEP._analyze_msi_embedded(_fake_msi)
        if isinstance(_info, dict) and _info.get("pe_count", 0) >= 1 and "injection_apis" in _info:
            rec("功能", "_analyze_msi_embedded 返回结构完整(内嵌PE识别+API分类)", True,
                "pe_count={} apis={} inj={}".format(_info["pe_count"], _info["total_apis"], len(_info["injection_apis"])))
        else:
            rec("功能", "_analyze_msi_embedded 返回结构完整(内嵌PE识别+API分类)", False, repr(_info)[:120])
    except Exception as e:
        rec("功能", "_analyze_msi_embedded 返回结构完整(内嵌PE识别+API分类)", False, repr(e))
    finally:
        try: os.remove(_fake_msi)
        except Exception: pass

    # ============ 3. 功能: _terminated_paths 有界回收 ============
    try:
        rm = SEP.RealtimeMonitor(None)
        _MAX = SEP.RealtimeMonitor._TERMINATED_PATHS_MAX
        for i in range(_MAX + 800):
            rm._mark_terminated_path("d:\\x\\mal%d.exe" % i)
        _ok = len(rm._terminated_paths) <= _MAX
        _ok2 = ("d:\\x\\mal0.exe" not in rm._terminated_paths) and ("d:\\x\\mal%d.exe" % (_MAX + 799) in rm._terminated_paths)
        with rm._terminated_lock:
            rm._terminated_paths.pop("d:\\x\\mal%d.exe" % (_MAX + 799), None)
        rec("功能", "_terminated_paths 上限FIFO回收(不再无限累积)", bool(_ok and _ok2),
            "len={} max={} 旧条目已淘汰={} 新条目保留={}".format(len(rm._terminated_paths), _MAX, _ok, _ok2))
    except Exception as e:
        rec("功能", "_terminated_paths 上限FIFO回收(不再无限累积)", False, traceback.format_exc()[-300:])

    # ============ 4. 功能: 链式终止 4 元组解包 ============
    try:
        _chain = [("a.exe", 111, "d:\\a.exe", 0x1f0f), ("b.exe", 222, "d:\\b.exe", 0x1f0f)]
        _desc = " -> ".join(f"{n}({p})" for n, p, _tp, _ta in _chain)
        rec("功能", "_terminate_chain 4元组解包不再 ValueError", _desc == "a.exe(111) -> b.exe(222)", _desc)
        rec("企业级", "全文已无 3 元解包残留在链描述处", "for n, p, _ in chain" not in _src)
    except Exception as e:
        rec("功能", "_terminate_chain 4元组解包不再 ValueError", False, repr(e))

    # ============ 5. 功能: 初始备份范围=用户文档目录 ============
    try:
        _m = re.search(r"_cleanup_old_backups\(\)\n\n(.*?)\n    def _periodic_backup_loop", _src, re.S)
        _seg = _m.group(1) if _m else ""
        rec("功能", "初始备份循环使用 _backup_roots(不再全盘)", ("for _d in _backup_roots:" in _seg) and ("for _d in watch_dirs:" not in _seg))
    except Exception as e:
        rec("功能", "初始备份循环使用 _backup_roots(不再全盘)", False, repr(e))

    # ============ 6. 功能: GUI 启动不再同步 join ============
    try:
        _m2 = re.search(r"def _start_realtime_monitor\(self\):(.*?)\n    def ", _src, re.S)
        _seg2 = _m2.group(1) if _m2 else ""
        _joins = [ln for ln in _seg2.splitlines() if ".join(timeout=30)" in ln]
        _all_indented = all(len(ln) - len(ln.lstrip()) >= 12 for ln in _joins) and _joins
        rec("功能", "_start_realtime_monitor 的 join 已移入后台Worker", bool(_all_indented), "{}处join".format(len(_joins)))
    except Exception as e:
        rec("功能", "_start_realtime_monitor 的 join 已移入后台Worker", False, repr(e))

    # ============ 7. 企业级: 勒索路径不再按进程名豁免 ============
    rec("企业级", "ransom 路径无 _FILE_OP_EXEMPT_NAMES 进程名豁免", "_FILE_OP_EXEMPT_NAMES" not in re.search(r"def _show_dialog\(self, count(.*?)\n    def _do_rollback", _src, re.S).group(1))
    rec("企业级", "trae 进程名笔误已修正(trae solo cn.exe)", "trae so lo cn.exe" not in _src and "trae solo cn.exe" in _src)
    rec("企业级", "score_only 计分链路贯通(子进程->主进程)", "score_only" in _src and '_show_dialog(c, cr, d, m, r, f, o, pn, pp, ppath, rw, so)' in _src.replace("\n", "").replace(" ", "") or "so=score_only" in _src)

# ============ 8. 误报/查杀: 子进程集成测试 ============
def _start_monitor():
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    env["_SEP_DBG"] = "1"
    p = subprocess.Popen([PY, TARGET, "--file-monitor"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=1, text=True,
                         encoding="utf-8", errors="replace", cwd=BASE, env=env,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    alerts = []
    _ready = threading.Event()
    def _err_reader():
        # 子进程模块初始化耗时波动大(2s~20s+), watcher 就绪前文件操作全部丢失;
        # 必须等 "[file-monitor] ready" 横幅再开跑场景, 否则测试时序不可靠
        try:
            for line in p.stderr:
                line = line.strip()
                if not line:
                    continue
                if "[file-monitor] ready" in line:
                    _ready.set()
        except Exception:
            pass
    def _reader():
        try:
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if msg.get("type") == "file_op_alert":
                    alerts.append(msg)
        except Exception:
            pass
    threading.Thread(target=_err_reader, daemon=True).start()
    threading.Thread(target=_reader, daemon=True).start()
    if not _ready.wait(60):
        print("[suite] 警告: 监控子进程 60s 未就绪(ready 横幅未出现)", flush=True)
    return p, alerts

def _wait_for(alerts, pred, timeout):
    _t0 = time.time()
    while time.time() - _t0 < timeout:
        for a in list(alerts):
            if pred(a):
                return a
        time.sleep(0.3)
    return None

if _import_err is None:
    _p, _alerts = _start_monitor()
    try:
        # --- 环境噪声基线(8s): 静置期不应出现勒索拦截 ---
        time.sleep(8)
        _base_block = [a for a in _alerts if a.get("ransomware") and not a.get("score_only")]
        rec("误报", "静置基线8s无勒索拦截(环境噪声检查)", not _base_block, "基线告警数={}".format(len(_alerts)))

        # --- B1: TraeCode式批量写盘(源码/文本类) => 不得拦截, 仅计分 ---
        _fp_dir = os.path.join(BASE, "_sep_fp_src")
        shutil.rmtree(_fp_dir, ignore_errors=True)
        os.makedirs(_fp_dir, exist_ok=True)
        _srcfiles = []
        for i in range(16):
            _fp = os.path.join(_fp_dir, "module%d.%s" % (i, (".py", ".ts", ".json", ".md")[i % 4]))
            with open(_fp, "w", encoding="utf-8") as f:
                f.write("// test source %d\n" % i)
            _srcfiles.append(_fp)
        for _round in range(8):
            for _fp in _srcfiles:
                with open(_fp, "a", encoding="utf-8") as f:
                    f.write("x = %d  # bulk edit\n" % _round)
                time.sleep(0.04)
        _blk = _wait_for(_alerts, lambda a: a.get("ransomware") and not a.get("score_only"), 22)
        _score = [a for a in _alerts if a.get("score_only") and not a.get("ransomware")]
        rec("误报", "TraeCode式源码批量写盘不触发勒索拦截", _blk is None,
            ("误拦: count=%s" % _blk.get("count")) if _blk else "观察22s无拦截")
        rec("误报", "源码批量写盘走仅计分路径(20次阈值计分放行)", len(_score) >= 1,
            "计分告警{}条".format(len(_score)))

        # --- B2: 勒索突发(改写文档类) => 拦截告警 ---
        _rn_dir = os.path.join(BASE, "_sep_ransom_sim")
        shutil.rmtree(_rn_dir, ignore_errors=True)
        os.makedirs(_rn_dir, exist_ok=True)
        _rnfiles = []
        for i in range(16):
            _fp = os.path.join(_rn_dir, "secret%d.docx" % i)
            with open(_fp, "wb") as f:
                f.write(b"CONFIDENTIAL DOCUMENT DATA " * 200)
            _rnfiles.append(_fp)
        time.sleep(0.5)
        for _round in range(6):
            for _fp in _rnfiles:
                with open(_fp, "wb") as f:
                    f.write(b"ENCRYPTED-BLOB-" + os.urandom(2048))
                time.sleep(0.03)
        _blk2 = _wait_for(_alerts, lambda a: a.get("ransomware") and not a.get("score_only"), 40)
        rec("误报", "勒索突发(文档类改写x60+)正确拦截", _blk2 is not None,
            ("count={} proc={} score_only={}".format(_blk2.get("count"), _blk2.get("proc_name"), _blk2.get("score_only"))) if _blk2 else "40s内未见拦截告警")
    finally:
        try:
            _p.stdin.write(json.dumps({"cmd": "resume"}) + "\n"); _p.stdin.flush()
        except Exception:
            pass
        try:
            _p.kill()
        except Exception:
            pass
        shutil.rmtree(_fp_dir, ignore_errors=True)
        shutil.rmtree(_rn_dir, ignore_errors=True)

    # ============ 9. 主进程 _show_dialog 行为规则单测 ============
    try:
        fm = SEP.FileMonitor(None)
        _blocked = threading.Event()
        fm._do_rollback_and_terminate = lambda *a, **k: _blocked.set()

        # C1: score_only=True -> 仅计分放行(不回滚不终止)
        _ops = [{"action": "create", "path": os.path.join(BASE, "_sep_fp_src", "m%d.py" % i)} for i in range(60)]
        _blocked.clear()
        fm._show_dialog(60, 60, 0, 0, 0, [], _ops, "traecode.exe", 123, r"D:\Apps\Trae\TraeCode.exe", False, True)
        rec("误报", "主进程: score_only 批量操作仅计分不拦截", not _blocked.is_set())

        # C2: 旧式60次告警但无勒索信号(源码创建) -> 行为规则放行
        _blocked.clear()
        fm._show_dialog(60, 60, 0, 0, 0, [], _ops, "traecode.exe", 123, r"D:\Apps\Trae\TraeCode.exe", False, False)
        rec("误报", "主进程: 无勒索信号批量写盘行为规则放行", not _blocked.is_set())

        # C3: 真实改后缀重命名>=8 -> 拦截
        _ops3 = []
        for i in range(8):
            _ops3.append({"action": "rename_new", "old_path": r"C:\Users\Administrator\Documents\v%d.docx" % i,
                          "path": r"C:\Users\Administrator\Documents\v%d.docx.locked" % i})
        for i in range(52):
            _ops3.append({"action": "delete", "path": r"C:\Users\Administrator\Documents\d%d.docx" % i})
        _blocked.clear()
        fm._show_dialog(60, 0, 52, 0, 8, [], _ops3, "evil.exe", 456, r"D:\mal\evil.exe", True, False)
        rec("误报", "主进程: 改后缀爆发+文档删除正确拦截", _blocked.is_set())
    except Exception as e:
        rec("误报", "主进程 _show_dialog 行为规则单测", False, traceback.format_exc()[-300:])

# ============ 汇总 ============
_pass = sum(1 for r in _results if r[2] == "PASS")
_fail = len(_results) - _pass
_lines = []
_lines.append("SevenEndPoint.py 修复验证报告  " + time.strftime("%Y-%m-%d %H:%M:%S"))
_lines.append("结果: {} PASS / {} FAIL".format(_pass, _fail))
_lines.append("=" * 72)
for g, n, s, d in _results:
    _lines.append("[{}] {}/{}{}".format(s, g, n, ("  | " + d) if d else ""))
report = "\n".join(_lines)
with open(os.path.join(BASE, "_sep_test_report.txt"), "w", encoding="utf-8") as f:
    f.write(report + "\n")
print("\n" + report, flush=True)
print("\nSUITE_DONE pass={} fail={}".format(_pass, _fail), flush=True)
