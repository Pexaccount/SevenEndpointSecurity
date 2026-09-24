import os, sys, threading, time, json, subprocess, hashlib
import shutil, zipfile, traceback, re, math, fnmatch, io, queue
import logging
import ctypes
from collections import OrderedDict, Counter

from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSignal, pyqtProperty, QPoint, QRect, QRectF, QPropertyAnimation, QEasingCurve, QObject, QByteArray, QBuffer, QIODevice, QEvent, QVariantAnimation
from PyQt6.QtGui import QFont, QFontMetrics, QIcon, QPixmap, QPainter, QColor, QPen, QBrush, QPainterPath, QLinearGradient, QRadialGradient, QPalette, QAction, QPolygon
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QSystemTrayIcon, QMenu, QStackedWidget, QScrollArea,
                             QTextEdit, QPushButton, QFrame, QGraphicsDropShadowEffect,
                             QSizePolicy, QCheckBox, QLineEdit, QFileDialog, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
                             QToolButton, QSpacerItem, QGridLayout,
                             QDialog, QListWidget, QListWidgetItem, QGraphicsOpacityEffect,
                             QComboBox, QGraphicsScene, QGraphicsView,
                             QGraphicsRectItem, QGraphicsLineItem, QGraphicsTextItem)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtSvgWidgets import QSvgWidget

_gui_queue = queue.Queue()
_g_log_lines = []
_g_scan_log_lines = []
MAX_LOG_LINES = 5000
_g_intercept_records = []
_g_intercept_lock = threading.Lock()
MAX_INTERCEPT_RECORDS = 500
_g_behavior_tree = {}
_g_behavior_lock = threading.Lock()
# 进程释放的落盘文件登记(pid -> {path,...}),供拦截后攻击链回滚
_g_dropped_files = {}
_g_dropped_files_lock = threading.Lock()

def _record_dropped_file(pid, filepath):
    """登记进程释放的落盘文件,供攻击链拦截后回滚删除。"""
    if not pid or not filepath:
        return
    try:
        pid = int(pid)
    except Exception:
        return
    with _g_dropped_files_lock:
        s = _g_dropped_files.setdefault(pid, set())
        s.add(filepath)
        if len(s) > 80:
            for old in sorted(s, key=lambda p: 0)[:len(s) - 80]:
                s.discard(old)
        if len(_g_dropped_files) > 600:
            _g_dropped_files.clear()

def _record_interception(record_type, name, path, threat_type='', confidence=0, engine='', action='terminated', extra=''):
    global _g_intercept_records
    rec = {
        'time': time.time(),
        'time_str': time.strftime('%Y-%m-%d %H:%M:%S'),
        'type': record_type,
        'name': name,
        'path': path,
        'threat_type': threat_type,
        'confidence': confidence,
        'engine': engine,
        'action': action,
        'extra': extra,
    }
    with _g_intercept_lock:
        _g_intercept_records.append(rec)
        if len(_g_intercept_records) > MAX_INTERCEPT_RECORDS:
            _g_intercept_records = _g_intercept_records[-MAX_INTERCEPT_RECORDS:]
    return rec


# ============================ EDR 事件评分账本(企业级行为打分) ============================
# 规则: 违规操作 +10 / 文件操作 +5 / 释放驱动 +15 / DLL释放 +5 / 脚本运行 +5 /
#       敏感注册表 +5(非敏感不计); 累计 >= EDR_SCORE_THRESHOLD(70) -> 终止整链 + 回滚全部操作 + 溯源报告。
g_window = None            # main() 注入, 供账本访问 RealtimeMonitor
EDR_EVENT_POINTS = {
    'violation': 10,           # 违规操作(命中拦截规则等)
    'file_op': 5,              # 可疑文件操作(释放/落盘/写入)
    'driver_drop': 15,         # 释放驱动
    'dll_drop': 5,             # DLL 释放
    'script_run': 5,           # 任何脚本运行(cmd/bat/ps1/js/vbs...)
    'registry_sensitive': 5,   # 敏感注册表操作
    'task_sched': 10,          # 任务计划/持久化操作
    'c2': 10,                  # C2/可疑外联
}
_g_edr_scores = {}
_g_edr_scores_lock = threading.Lock()
LINE_REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Line')

def _edr_add_event(pid, name, path, etype, points=None, detail=''):
    """给进程累积 EDR 行为分; 达到阈值(70)自动终止整链+回滚全部操作+生成溯源HTML+通知。"""
    try:
        pid = int(pid or 0)
        if pid <= 0:
            return 0
        if points is None:
            points = EDR_EVENT_POINTS.get(etype, 5)
        points = int(points)
        now = time.time()
        with _g_edr_scores_lock:
            rec = _g_edr_scores.get(pid)
            if rec is None:
                if len(_g_edr_scores) > 2000:
                    for k in list(_g_edr_scores.keys())[:1000]:
                        _g_edr_scores.pop(k, None)
                rec = {'name': name or '', 'path': path or '', 'score': 0, 'events': []}
                _g_edr_scores[pid] = rec
            rec['score'] += points
            rec.setdefault('events', []).append((now, etype, str(detail)[:200], points))
            if len(rec['events']) > 400:
                rec['events'] = rec['events'][-400:]
            score = rec['score']
        _log("[EDR评分] {}({}) +{} [{}] => {}分".format(name or '?', pid, points, etype, score))
        if score >= EDR_SCORE_THRESHOLD:
            _edr_enforce_chain(pid)
        return score
    except Exception as e:
        _log("[EDR评分] 异常: {}".format(e))
        return 0

def _edr_get_chain_events(pid, name, path, extra_events=None):
    """汇总溯源事件: 账本事件 + 传入事件 + 行为链动作。返回 [(time, desc, points)]。"""
    rows = []
    try:
        with _g_edr_scores_lock:
            rec = _g_edr_scores.get(int(pid or 0)) or {}
            for ts, et, det, pt in (rec.get('events') or [])[-200:]:
                rows.append((ts, "[{}] {}".format(et, det), pt))
    except Exception:
        pass
    if extra_events:
        for desc, pt in extra_events:
            rows.append((time.time(), str(desc), int(pt or 0)))
    try:
        with _g_behavior_lock:
            node = _g_behavior_tree.get(pid)
            if node:
                for a in (node.get('actions') or [])[-50:]:
                    rows.append((a.get('time', 0), "[chain] {} {}".format(a.get('action', ''), a.get('detail', ''))[:200], 0))
    except Exception:
        pass
    rows.sort(key=lambda r: r[0])
    return rows

def _edr_report_chain(pid, name, path, events, action='blocked'):
    """把攻击链(进程树+事件+评分+处置)生成 HTML 报告, 写入 Line/ 目录。"""
    try:
        os.makedirs(LINE_REPORT_DIR, exist_ok=True)
        rows = _edr_get_chain_events(pid, name, path, events)
        # 进程树(向上父链 + 子进程)
        tree_rows = []
        try:
            with _g_behavior_lock:
                node = _g_behavior_tree.get(pid)
                seen = set()
                cur = node
                depth = 0
                while cur is not None and id(cur) not in seen and depth < 8:
                    seen.add(id(cur))
                    tree_rows.append(("{}{} {} (PID:{})".format('&nbsp;' * depth * 4,
                                     _html_esc(cur.get('name') or '?'), _html_esc(cur.get('path') or ''), cur.get('pid', '?')),
                                     'alive' if cur.get('alive') else 'exited'))
                    npid = cur.get('ppid')
                    cur = _g_behavior_tree.get(npid) if npid else None
                    depth += 1
                if node:
                    for cpid in (node.get('children') or [])[:30]:
                        c = _g_behavior_tree.get(cpid)
                        if c:
                            tree_rows.append(("&nbsp;&nbsp;&nbsp;&nbsp;└─ {} (PID:{})".format(
                                _html_esc(c.get('name') or '?'), c.get('pid', '?')),
                                'alive' if c.get('alive') else 'exited'))
        except Exception:
            pass
        with _g_dropped_files_lock:
            dropped = sorted(_g_dropped_files.get(int(pid or 0), set()))[:80]
        score = 0
        try:
            with _g_edr_scores_lock:
                score = (_g_edr_scores.get(int(pid or 0)) or {}).get('score', 0)
        except Exception:
            pass
        ev_html = ''.join(
            "<tr><td>{}</td><td>{}</td><td style='text-align:right'>{}</td></tr>".format(
                time.strftime('%H:%M:%S', time.localtime(ts)) if ts else '-',
                _html_esc(desc), pt)
            for ts, desc, pt in rows)
        tree_html = ''.join("<div class='{}'>{}</div>".format(st, tx) for tx, st in tree_rows)
        drop_html = ''.join("<li>{}</li>".format(_html_esc(f)) for f in dropped) or '<li>(none)</li>'
        css = ("body{font-family:Consolas,'Microsoft YaHei',monospace;background:#141d2b;color:#d8e2f0;margin:24px}"
               "h1{color:#4fc3f7;font-size:20px}h2{color:#ffb74d;font-size:15px;margin-top:22px}"
               "table{border-collapse:collapse;width:100%}td{border:1px solid #2c3d57;padding:4px 8px;font-size:13px}"
               ".alive{color:#81c784}.exited{color:#90a4ae}.badge{background:#d32f2f;color:#fff;padding:2px 10px;border-radius:10px}"
               "li{font-size:13px}")
        html = ("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Attack Chain Report</title>"
                "<style>" + css + "</style></head><body>"
                "<h1>Attack Chain Report - SevenEndPointSecurity EDR <span class='badge'>" + _html_esc(action) + "</span></h1>"
                "<p><b>Process:</b> " + _html_esc(name or 'Unknown.exe') + " (PID: " + str(int(pid or 0)) + ")<br>"
                "<b>Path:</b> " + _html_esc(path or '') + "<br>"
                "<b>Time:</b> " + time.strftime('%Y-%m-%d %H:%M:%S') + "<br>"
                "<b>Score:</b> " + str(score) + "</p>"
                "<h2>Process Tree</h2>" + tree_html +
                "<h2>Events (traced)</h2><table>" + ev_html + "</table>"
                "<h2>Dropped Files</h2><ul>" + drop_html + "</ul>"
                "</body></html>")
        fname = "chain_{}_{}.html".format(int(pid or 0), time.strftime('%Y%m%d_%H%M%S'))
        fpath = os.path.join(LINE_REPORT_DIR, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(html)
        _log("[EDR溯源] 攻击链报告已生成: {}".format(fpath))
        # 只保留最近 100 份报告
        try:
            olds = sorted(os.listdir(LINE_REPORT_DIR))
            if len(olds) > 100:
                for old in olds[:-100]:
                    try:
                        os.remove(os.path.join(LINE_REPORT_DIR, old))
                    except Exception:
                        pass
        except Exception:
            pass
        return fpath
    except Exception as e:
        _log("[EDR溯源] 报告生成失败: {}".format(e))
        return None

def _html_esc(s):
    return (str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))

def _edr_enforce_chain(pid):
    """评分达阈值(70): 终止整条进程链 + 回滚全部落盘 + 溯源HTML + Threat Block 通知。"""
    with _g_edr_scores_lock:
        rec = _g_edr_scores.get(int(pid or 0))
        if not rec or rec.get('enforced'):
            return
        rec['enforced'] = True
    name = rec.get('name') or 'Unknown.exe'
    path = rec.get('path') or ''
    _log("[EDR] 行为评分达阈值, 还原攻击链: {}({}) {}".format(name, pid, path))
    # 1) 终止整条进程链
    rt = getattr(g_window, '_realtime_monitor', None) if g_window else None
    try:
        if rt:
            rt._terminate_chain(int(pid), full=True)
    except Exception as e:
        _log("[EDR] 终止进程链失败: {}".format(e))
    # 2) 回滚整链落盘(含链内文件扫描->威胁隔离)
    try:
        if rt:
            rt._rollback_chain_drops({int(pid)})
        else:
            _rollback_chain_files({int(pid)}, notify=True)
    except Exception as e:
        _log("[EDR] 回滚失败: {}".format(e))
    # 3) 溯源 + 通知
    _record_interception('EDR行为评分拦截', name, path, threat_type='Behavior Score',
                         confidence=min(100, rec.get('score', 0)), engine='EDR-Ledger',
                         action='terminated', extra='评分达{}触发整链回滚'.format(EDR_SCORE_THRESHOLD))
    _edr_report_chain(pid, name, path, [('Score threshold reached - chain rolled back', 0)],
                      action='rolled back')
    _notify("Threat Block", "Threat Block {}".format(name))
    # 清账
    try:
        with _g_edr_scores_lock:
            _g_edr_scores.pop(int(pid or 0), None)
    except Exception:
        pass

def _rollback_chain_files(pids, notify=True):
    """回滚一组 pid 的落盘文件: 先扫描, 威胁 -> 隔离+通知; 干净 -> 删除。"""
    quarantined = []
    removed = 0
    with _g_dropped_files_lock:
        targets = set()
        for p in (pids or []):
            targets |= _g_dropped_files.pop(int(p or 0), set())
    for fp in targets:
        try:
            if not fp or not os.path.exists(fp):
                continue
            verdict = "CLEAN"
            _t = ""
            try:
                if g_scanner:
                    verdict, _c, _t = g_scanner.scan_file(fp)
            except Exception:
                verdict = "CLEAN"
            fname = os.path.basename(fp)
            if verdict.startswith("MALICIOUS"):
                try:
                    os.makedirs(QUARANTINE_DIR, exist_ok=True)
                    dest = os.path.join(QUARANTINE_DIR, fname + ".quarantine")
                    shutil.move(fp, dest)
                    quarantined.append(fname)
                    _record_interception('攻击链文件隔离', fname, fp, threat_type=(_t or 'Threat'),
                                         action='quarantined', extra=verdict)
                    if notify:
                        _notify("Threat Quarantined", "Threat Quarantined {}".format(fname))
                except Exception as e:
                    _log("[回滚] 隔离失败 {}: {}".format(fp, e))
            else:
                # 纵深防御: 引擎判白后端点仍独立研判, 可疑则隔离而非删除
                _sec = None
                try:
                    _rt = getattr(g_window, '_realtime_monitor', None) if g_window else None
                    if _rt is not None:
                        _sec = _rt._endpoint_secondary_check(fp, fname, 0, 0)
                except Exception:
                    _sec = None
                if _sec:
                    try:
                        os.makedirs(QUARANTINE_DIR, exist_ok=True)
                        dest = os.path.join(QUARANTINE_DIR, fname + ".quarantine")
                        shutil.move(fp, dest)
                        quarantined.append(fname)
                        _record_interception('攻击链文件隔离(端点研判)', fname, fp, threat_type='Suspicious Behavior',
                                             confidence=int(_sec[1]), engine='Endpoint-Secondary',
                                             action='quarantined', extra=_sec[0])
                        if notify:
                            _notify("Threat Quarantined", "Threat Quarantined {}".format(fname))
                    except Exception as e:
                        _log("[回滚] 隔离失败 {}: {}".format(fp, e))
                else:
                    try:
                        os.remove(fp)
                        removed += 1
                    except Exception:
                        pass
        except Exception:
            pass
    if removed:
        _log("[回滚] 已删除 {} 个落盘文件".format(removed))
    return quarantined

def _mark_process_exited(pid):
    """进程退出:冻结其行为链节点(不再追加任何记录)。
    有子节点的节点保留供拓扑回看,无子节点的节点由清理逻辑回收。"""
    global _g_behavior_tree
    with _g_behavior_lock:
        node = _g_behavior_tree.get(pid)
        if node is not None and node.get('alive', True):
            node['alive'] = False
            node['exit_time'] = time.time()

def _record_behavior(pid, name, path, ppid, action, detail=''):
    """记录进程行为到拓扑链。
    - 仅当父进程节点仍存活且创建更早时才挂载子进程,避免PID复用把
      其他进程启动的子进程误挂到本链;
    - 已退出(冻结)的节点不再追加记录;PID被复用时旧链转为墓碑键保留;
    - 已退出且无子节点的进程节点定期回收。"""
    global _g_behavior_tree
    now = time.time()
    with _g_behavior_lock:
        node = _g_behavior_tree.get(pid)
        if node is not None and not node.get('alive', True):
            # PID被复用:旧链转墓碑键保留(供拓扑回看),新进程开新节点
            if not isinstance(pid, str):
                _g_behavior_tree[f"#{pid}#{int(node.get('exit_time', 0) or 0)}"] = node
            node = None
        if node is None:
            node = _g_behavior_tree[pid] = {
                'pid': pid,
                'name': name,
                'path': path,
                'ppid': ppid or 0,
                'children': [],
                'actions': [],
                'first_seen': now,
                'last_seen': now,
                'alive': True,
            }
        node['last_seen'] = now
        if name:
            node['name'] = name
        if path:
            node['path'] = path
        if len(node['actions']) < 200:
            node['actions'].append({
                'time': now,
                'time_str': time.strftime('%H:%M:%S'),
                'action': action,
                'detail': detail,
            })
        # 挂载到父进程(仅当父节点存活且创建时间早于本记录)
        if ppid:
            pnode = _g_behavior_tree.get(ppid)
            if (isinstance(pnode, dict) and pnode.get('alive', True)
                    and pnode['first_seen'] <= now + 1
                    and pid not in [c['pid'] for c in pnode['children']]):
                pnode['children'].append({
                    'pid': pid,
                    'name': name,
                    'path': path,
                })
        # 清理:已退出且无子节点的节点(含墓碑)超时回收
        cutoff = now - 600
        tomb_cutoff = now - 1800
        stale = [p for p, n in _g_behavior_tree.items()
                 if not n.get('alive', True) and n['last_seen'] < cutoff and not n['children']]
        stale += [p for p, n in _g_behavior_tree.items()
                  if isinstance(p, str) and n['last_seen'] < tomb_cutoff]
        for p in stale:
            _g_behavior_tree.pop(p, None)

def _exec_gui():
    _count = 0
    while _count < 20:
        try:
            fn = _gui_queue.get_nowait()
        except queue.Empty:
            break
        try:
            fn()
        except Exception:
            pass
        _count += 1

def _apply_rounded_mask(widget, radius=12):
    from PyQt6.QtGui import QRegion, QPainterPath
    from PyQt6.QtCore import QRectF
    path = QPainterPath()
    path.addRoundedRect(QRectF(0, 0, widget.width(), widget.height()), radius, radius)
    widget.setMask(QRegion(path.toFillPolygon().toPolygon()))

def _show_log_dialog(title, log_lines):
    from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
    dlg = QDialog()
    dlg.setWindowTitle(title)
    dlg.resize(800, 500)
    dlg.setWindowFlags(dlg.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
    layout = QVBoxLayout(dlg)
    te = QTextEdit()
    te.setReadOnly(True)
    te.setPlainText("\n".join(log_lines) if log_lines else "（暂无日志）")
    layout.addWidget(te)
    btn = QPushButton("关闭")
    btn.clicked.connect(dlg.accept)
    layout.addWidget(btn)
    dlg.exec()

_UI_DEBUG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Main', 'UIdebug.txt')
os.makedirs(os.path.dirname(_UI_DEBUG_FILE), exist_ok=True)

def _log(msg):
    global _g_log_lines
    _g_log_lines.append(time.strftime("[%H:%M:%S] ") + str(msg))
    if len(_g_log_lines) > MAX_LOG_LINES:
        _g_log_lines = _g_log_lines[-MAX_LOG_LINES:]
    try:
        with open(_UI_DEBUG_FILE, 'a', encoding='utf-8') as _df:
            _df.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + str(msg) + "\n")
    except:
        pass

def _scan_log(msg):
    global _g_scan_log_lines
    _g_scan_log_lines.append(time.strftime("[%H:%M:%S] ") + str(msg))
    if len(_g_scan_log_lines) > MAX_LOG_LINES:
        _g_scan_log_lines = _g_scan_log_lines[-MAX_LOG_LINES:]

# ===== 托盘通知(全局, 线程安全: 经 _gui_queue 回 GUI 线程) =====
_g_tray = None
SETTINGS_JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')

def _notify(title, body):
    """托盘气泡通知(任意线程可调)。Name 固定 SevenEndPointSecurity, 图标为 Icon/SevenEndpoint.ico。"""
    body = str(body)
    if _g_tray is not None:
        def _do():
            try:
                _g_tray.showMessage(title, body, app_icon(), 5000)
            except Exception:
                pass
        try:
            _gui_queue.put(_do)
        except Exception:
            pass
    _log("[通知] {}: {}".format(title, body))

def _load_settings_json():
    """启动时从 settings.json 恢复设置(仅接受 g_settings 已存在的键)。"""
    try:
        if os.path.exists(SETTINGS_JSON_PATH):
            with open(SETTINGS_JSON_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in g_settings:
                        g_settings[k] = v
                _log("[设置] 已从 settings.json 恢复 {} 项".format(len(data)))
    except Exception as e:
        _log("[设置] settings.json 读取失败: {}".format(e))

def _save_settings_json():
    """设置变更后写 settings.json。"""
    try:
        with open(SETTINGS_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(g_settings, f, indent=2, ensure_ascii=False)
    except Exception as e:
        _log("[设置] settings.json 写入失败: {}".format(e))


CONFIG = {
    "worker_threads": 20,
    "skip_dirs": [
        "$Recycle.Bin", "System Volume Information", "Windows\\WinSxS",
        "ProgramData\\Package Cache", "AppData\\Local\\Temp", "AppData\\Local\\Microsoft\\Windows\\INetCache",
        "PASW", "Pedefense"
    ],
    "whitelist_file": "whitelist.txt",
    "log_file": "engine.log",
    "cloud_api_base": "https://cloudapi.xiguastudio.top",
    "cloud_api_key": "scan_238e9dc876104329b9488495cfc4ea44",
    "cloud_scan_enabled": True,
    "cloud_timeout": 10,
}

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'Main', 'Main', 'config.json')
if not os.path.exists(SHARED_CONFIG_PATH):
    SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'Main', 'config.json')
if not os.path.exists(SHARED_CONFIG_PATH):
    SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
if os.path.exists(SHARED_CONFIG_PATH):
    try:
        with open(SHARED_CONFIG_PATH, 'r', encoding='utf-8') as _f:
            _shared_cfg = json.load(_f)
        _scanner_keys = set(CONFIG.keys())
        for _k in _scanner_keys:
            if _k in _shared_cfg:
                CONFIG[_k] = _shared_cfg[_k]
    except Exception:
        pass

CONFIG["whitelist_file"] = os.path.join(BASE_DIR, CONFIG["whitelist_file"])
CONFIG["log_file"] = os.path.join(BASE_DIR, CONFIG["log_file"])

# 外置引擎位置(SevenEngine\SevenEngine.py 及打包好的 SevenEngine.exe)
SEVENGINE_DIR = os.path.join(BASE_DIR, "SevenEngine")
if not os.path.isdir(SEVENGINE_DIR) and getattr(sys, 'frozen', False):
    SEVENGINE_DIR = os.path.join(os.path.dirname(sys.executable), "SevenEngine")
SEVENGINE_EXE = os.path.join(SEVENGINE_DIR, "SevenEngine.exe")

logger = logging.getLogger('Engine')

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger("Engine")

_engine_exe_missing_warned = False

def _engine_use_exe():
    """引擎调用方式: 设置为 exe 且 SevenEngine.exe 存在时返回 True。"""
    global _engine_exe_missing_warned
    try:
        _mode = g_settings.get("engine_mode", "exe")
    except Exception:
        _mode = "code"
    if _mode != "exe":
        return False
    if os.path.exists(SEVENGINE_EXE):
        return True
    if not _engine_exe_missing_warned:
        _engine_exe_missing_warned = True
        _log("[扫描引擎] 未找到 SevenEngine.exe, 回退引擎代码模式: {}".format(SEVENGINE_EXE))
    return False

def _worker_cmd():
    if _engine_use_exe():
        return [SEVENGINE_EXE, "--WORKER"]
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--worker']
    return [sys.executable, os.path.abspath(__file__), '--worker']

def _file_monitor_cmd():
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--file-monitor']
    return [sys.executable, os.path.abspath(__file__), '--file-monitor']

def _etw_worker_cmd():
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--etw-worker']
    return [sys.executable, os.path.abspath(__file__), '--etw-worker']

class Whitelist:
    def __init__(self):
        self.paths = set()
        self.lock = threading.Lock()
        self.load()
    def load(self):
        if os.path.exists(CONFIG["whitelist_file"]):
            with open(CONFIG["whitelist_file"], 'r', encoding='utf-8') as f:
                self.paths = {line.strip() for line in f if line.strip() and not line.strip().startswith('#')}
    def contains(self, path):
        with self.lock:
            if path in self.paths:
                return True
            norm = os.path.normpath(path)
            for wp in self.paths:
                if os.path.isdir(wp) or not os.path.splitext(wp)[1]:
                    wnorm = os.path.normpath(wp)
                    if norm == wnorm or norm.startswith(wnorm + os.sep):
                        return True
            return False
    def add_path(self, path):
        with self.lock:
            self.paths.add(path)
            self._save()
    def remove_path(self, path):
        with self.lock:
            if path in self.paths:
                self.paths.discard(path)
                self._save()
                return True
            return False
    def get_paths(self):
        with self.lock:
            return sorted(self.paths)
    def _save(self):
        try:
            os.makedirs(os.path.dirname(CONFIG["whitelist_file"]), exist_ok=True)
            with open(CONFIG["whitelist_file"], 'w', encoding='utf-8') as f:
                for p in sorted(self.paths):
                    f.write(p + '\n')
        except Exception as e:
            _log(f"[白名单] 保存失败: {e}")

THREAT_CATEGORIES = {
    'ransom': ('Trojan', 'Ransom'), 'crypt': ('Trojan', 'Crypt'), 'locky': ('Trojan', 'Locky'), 'wannacry': ('Trojan', 'WannaCry'),
    'cerber': ('Trojan', 'Cerber'), 'cryptolocker': ('Trojan', 'CryptoLocker'), 'bitlocker': ('Trojan', 'BitLocker'),
    'bank': ('Trojan', 'Banker'), 'dridex': ('Trojan', 'Dridex'), 'emotet': ('Trojan', 'Emotet'), 'zeus': ('Trojan', 'Zbot'),
    'banker': ('Trojan', 'Banker'), 'onlinebanking': ('Trojan', 'Banker'),
    'stealer': ('Trojan', 'Stealer'), 'password': ('Trojan', 'PSW'), 'grabber': ('Trojan', 'Grabber'), 'info': ('Trojan', 'Stealer'),
    'credential': ('Trojan', 'Stealer'), 'pwd': ('Trojan', 'PSW'), 'mail': ('Trojan', 'MailStealer'),
    'keylog': ('Trojan', 'KeyLogger'), 'keylogger': ('Trojan', 'KeyLogger'), 'hook': ('Trojan', 'Hook'),
    'spy': ('Trojan', 'Spy'), 'agent': ('Trojan', 'Agent'), 'rat': ('Backdoor', 'RAT'), 'remote': ('Backdoor', 'Remote'),
    'backdoor': ('Backdoor', 'Agent'), 'agenttesla': ('Trojan', 'AgentTesla'), 'njrat': ('Backdoor', 'Njrat'),
    'darkcomet': ('Backdoor', 'DarkComet'), 'poisonivy': ('Backdoor', 'Poison'), 'gh0st': ('Backdoor', 'Gh0st'),
    'dropper': ('Trojan', 'Dropper'), 'downloader': ('Trojan', 'Downloader'), 'install': ('Trojan', 'Installer'),
    'miner': ('Trojan', 'CoinMiner'), 'coin': ('Trojan', 'CoinMiner'), 'cryptocurrency': ('Trojan', 'CoinMiner'), 'xmr': ('Trojan', 'XMRMiner'),
    'worm': ('Worm', 'Generic'), 'bot': ('Backdoor', 'Bot'), 'conficker': ('Worm', 'Conficker'), 'morris': ('Worm', 'Morris'),
    'silverfox': ('Trojan', 'SilverFox'), 'sfox': ('Trojan', 'SilverFox'),
    'inject': ('Trojan', 'Injector'), 'reflect': ('Trojan', 'Injector'), 'process hollow': ('Trojan', 'Hollow'),
    'hijack': ('Trojan', 'Hijack'), 'browser': ('Trojan', 'BrowserHijack'), 'dns': ('Trojan', 'DNSHijack'),
    'adware': ('Adware', 'Generic'), 'trojan': ('Trojan', 'Generic'), 'malware': ('Trojan', 'Generic'),
    'packed': ('Trojan', 'Packed'), 'packer': ('Trojan', 'Packed'), 'obfuscated': ('Trojan', 'Obfuscated'),
    'upx': ('Trojan', 'UPX'), 'aspack': ('Trojan', 'ASPack'), 'themida': ('Trojan', 'Themida'),
    'vmprotect': ('Trojan', 'VMProtect'), 'enigma': ('Trojan', 'Enigma'),
    'rootkit': ('Rootkit', 'Generic'), 'bootkit': ('Bootkit', 'Generic'),
    'wiper': ('Trojan', 'Wiper'), 'destructive': ('Trojan', 'Wiper'),
    'exploit': ('Exploit', 'Generic'), 'shellcode': ('Exploit', 'Shellcode'),
    'loader': ('Trojan', 'Loader'), 'stager': ('Trojan', 'Stager'), 'launcher': ('Trojan', 'Launcher'),
    'infostealer': ('Trojan', 'Stealer'), 'exfiltrate': ('Trojan', 'Exfil'), 'clipboard': ('Trojan', 'ClipBanker'),
    'c2': ('Backdoor', 'C2'), 'beacon': ('Backdoor', 'Beacon'),
    'proxy': ('Trojan', 'Proxy'), 'socks': ('Trojan', 'Socks'),
    'ransomware': ('Trojan', 'Ransom'), 'cryptojacking': ('Trojan', 'CoinMiner'),
    'macro': ('Trojan', 'Macro'), 'office': ('Trojan', 'Macro'),
    'phishing': ('Trojan', 'Phish'), 'phish': ('Trojan', 'Phish'), 'fake': ('Trojan', 'Fake'),
    'scareware': ('Trojan', 'Scare'), 'rogue': ('Trojan', 'Rogue'), 'fakeav': ('Trojan', 'FakeAV'),
    'webshell': ('Backdoor', 'Webshell'), 'asp': ('Backdoor', 'Webshell'), 'jsp': ('Backdoor', 'Webshell'),
}

EXTENSION_THREATS = {
    '.scr': ('Trojan', 'Win32', 'SCR'), '.pif': ('Trojan', 'Win32', 'PIF'), '.com': ('Trojan', 'Win32', 'COM'),
    '.vbs': ('Trojan', 'VBS', 'Generic'), '.ps1': ('Trojan', 'Win32', 'PowerShell'),
    '.js': ('Trojan', 'JS', 'Generic'), '.jar': ('Trojan', 'Java', 'Generic'),
    '.wsf': ('Trojan', 'Script', 'WSF'), '.hta': ('Trojan', 'Script', 'HTA'),
    '.vbe': ('Trojan', 'VBS', 'Generic'), '.cpl': ('Trojan', 'Win32', 'CPL'),
    '.msi': ('Trojan', 'Win32', 'MSI'), '.chm': ('Trojan', 'Win32', 'CHM'),
    '.bat': ('Trojan', 'BAT', 'Generic'), '.cmd': ('Trojan', 'BAT', 'Generic'),
    '.sct': ('Trojan', 'Script', 'SCT'), '.wsc': ('Trojan', 'Script', 'WSC'),
}

_VARIANT_POOL = 'abcdefghijkmnpqrstuvwxyz0123456789'

def _gen_variant(seed_str):
    import hashlib
    h = hashlib.md5(seed_str.encode('utf-8')).hexdigest()
    v = ''
    for i in range(0, 6, 2):
        idx = int(h[i:i+2], 16) % len(_VARIANT_POOL)
        v += _VARIANT_POOL[idx]
    return v[:3]

def _get_platform(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ('.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.com', '.msi', '.chm', '.ps1'):
        return 'Win32'
    if ext in ('.vbs', '.vbe'):
        return 'VBS'
    if ext in ('.js',):
        return 'JS'
    if ext in ('.bat', '.cmd'):
        return 'BAT'
    if ext in ('.py', '.pyw'):
        return 'Python'
    if ext in ('.jar',):
        return 'Java'
    if ext in ('.hta', '.wsf', '.sct', '.wsc'):
        return 'Script'
    return 'Generic'

def classify_threat(filepath, rule_name=None, pe_apis=None, heuristic=False):
    basename = os.path.basename(filepath).lower()
    lower_path = filepath.lower()
    ext = os.path.splitext(filepath)[1].lower()
    platform = _get_platform(filepath)
    is_heur = heuristic
    threat_type = 'Trojan'
    family = 'Generic'
    if rule_name:
        rule_lower = rule_name.lower()
        for kw, (ttype, fam) in THREAT_CATEGORIES.items():
            if kw in rule_lower and len(kw) >= 4:
                threat_type = ttype
                family = fam
                break
        if family == 'Generic':
            if 'silverfox' in rule_lower:
                threat_type, family = 'Trojan', 'SilverFox'
            elif any(x in rule_lower for x in ['ransom','crypt','locky','encrypt']):
                threat_type, family = 'Trojan', 'Ransom'
            elif any(x in rule_lower for x in ['keylog','hook']):
                threat_type, family = 'Trojan', 'KeyLogger'
            elif any(x in rule_lower for x in ['bank','dridex','zeus','emotet']):
                threat_type, family = 'Trojan', 'Banker'
            elif any(x in rule_lower for x in ['pack','upx','aspack','themida','vmprotect']):
                threat_type, family = 'Trojan', 'Packed'
            elif any(x in rule_lower for x in ['miner','coin','xmr','stratum']):
                threat_type, family = 'Trojan', 'CoinMiner'
    if pe_apis and isinstance(pe_apis, list):
        if any(api in ['CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','NtCreateThreadEx','QueueUserAPC','NtUnmapViewOfSection','SetThreadContext','RtlCreateUserThread'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'Injector'
            is_heur = True
        elif any(api in ['SetWindowsHookEx','GetAsyncKeyState','GetClipboardData'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'KeyLogger'
            is_heur = True
        elif any(api in ['CredEnumerate','CredRead','LsaOpenPolicy','LsaRetrievePrivateData','SamOpenUser','CryptUnprotectData'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'Stealer'
            is_heur = True
    packer_kw = ['upx','aspack','themida','vmprotect','enigma','molebox','armadillo','telock','pespin','mpress','obsidium','nspack']
    for pk in packer_kw:
        if pk in basename or pk in lower_path:
            threat_type, family = 'Trojan', pk.upper()
            is_heur = True
            break
    if family == 'Generic':
        for kw, (ttype, fam) in THREAT_CATEGORIES.items():
            if len(kw) >= 5 and kw in basename:
                threat_type, family = ttype, fam
                break
            if len(kw) >= 6 and kw in lower_path:
                threat_type, family = ttype, fam
                break
    if ext in EXTENSION_THREATS and family == 'Generic':
        et_type, et_platform, et_family = EXTENSION_THREATS[ext]
        threat_type = et_type
        if platform == 'Generic':
            platform = et_platform
        family = et_family
        is_heur = True
    if ext in ('.ps1',) and family == 'Generic':
        family = 'PowerShell'
        platform = 'Win32'
        is_heur = True
    if ext in ('.bat', '.cmd') and family == 'Generic':
        family = 'Generic'
        is_heur = True
    if platform == 'Win32' and family in ('PowerShell',):
        pass
    variant = _gen_variant(filepath + family)
    prefix = 'HEUR:' if is_heur else ''
    return f'{prefix}{threat_type}.{platform}.{family}.{variant}'

def is_system_path(file_path):
    norm = os.path.normpath(file_path).lower().replace('\\', '/')
    if norm.find('/windows/') <= 4 and '/windows/' in norm:
        return True
    if norm.find('/$windows.~bt/') <= 4 and '/$windows.~bt/' in norm:
        return True
    if norm.find('/$windows.~ws/') <= 4 and '/$windows.~ws/' in norm:
        return True
    if norm.find('/$winreagent/') <= 4 and '/$winreagent/' in norm:
        return True
    if norm.find('/program files/') <= 4 and '/program files/' in norm:
        return True
    if norm.find('/program files (x86)/') <= 4 and '/program files (x86)/' in norm:
        return True
    if norm.find('/programdata/') <= 4 and '/programdata/' in norm:
        return True
    if norm.find('/esd/') <= 4 and '/esd/' in norm:
        return True
    if norm.find('/drvpath/') <= 4 and '/drvpath/' in norm:
        return True
    if norm.find('/drivers/') <= 4 and '/drivers/' in norm:
        return True
    if norm.find('/driverstore/') <= 4 and '/driverstore/' in norm:
        return True
    if norm.find('/windowsapps/') <= 4 and '/windowsapps/' in norm:
        return True
    if norm.find('/$windows.~q/') <= 4 and '/$windows.~q/' in norm:
        return True
    if norm.find('/windows.old/') <= 4 and '/windows.old/' in norm:
        return True
    try:
        _self_dir = os.path.dirname(os.path.abspath(__file__)).lower().replace('\\', '/')
        if norm.startswith(_self_dir + '/') or norm == _self_dir:
            return True
    except:
        pass
    if '/pasw/' in norm:
        return True
    return False

_SYS_PROC_NAMES = frozenset({
    'explorer.exe', 'svchost.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
    'winlogon.exe', 'lsass.exe', 'services.exe', 'dwm.exe', 'conhost.exe',
    'runtimebroker.exe', 'taskhostw.exe', 'sihost.exe', 'fontdrvhost.exe',
    'ctfmon.exe', 'audiodg.exe', 'spoolsv.exe', 'searchhost.exe',
    'startmenuexperiencehost.exe', 'textinputhost.exe',
    'shellexperiencehost.exe', 'applicationframehost.exe',
    'securityhealthsystray.exe', 'securityhealthservice.exe',
    'securityhealthhost.exe', 'msmpeng.exe', 'nissrv.exe', 'sppsvc.exe',
    'wudfhost.exe', 'dashost.exe', 'system', 'wininit.exe', 'userinit.exe',
    'fontdrvhost.exe', 'dllhost.exe', 'taskhost.exe',
})

def verify_name_path(name_lower, path):
    norm = os.path.normpath(path).lower().replace('\\', '/')
    if name_lower in _SYS_PROC_NAMES:
        return '/windows/' in norm
    trusted = ['/program files/', '/program files (x86)/', '/windows/', '/programdata/']
    if any(norm.find(p) <= 4 for p in trusted):
        return True
    if name_lower in {'python.exe', 'pythonw.exe', 'python3.exe', 'python314.exe'}:
        py_markers = ['/python3', '/programs/python', '/appdata/local/programs/python']
        if any(m in norm for m in py_markers):
            return True
    return False

_SILVERFOX_FAKE_VENDORS = frozenset({
    '360.cn', '360安全', '火绒', '向日葵', '上海贝锐', '北京火绒',
    '海南有趣', '腾讯', '奇虎', '金山', '百度', '阿里',
    '卡巴斯基', '迈克菲', '诺顿', '赛门铁克', '微点', '瑞星',
    '江民', '安天', '微步', '猎豹', '2345', '管家', 'netsec',
})

_pe_parse_cache = {}
_pe_parse_lock = threading.Lock()
_pe_cache_max = 600

def _parse_pe_all(filepath):
    try:
        st = os.stat(filepath)
        cache_key = (st.st_mtime_ns, st.st_size, filepath)
    except:
        cache_key = (0, 0, filepath)
    with _pe_parse_lock:
        if cache_key in _pe_parse_cache:
            _pe_parse_cache[cache_key] = _pe_parse_cache.pop(cache_key)
            return _pe_parse_cache[cache_key]
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        info = {'apis': [], 'signer': None, 'sections': [], 'has_clr': False, 'import_count': 0, 'version_info': {}, 'is_dll': False, 'exports': [], 'export_count': 0, 'overlay_size': 0}
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            ])
            info['is_dll'] = pe.is_dll()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            info['apis'].append(imp.name.decode('utf-8', 'ignore'))
                info['import_count'] = len(info['apis'])
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY:
                security = pe.DIRECTORY_ENTRY_SECURITY
                cert_offset = security.struct.VirtualAddress
                cert_size = security.struct.Size
                if 8 <= cert_size <= 0x200000:
                    try:
                        with open(filepath, 'rb') as f:
                            f.seek(cert_offset)
                            cert_data = f.read(min(cert_size, 0x200000))
                        if len(cert_data) >= 8:
                            cert_body = cert_data[8:]
                            try:
                                cert_text = cert_body.decode('utf-16-le', errors='ignore')
                            except:
                                cert_text = cert_body.decode('latin-1', errors='ignore')
                            for p in ['Microsoft Corporation','Google','Apple','Mozilla','Adobe','Oracle','Intel','NVIDIA','AMD','VMware','Dell','HP','Inno Setup','Nullsoft','Bitdefender','Kaspersky','ESET','Avast','AVG','Avira','McAfee','Symantec','Norton','Malwarebytes','Trend Micro','Sophos','Fortinet','JetBrains','GitHub','Atlassian','Slack','Zoom','Valve','Epic Games','Electronic Arts','Ubisoft','Blizzard','Autodesk','Docker','Red Hat','Canonical','Tencent','Baidu','Qihoo','Kingsoft','Huawei','Xiaomi','Python','OBS Project','VideoLAN','7-Zip','WinRAR','TeamViewer','AnyDesk','RealVNC','Splashtop','Open Source Developer','Certum','DigiCert','Sectigo','GlobalSign','COMODO','Entrust','IdenTrust',"Let's Encrypt",'Cloudflare','Amazon']:
                                if p.lower() in cert_text.lower():
                                    info['signer'] = p
                                    break
                    except:
                        pass
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.Size:
                info['has_clr'] = True
            for sec in pe.sections:
                try:
                    sn = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                    se = sec.get_entropy()
                    sr = sec.SizeOfRawData
                    sc = sec.Characteristics
                    info['sections'].append((sn, se, sr, sc))
                except:
                    pass
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
                    ffi = pe.VS_FIXEDFILEINFO[0]
                    info['version_info']['FileVersion'] = f"{ffi.FileVersionMS >> 16}.{ffi.FileVersionMS & 0xFFFF}.{ffi.FileVersionLS >> 16}.{ffi.FileVersionLS & 0xFFFF}"
                if hasattr(pe, 'FileInfo'):
                    for finfo in pe.FileInfo:
                        for entry in finfo:
                            if hasattr(entry, 'StringTable'):
                                for st in entry.StringTable:
                                    for k, v in st.entries.items():
                                        try:
                                            key = k.decode('utf-8', 'ignore')
                                            val = v.decode('utf-8', 'ignore').strip()
                                            if key == 'FileVersion' and 'FileVersion' in info['version_info'] and info['version_info']['FileVersion']:
                                                continue
                                            if val:
                                                info['version_info'][key] = val
                                        except:
                                            pass
            except:
                pass
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT and pe.DIRECTORY_ENTRY_EXPORT.symbols:
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name:
                        try:
                            info['exports'].append(sym.name.decode('utf-8', 'ignore'))
                        except:
                            pass
                info['export_count'] = len(info['exports'])
            try:
                _overlay_offset = pe.get_overlay_data_start_offset()
                if _overlay_offset:
                    info['overlay_size'] = os.path.getsize(filepath) - _overlay_offset
            except:
                pass
        except:
            pass
        pe.close()
        with _pe_parse_lock:
            if len(_pe_parse_cache) >= _pe_cache_max:
                keep = len(_pe_parse_cache) // 2
                keys = list(_pe_parse_cache.keys())
                for k in keys[:len(_pe_parse_cache) - keep]:
                    _pe_parse_cache.pop(k, None)
            _pe_parse_cache[cache_key] = info
        return info
    except:
        empty = {'apis': [], 'signer': None, 'sections': [], 'has_clr': False, 'import_count': 0, 'version_info': {}, 'is_dll': False, 'exports': [], 'export_count': 0, 'overlay_size': 0}
        with _pe_parse_lock:
            _pe_parse_cache[cache_key] = empty
        return empty

def _extract_signer(filepath):
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            pe.close(); return None
        security = pe.DIRECTORY_ENTRY_SECURITY
        cert_offset = security.struct.VirtualAddress
        cert_size = security.struct.Size
        pe.close()
        if cert_size < 8 or cert_size > 0x200000:
            return None
        with open(filepath, 'rb') as f:
            f.seek(cert_offset)
            cert_data = f.read(min(cert_size, 0x200000))
        if len(cert_data) < 8:
            return None
        cert_body = cert_data[8:]
        try: text = cert_body.decode('utf-16-le', errors='ignore')
        except: text = cert_body.decode('latin-1', errors='ignore')
        for p in ['Microsoft Corporation','Google','Apple','Mozilla','Adobe','Oracle','Intel','NVIDIA','AMD','VMware','Dell','HP','Inno Setup','Nullsoft','Bitdefender','Kaspersky','ESET','Avast','AVG','Avira','McAfee','Symantec','Norton','Malwarebytes','Trend Micro','Sophos','Fortinet','JetBrains','GitHub','Atlassian','Slack','Zoom','Valve','Epic Games','Electronic Arts','Ubisoft','Blizzard','Autodesk','Docker','Red Hat','Canonical','Tencent','Baidu','Qihoo','Kingsoft','Huawei','Xiaomi','Python','OBS Project','VideoLAN','7-Zip','WinRAR','TeamViewer','AnyDesk','RealVNC','Splashtop','Open Source Developer','Certum','DigiCert','Sectigo','GlobalSign','COMODO','Entrust','IdenTrust',"Let's Encrypt",'Cloudflare','Amazon']:
            if p.lower() in text.lower():
                return p
        return None
    except:
        return None

def _extract_msi_signer(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(min(os.path.getsize(filepath), 80*1024*1024))
        pos = -1
        for i in range(len(data) - 5):
            if data[i:i+3] == b'\x00\x02\x01' and data[i+3] in (0x30,):
                pos = i
                break
        if pos == -1:
            return None
        for start in range(pos, min(pos + 200, len(data) - 4)):
            if data[start:start+2] == b'\x30\x82':
                try:
                    asn1_len = ((data[start+2] << 8) | data[start+3]) + 4
                    if asn1_len > 100 and asn1_len < 0x100000 and start + asn1_len <= len(data):
                        cert_blob = data[start:start+asn1_len]
                        signer = _parse_pkcs7_signer(cert_blob)
                        if signer:
                            return signer
                except:
                    continue
        return None
    except:
        return None

def _analyze_msi_embedded(filepath):
    try:
        import struct as _struct
        fsize = os.path.getsize(filepath)
        read_size = min(fsize, 80*1024*1024)
        with open(filepath, 'rb') as f:
            data = f.read(read_size)
        pe_offsets = []
        idx = 0
        while True:
            pos = data.find(b'MZ', idx)
            if pos == -1:
                break
            try:
                if pos + 64 < len(data):
                    pe_off = _struct.unpack_from('<I', data, pos + 60)[0]
                    if pe_off < 1024 and pos + pe_off + 4 <= len(data):
                        if data[pos + pe_off:pos + pe_off + 4] == b'PE\x00\x00':
                            pe_offsets.append(pos)
            except:
                pass
            idx = pos + 2
            if len(pe_offsets) > 50:
                break
        if not pe_offsets:
            return None
        import pefile
        all_apis = set()
        pe_count = 0
        dll_pe_count = 0
        obfuscated_pe_count = 0
        packed_section_count = 0
        high_entropy_count = 0
        has_exports = False
        zero_import_pe_count = 0
        for i, off in enumerate(pe_offsets):
            end = pe_offsets[i+1] if i+1 < len(pe_offsets) else len(data)
            pe_data = data[off:end]
            if len(pe_data) < 512:
                continue
            try:
                pe = pefile.PE(data=pe_data, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                ])
                pe_count += 1
                if pe.is_dll():
                    dll_pe_count += 1
                _pe_imp_count = 0
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                all_apis.add(imp.name.decode('utf-8', 'ignore'))
                                _pe_imp_count += 1
                if _pe_imp_count == 0:
                    zero_import_pe_count += 1
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT and pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    has_exports = True
                _pe_packed = False
                _pe_obf = False
                for sec in pe.sections:
                    sn = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                    try:
                        clean = sn.encode('ascii').isascii() and all(c.isalnum() or c == '.' or c == '_' for c in sn)
                    except:
                        clean = False
                    if not clean and (sec.SizeOfRawData > 512 or sec.Misc_VirtualSize > 10000):
                        _pe_obf = True
                    if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 50000:
                        _pe_packed = True
                    if sec.SizeOfRawData > 50000:
                        try:
                            entropy = sec.get_entropy()
                            if entropy > 7.5:
                                high_entropy_count += 1
                        except:
                            pass
                if _pe_obf:
                    obfuscated_pe_count += 1
                if _pe_packed:
                    packed_section_count += 1
                pe.close()
            except:
                continue
        api_lower = set(a.lower() for a in all_apis)
        inj = api_lower & _MSI_API_INJECTION
        net = api_lower & _MSI_API_NETWORK
        pers = api_lower & _MSI_API_PERSISTENCE
        anti = api_lower & _MSI_API_ANTIDEBUG
        res = api_lower & _MSI_API_RESOURCE
        file_apis = api_lower & _MSI_API_FILE
        crypto_apis = api_lower & _MSI_API_CRYPTO
        proc_apis = api_lower & _MSI_API_PROCESS
        return {
            'pe_count': pe_count, 'dll_pe_count': dll_pe_count,
            'obfuscated_pe_count': obfuscated_pe_count, 'packed_section_count': packed_section_count,
            'high_entropy_count': high_entropy_count, 'zero_import_pe_count': zero_import_pe_count,
            'has_exports': has_exports, 'total_apis': len(all_apis),
            'injection_apis': sorted(inj), 'network_apis': sorted(net),
            'persistence_apis': sorted(pers), 'antidebug_apis': sorted(anti),
            'resource_apis': sorted(res), 'file_apis': sorted(file_apis),
            'crypto_apis': sorted(crypto_apis), 'process_apis': sorted(proc_apis),
            'all_apis': sorted(all_apis),
        }
    except Exception:
        return None

_SYS_DLL_NAMES = {
    'uxtheme.dll','version.dll','winhttp.dll','wininet.dll','ws2_32.dll',
    'cryptbase.dll','cryptsp.dll','dbghelp.dll','iphlpapi.dll','msvcr100.dll',
    'msvcp140.dll','vcruntime140.dll','nlaapi.dll','napinsp.dll','pnrpnsp.dll',
    'wshbth.dll','winrnr.dll','nrm.dll','mimefilt.dll','urlmon.dll',
    'mscoree.dll','msvcr110.dll','msvcr120.dll','d3d11.dll','dxgi.dll',
    'dwmapi.dll','userenv.dll','secur32.dll','netprofm.dll','npmproxy.dll',
    'wtsapi32.dll','powrprof.dll','psapi.dll','samlib.dll','sensapi.dll',
    'winmm.dll','mswsock.dll','shlwapi.dll','setupapi.dll',
    'cfgmgr32.dll','clusapi.dll','user32.dll','kernel32.dll','ntdll.dll',
    'advapi32.dll','gdi32.dll','ole32.dll','comctl32.dll','comdlg32.dll',
    'shell32.dll','rpcrt4.dll','oleaut32.dll','wintrust.dll','crypt32.dll',
}

class _StudyProxy:
    """SevenEngine 学习引擎的只读代理(ToolPage 兼容接口)。"""
    def __init__(self, se_study):
        self._s = se_study
    def get_record_count(self):
        return len(getattr(self._s, 'records', {}) or {})
    def get_known_threats(self):
        out = []
        for md5, rec in (getattr(self._s, 'records', {}) or {}).items():
            rtype = rec.get('threat_type', '')
            if rtype not in ('CLEAN', '') or rec.get('type', '') == 'malicious':
                out.append({
                    'md5': md5,
                    'filepath': rec.get('filepath', ''),
                    'threat_type': rtype or rec.get('type', 'malicious'),
                    'confidence': rec.get('confidence', 0),
                    'count': rec.get('count', 0),
                    'last_seen': rec.get('last_seen', ''),
                })
        return out

def _exe_scan_file(filepath):
    """通过打包好的 SevenEngine.exe(CLI 模式)扫描单个文件, 返回 (res, conf, vt)。"""
    try:
        _env = dict(os.environ)
        _env['PYTHONIOENCODING'] = 'utf-8'
        proc = subprocess.run(
            [SEVENGINE_EXE, filepath],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', errors='replace',
            timeout=120, env=_env, cwd=BASE_DIR,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        res, conf, vt = "CLEAN", 0, ""
        for _ln in (proc.stdout or '').splitlines():
            _ln = _ln.strip()
            if _ln.startswith('Result:'):
                res = _ln[len('Result:'):].strip()
            elif _ln.startswith('Confidence:'):
                try:
                    conf = int(_ln[len('Confidence:'):].strip() or 0)
                except ValueError:
                    conf = 0
            elif _ln.startswith('Info:'):
                vt = _ln[len('Info:'):].strip()
        if conf <= 0 and res.startswith('MALICIOUS'):
            try:
                conf = int(res.rsplit('|', 1)[1])
            except Exception:
                conf = 60
        return res, conf, vt
    except Exception as e:
        _log("[扫描引擎] exe 调用失败: {}".format(e))
        return "ERROR", 0, ""

class Scanner:
    """扫描门面:实际引擎为 SevenEngine\\SevenEngine.py(SevenEngine 目录)。
    旧内置引擎(StudyEngine/Yara/AdvancedSignature/Onnx/Archive/Cloud)已移除,
    扫描结果格式保持 MALICIOUS|类型|来源|置信度 不变。
    支持两种调用方式(设置中切换):
      code - import SevenEngine 代码模式(默认)
      exe  - 调用打包好的 SevenEngine.exe(worker 常驻协议 / CLI 单文件)"""
    def __init__(self):
        self.whitelist = Whitelist()
        self._se = None
        self._se_lock = threading.Lock()
        class _CloudCompat:
            api_key = CONFIG.get("cloud_api_key", "")
        self.cloud = _CloudCompat()
        if _engine_use_exe():
            _log(">>> [扫描引擎] 调用方式: 打包引擎 SevenEngine.exe")
        else:
            try:
                self._ensure()
            except Exception as _e:
                _log("[扫描引擎] SevenEngine 初始化失败: {}".format(_e))
    def _use_exe(self):
        if not _engine_use_exe():
            return False
        return True
    def _ensure(self):
        if self._se is None:
            with self._se_lock:
                if self._se is None:
                    if SEVENGINE_DIR not in sys.path:
                        sys.path.insert(0, SEVENGINE_DIR)
                    import SevenEngine as _se_mod
                    self._se = _se_mod.Scanner()
                    _lgbm_ok = getattr(getattr(self._se, 'lgbm', None), 'available', False)
                    _log(">>> [扫描引擎] SevenEngine 已加载 (LightGBM: {})".format('正常' if _lgbm_ok else '未激活'))
        return self._se
    def scan_file(self, filepath, depth=0):
        if self._use_exe():
            return _exe_scan_file(filepath)
        return self._ensure().scan_file(filepath, depth)
    def scan_file_quick(self, filepath):
        if self._use_exe():
            return _exe_scan_file(filepath)
        return self._ensure().scan_file_quick(filepath)
    @property
    def study(self):
        return _StudyProxy(self._ensure().study)

QUARANTINE_DIR = os.path.join(os.environ.get('APPDATA', 'C:\\Users\\Public\\AppData'), 'PASW', 'LockFile')
WHITE_LIST_FILE = os.path.join(os.environ.get('APPDATA', 'C:\\Users\\Public\\AppData'), 'PASW', 'White', 'Write.txt')
CONFIG_JSON = os.path.join(BASE_DIR, 'Main', 'Main', 'config.json')
LOG_FILE = os.path.join(BASE_DIR, 'Main', 'log.txt')
QUIT_SIGNAL = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'PASW', 'quit.signal')
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(WHITE_LIST_FILE), exist_ok=True)

SERVER_API_BASE = "http://127.0.0.1:15555"
API_TIMEOUT = 5

THEME = {
    "bg": "#f5f5f5",
    "sidebar_bg": "#ffffff",
    "card_bg": "#ffffff",
    "accent": "#0078d4",
    "accent_hover": "#106ebe",
    "text": "#1a1a1a",
    "text_secondary": "#555555",
    "border": "#e8e8e8",
    "green": "#107c10",
    "red": "#d32f2f",
}

class ApiClient:

    @staticmethod
    def get(endpoint, timeout=API_TIMEOUT):
        import requests
        try:
            resp = requests.get(f"{SERVER_API_BASE}{endpoint}", timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
        except requests.ConnectionError:
            pass
        except Exception:
            pass
        return None

    @staticmethod
    def post(endpoint, data=None, timeout=API_TIMEOUT):
        import requests
        try:
            headers = {"Content-Type": "application/json"}
            resp = requests.post(f"{SERVER_API_BASE}{endpoint}",
                                 json=data or {}, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
        except requests.ConnectionError:
            pass
        except Exception:
            pass
        return None

    @classmethod
    def get_status(cls):
        return cls.get("/api/status")

    @classmethod
    def get_config(cls):
        return cls.get("/api/config")

    @classmethod
    def update_config(cls, key, value):
        return cls.post("/api/config/update", {"key": key, "value": value})

    @classmethod
    def get_logs(cls, count=200):
        return cls.get("/api/logs")

    @classmethod
    def get_quarantine_list(cls):
        return cls.get("/api/quarantine/list")

    @classmethod
    def get_quarantine_info(cls, name):
        return cls.get(f"/api/quarantine/info/{name}")

    @classmethod
    def get_quarantine_count(cls):
        return cls.get("/api/quarantine/count")

    @classmethod
    def quarantine_restore(cls, name, dest_dir=None):
        data = {"name": name}
        if dest_dir:
            data["dest_dir"] = dest_dir
        return cls.post("/api/quarantine/restore", data)

    @classmethod
    def quarantine_delete(cls, name):
        return cls.post("/api/quarantine/delete", {"name": name})

    @classmethod
    def quarantine_relock(cls):
        return cls.post("/api/quarantine/relock")

g_scanner = None
g_status = {"ok": False, "msg": "初始化中"}
g_settings = {
    "high_sensitivity": False, "auto_handle": False,
    "enhanced_mode": False, "realtime_protect": True,
    "privacy_enabled": False, "autostart_enabled": False,
    "process_protect": True, "process_pause": True,
    "file_protect": True, "system_protect": True,
    "file_modify_monitor": True,
    "driver_protect": True, "network_protect": True,
    "engine_mode": "exe",
    "enhanced_scan": False, "extended_engine": False,
    "cloud_service": True, "ext_filter": True,
    "boot_start": True, "menu_scan": False,
    "cloud_scan": True,
    "edr_protect": True,            # 行为EDR评分(进程落地文件+偏僻位置加分,≥70终止进程链)
    "dll_sideload_protect": True,   # DLL侧载/内存注入拦截(系统进程加载非系统未签名DLL)
    "etw_telemetry": True,          # 遥测拦截(端点规则):默认启动,全维度事件采集+按Rules端点规则拦截
}

# ============================ 轻量行为EDR配置 ============================
# EDR豁免进程名(不再对其打分):系统关键 + 办公浏览器通讯 + 开发工具
EDR_EXEMPT_NAMES = {
    # 系统关键进程
    'smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe','svchost.exe',
    'winlogon.exe','dwm.exe','sihost.exe','taskhostw.exe','runtimebroker.exe',
    'fontdrvhost.exe','explorer.exe','conhost.exe','ctfmon.exe','audiodg.exe',
    'spoolsv.exe','searchhost.exe','startmenuexperiencehost.exe','textinputhost.exe',
    'shellexperiencehost.exe','applicationframehost.exe','securityhealthsystray.exe',
    'securityhealthservice.exe','securityhealthhost.exe','msmpeng.exe','nissrv.exe',
    'sppsvc.exe','wudfhost.exe','dashost.exe','wininit.exe','system',
    # 办公/浏览器/通讯
    'chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','vivaldi.exe',
    'wps.exe','et.exe','wpp.exe','winword.exe','excel.exe','powerpnt.exe','outlook.exe',
    'onenote.exe','wpscloudsvr.exe','foxitphantom.exe','foxitreader.exe','acrord32.exe',
    'soffice.bin','soffice.exe','notion.exe','obsidian.exe','evernote.exe',
    'qq.exe','tim.exe','wechat.exe','weixin.exe','wechatappex.exe','dingtalk.exe','feishu.exe','lark.exe',
    'telegram.exe','discord.exe','slack.exe','wemeet.exe','tencentmeeting.exe','zoom.exe',
    'teams.exe','skype.exe','youdaodict.exe',
    'wechatapp.exe','wechatbrowser.exe','weixin.exe','tencentmeeting.exe',
    'qqlive.exe','qqplayer.exe','qqmusic.exe','qqbrowser.exe',
    # 开发工具(频繁编译/调用,易误报)
    'python.exe','pythonw.exe','python3.exe','python3w.exe','git.exe','git-bash.exe',
    'bash.exe','node.exe','npm.exe','code.exe','code-server.exe','cursor.exe',
    'devenv.exe','idea64.exe','pycharm64.exe','webstorm64.exe','rider64.exe',
    'goland64.exe','clion64.exe','sublime_text.exe','notepad++.exe','windowsterminal.exe',
    'openconsole.exe','cargo.exe','rustc.exe','rust-analyzer.exe','go.exe','java.exe',
    'mvnd.exe','maven.exe','gradle.exe','msbuild.exe','dotnet.exe',
    # 系统工具/安全
    'taskmgr.exe','regedit.exe','mmc.exe','explorer.exe','everything.exe','listary.exe',
    # 自身
    'pedefense.exe','pedefenseserver.exe','pasw.exe','peui.pyw','pescanner.pyw',
    'sevenendpointsecurity.exe','sevenendpoint.exe','sevenend.exe','sevenendpointui.pyw',
}

# 需额外监控注入情况的关键/常用进程(银狐惯于注入explorer/浏览器/Office)
# 这些进程即使名字在豁免集,也要检查其加载的非常规DLL
EDR_SYS_PROC_FOR_INJECTION = {
    'explorer.exe','svchost.exe','csrss.exe','winlogon.exe','dwm.exe','runtimebroker.exe',
    'chrome.exe','msedge.exe','firefox.exe','winword.exe','excel.exe','powerpnt.exe',
    'outlook.exe','wps.exe','wechat.exe','qq.exe','dingtalk.exe','soffice.bin',
}

# 偏僻/可疑目录标记(落地于此加分)
EDR_SUSPICIOUS_DIR_TOKENS = (
    '\\temp\\','\\appdata\\roaming\\','\\appdata\\local\\temp\\','\\downloads\\',
    '\\programdata\\','\\users\\public\\','\\public\\','\\$recycle.bin\\',
    '\\startup\\','\\windows\\start menu\\programs\\startup\\',
    '\\application data\\','\\local settings\\',
)

# 系统DLL伪装名(同名DLL落在非system32即为可疑侧载)
EDR_SYSTEM_DLL_NAMES = {
    'version.dll','msvcp140.dll','vcruntime140.dll','vcruntime140_1.dll',
    'ucrtbase.dll','winhttp.dll','wininet.dll','urlmon.dll','cryptbase.dll',
    'nvinit.dll','nvgi.dll','atiadlxx.dll','amdocl64.dll','igdumd64.dll',
    'd3d9.dll','d3d11.dll','d3d12.dll','dxgi.dll','dwmapi.dll','powrprof.dll',
    'propsys.dll','mscoree.dll','clr.dll','ole32.dll','oleaut32.dll',
    'ntdll.dll','kernel32.dll','kernelbase.dll','user32.dll','gdi32.dll',
    'advapi32.dll','ws2_32.dll','iphlpapi.dll','dnsapi.dll','winmm.dll',
}

# 可疑API链(PE导入) -> (特征名, 所需API集合, 加分)
EDR_API_CHAINS = [
    ('进程注入', {'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread'}, 30),
    ('键盘记录', {'SetWindowsHookExW','GetAsyncKeyState'} | {'SetWindowsHookExA','GetAsyncKeyState'}, 25),
    ('凭证转储', {'MiniDumpWriteDump'} | {'CryptDuplicateKey'}, 30),
    ('屏幕监控', {'GetDC','BitBlt','CreateCompatibleBitmap'}, 15),
    ('自启动', {'RegSetValueExW','RegCreateKeyExW'} & {'Software\\Microsoft\\Windows\\CurrentVersion\\Run'}, 20),
    ('网络回连', {'WSAStartup','connect','socket'} | {'InternetOpenA','InternetConnectA'}, 15),
    ('反调试', {'IsDebuggerPresent','CheckRemoteDebuggerPresent'}, 10),
    ('进程操作', {'OpenProcess','TerminateProcess','CreateProcessW'}, 15),
]

# 单因素加分上限(保证纯单因素到不了70终止阈值,降低误报)
EDR_MAX_SINGLE_FACTOR = 35

# 可信签名厂商token(命中即实时快速放行,商业EDR标准)
_TRUSTED_SIGNER_TOKENS = frozenset({
    'microsoft', 'google', 'apple', 'intel', 'nvidia', 'amd', 'oracle', 'adobe',
    'tencent', 'alibaba', 'baidu', 'qihoo', 'kingsoft', 'wps', 'huawei', 'xiaomi',
    'mozilla', 'opera', 'valve', 'epic games', 'github', 'gitlab', 'slack', 'zoom',
    'dropbox', 'atlassian', 'discord', 'lenovo', 'realtek', 'samsung', 'vmware',
    'citrix', 'kaspersky', 'eset', 'avast', 'avg', 'avira', 'bitdefender',
    'mcafee', 'symantec', 'norton', 'malwarebytes', 'sophos', 'trend micro',
    'jetbrains', 'docker', 'red hat', 'canonical', 'python software foundation',
    'dell', 'hp', 'cisco', 'ibm',
})

REG_KEY_DIR = r"Directory\\shell\\SevenEndPointScan"
REG_KEY_DIR_BG = r"Directory\\Background\\shell\\SevenEndPointScan"
REG_KEY_STAR = r"*\\shell\\SevenEndPointScan"
REG_KEY_ALLF = r"AllFilesystemObjects\\shell\\SevenEndPointScan"
# 旧版右键菜单键(升级时清理)
_LEGACY_REG_KEYS = [r"Directory\\shell\\PASWScan", r"Directory\\Background\\shell\\PASWScan",
                    r"*\\shell\\PASWScan", r"AllFilesystemObjects\\shell\\PASWScan"]

def install_context_menu():
    try:
        import winreg
        exe_path = os.path.abspath(sys.argv[0])
        py_exe = sys.executable
        if exe_path.lower().endswith('.pyw'):
            cmd = f'"{py_exe}" "{exe_path}" --scan "%1"'
        else:
            cmd = f'"{exe_path}" --scan "%1"'
        keys = [REG_KEY_DIR, REG_KEY_DIR_BG, REG_KEY_STAR, REG_KEY_ALLF]
        for k in keys:
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, k, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, "使用 SevenEndPointSecurity 扫描")
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(key)
            cmd_key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, k + "\\command", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(cmd_key, None, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(cmd_key)
        _log("[右键菜单] 已注册右键扫描")
        return True
    except Exception as e:
        _log(f"[右键菜单] 注册失败: {e}")
        return False

def remove_context_menu():
    try:
        import winreg
        keys = [REG_KEY_DIR + "\\command", REG_KEY_DIR_BG + "\\command",
                REG_KEY_STAR + "\\command", REG_KEY_ALLF + "\\command",
                REG_KEY_DIR, REG_KEY_DIR_BG, REG_KEY_STAR, REG_KEY_ALLF]
        for lk in _LEGACY_REG_KEYS:
            keys += [lk + "\\command", lk]
        for k in keys:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, k)
            except:
                pass
        _log("[右键菜单] 已注销右键扫描")
        return True
    except Exception as e:
        _log(f"[右键菜单] 注销失败: {e}")
        return False


WHITE_THEME = {
    "bg_window": QColor(247, 248, 250), "bg_nav": QColor(252, 252, 253),
    "bg_panel": QColor(255, 255, 255), "bg_hover": QColor(0, 120, 215, 12),
    "text_primary": QColor(32, 32, 35), "text_secondary": QColor(130, 130, 140),
    "border": QColor(232, 234, 238), "accent": QColor(0, 120, 215),
    "accent_light": QColor(0, 120, 215, 20), "accent_shadow": QColor(0, 120, 215, 40),
    "danger": QColor(232, 72, 72), "success": QColor(0, 168, 89),
    "shadow": QColor(0, 0, 0, 8),
}

_current_theme = "white"

def get_theme():
    return WHITE_THEME

def set_theme(name):
    global _current_theme
    _current_theme = "white"

SVG_ICONS = {
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L4 5v6c0 5.5 3.4 10.6 8 12 4.6-1.4 8-6.5 8-12V5l-8-3z"/></svg>',
    "shield_check": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L4 5v6c0 5.5 3.4 10.6 8 12 4.6-1.4 8-6.5 8-12V5l-8-3z"/><polyline points="8.5 12 11 14.5 15.5 9.5"/></svg>',
    "shield_cross": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L4 5v6c0 5.5 3.4 10.6 8 12 4.6-1.4 8-6.5 8-12V5l-8-3z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>',
    "home": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5L12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/></svg>',
    "scan": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="3" y1="12" x2="21" y2="12"/></svg>',
    "settings": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    "tool": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.1 2.1-2.7-.3-.3-2.7z"/></svg>',
    "info": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><circle cx="12" cy="8" r="0.5" fill="currentColor"/></svg>',
    "minimize": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="5" y1="12.5" x2="19" y2="12.5"/></svg>',
    "maximize": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="1"/></svg>',
    "restore": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="3" width="14" height="14" rx="1"/><path d="M3 7v12a2 2 0 0 0 2 2h12"/></svg>',
    "close": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>',
    "chevron_right": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
    "chevron_down": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
    "play": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 4 20 12 6 20 6 4" fill="currentColor"/></svg>',
    "stop": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor"/></svg>',
    "folder": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    "trash": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    "lock": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    "list": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
    "terminal": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
    "server": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><line x1="7" y1="7.5" x2="7.01" y2="7.5"/><line x1="7" y1="16.5" x2="7.01" y2="16.5"/></svg>',
    "cpu": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/></svg>',
    "book": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><line x1="8" y1="6" x2="16" y2="6"/><line x1="8" y1="10" x2="16" y2="10"/><line x1="8" y1="14" x2="12" y2="14"/></svg>',
    "shield_alert": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L4 5v6c0 5.5 3.4 10.6 8 12 4.6-1.4 8-6.5 8-12V5l-8-3z"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16.5" r="0.6" fill="currentColor"/></svg>',
    "file": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    "bell": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
    "network": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="12" y1="11" x2="6" y2="17"/><line x1="12" y1="11" x2="18" y2="17"/></svg>',
    "refresh": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
}

def _get_dpr():
    screen = QApplication.primaryScreen()
    return screen.devicePixelRatio() if screen else 1.0

_APP_ICON_PATH = os.path.join(BASE_DIR, 'Icon', 'SevenEndpoint.ico')
_APP_ICON_PNG = os.path.join(BASE_DIR, 'Icon', 'SevenEndpoint.png')
_app_icon_cache = None

def app_icon():
    """应用图标:优先 Icon 目录下的 .ico(多分辨率),其次 .png。"""
    global _app_icon_cache
    if _app_icon_cache is not None:
        return _app_icon_cache
    if os.path.exists(_APP_ICON_PATH):
        _app_icon_cache = QIcon(_APP_ICON_PATH)
    elif os.path.exists(_APP_ICON_PNG):
        _app_icon_cache = QIcon(_APP_ICON_PNG)
    else:
        _app_icon_cache = QIcon()
    return _app_icon_cache

def _toast_place(dlg):
    """拦截类弹窗统一停靠屏幕右下角(任务栏上方)。"""
    try:
        screen = QApplication.primaryScreen().availableGeometry()
        dlg.move(max(8, screen.right() - dlg.width() - 28),
                 max(8, screen.bottom() - dlg.height() - 28))
    except Exception:
        pass

def _toast_slide_up(dlg, container):
    """从右下角下方48px处上滑进入(Windows toast 风格)。"""
    try:
        end_pos = container.pos()
        start_pos = QPoint(end_pos.x(), end_pos.y() + 48)
        container.move(start_pos)
        anim = QPropertyAnimation(container, b"pos", dlg)
        anim.setDuration(280)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.setStartValue(start_pos)
        anim.setEndValue(end_pos)
        anim.start()
        dlg._toast_pos_anim = anim  # 防GC
    except Exception:
        pass

def render_svg(icon_key, color, size=22):
    svg_str = SVG_ICONS.get(icon_key, "")
    if not svg_str:
        return QPixmap(size, size)
    c = f'rgb({color.red()},{color.green()},{color.blue()})'
    svg_str = svg_str.replace('currentColor', c)
    renderer = QSvgRenderer(QByteArray(svg_str.encode('utf-8')))
    if not renderer.isValid():
        return QPixmap(size, size)
    dpr = _get_dpr()
    phys = int(size * dpr)
    pix = QPixmap(phys, phys)
    pix.setDevicePixelRatio(dpr)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    target = QRectF(0, 0, size, size)
    renderer.render(painter, target)
    painter.end()
    return pix

def render_svg_byte(svg_str, color, size=22):
    c = f'rgb({color.red()},{color.green()},{color.blue()})'
    svg_str = svg_str.replace('currentColor', c)
    renderer = QSvgRenderer(QByteArray(svg_str.encode('utf-8')))
    if not renderer.isValid():
        return QPixmap(size, size)
    dpr = _get_dpr()
    phys = int(size * dpr)
    pix = QPixmap(phys, phys)
    pix.setDevicePixelRatio(dpr)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    target = QRectF(0, 0, size, size)
    renderer.render(painter, target)
    painter.end()
    return pix


class SvgButton(QPushButton):
    def __init__(self, icon_key="", size=32, icon_size=18, parent=None):
        super().__init__(parent)
        self.icon_key = icon_key
        self._size = size
        self._icon_size = icon_size
        self.setFixedSize(size, size)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hover = False
        self._active = False
        self._color = None
        self._custom_svg = None
        self._hover_val = 0.0
        self._hover_anim = QPropertyAnimation(self, b"hover_val")
        self._hover_anim.setDuration(150)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_hover_val(self):
        return self._hover_val

    def set_hover_val(self, v):
        self._hover_val = v
        self.update()

    hover_val = pyqtProperty(float, get_hover_val, set_hover_val)

    def setIconKey(self, key):
        self.icon_key = key
        self.update()

    def setCustomSvg(self, svg_str):
        self._custom_svg = svg_str
        self.update()

    def setActive(self, active):
        self._active = active
        self.update()

    def update_theme(self):
        self.update()

    def enterEvent(self, event):
        self._hover = True
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_val)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()
        self.update()

    def leaveEvent(self, event):
        self._hover = False
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_val)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = get_theme()
        w = self.width()
        h = self.height()
        r = QRectF(0, 0, w, h)
        radius = min(8.0, min(w, h) / 4.0)
        path = QPainterPath()
        path.addRoundedRect(r, radius, radius)
        if self._active:
            bg = QColor(th["accent"])
            bg.setAlpha(int(20 + self._hover_val * 15))
            painter.fillPath(path, bg)
        elif self._hover_val > 0:
            bg = QColor(th["accent"])
            bg.setAlpha(int(self._hover_val * 15))
            painter.fillPath(path, bg)
        if self._active:
            painter.setPen(QPen(th["accent"], 0))
        if self._custom_svg:
            icon_color = th["accent"] if self._active else th["text_primary"]
            pix = render_svg_byte(self._custom_svg, icon_color, self._icon_size)
        else:
            if self._active:
                icon_color = th["accent"]
            else:
                base = th["text_primary"]
                icon_color = QColor(
                    base.red() + int((th["accent"].red() - base.red()) * self._hover_val),
                    base.green() + int((th["accent"].green() - base.green()) * self._hover_val),
                    base.blue() + int((th["accent"].blue() - base.blue()) * self._hover_val),
                )
            pix = render_svg(self.icon_key, icon_color, self._icon_size)
        dpr = pix.devicePixelRatio()
        pix_w = pix.width() / dpr if dpr > 0 else pix.width()
        pix_h = pix.height() / dpr if dpr > 0 else pix.height()
        target = QRectF((w - pix_w) / 2.0, (h - pix_h) / 2.0, pix_w, pix_h)
        painter.drawPixmap(target.toRect(), pix)


class ToggleSwitch(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, checked=True, parent=None):
        super().__init__(parent)
        self.setFixedSize(44, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._checked = checked
        self._hover = False
        self._anim_progress = 1.0 if checked else 0.0
        self._anim = QPropertyAnimation(self, b"anim_progress")
        self._anim.setDuration(200)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def setChecked(self, checked):
        if self._checked != checked:
            self._checked = checked
            end = 1.0 if checked else 0.0
            if self._anim.state() == QPropertyAnimation.State.Running:
                self._anim.stop()
            self._anim.setStartValue(1.0 - end)
            self._anim.setEndValue(end)
            self._anim.start()
            self.toggled.emit(checked)
            self.update()

    def isChecked(self):
        return self._checked

    def get_anim_progress(self):
        return getattr(self, '_anim_progress', 0.0)

    def set_anim_progress(self, val):
        self._anim_progress = val
        self.update()

    anim_progress = pyqtProperty(float, get_anim_progress, set_anim_progress)

    def enterEvent(self, event):
        self._hover = True
        self.update()

    def leaveEvent(self, event):
        self._hover = False
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._checked = not self._checked
            end = 1.0 if self._checked else 0.0
            if self._anim.state() == QPropertyAnimation.State.Running:
                self._anim.stop()
            self._anim.setStartValue(1.0 - end)
            self._anim.setEndValue(end)
            self._anim.start()
            self.toggled.emit(self._checked)
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = get_theme()
        w, h = 44, 24
        r = h / 2
        track_rect = QRectF(0, 0, w, h)
        track_path = QPainterPath()
        track_path.addRoundedRect(track_rect, r, r)
        if self._anim_progress > 0.01:
            base = th["accent"]
            bg = QColor(base)
            bg.setAlpha(int(255 * self._anim_progress))
            painter.fillPath(track_path, bg)
        if self._anim_progress < 0.99:
            border_c = th["border"]
            border_c = QColor(border_c)
            border_c.setAlpha(int(255 * (1 - self._anim_progress)))
            painter.setPen(QPen(border_c, 1.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(track_path)
        knob_size = h - 6
        knob_x = 3 + (w - knob_size - 6) * self._anim_progress
        knob_y = 3
        knob_rect = QRectF(knob_x, knob_y, knob_size, knob_size)
        painter.setPen(QPen(QColor(0, 0, 0, 15), 1))
        painter.setBrush(QBrush(QColor(255, 255, 255)))
        painter.drawEllipse(knob_rect)


class CardWidget(QFrame):
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hover = False
        self._clickable = False
        self._hover_val = 0.0
        self._hover_anim = QPropertyAnimation(self, b"hover_val")
        self._hover_anim.setDuration(180)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._elevation = 0

    def get_hover_val(self):
        return self._hover_val

    def set_hover_val(self, v):
        self._hover_val = v
        self.update()

    hover_val = pyqtProperty(float, get_hover_val, set_hover_val)

    def setClickable(self, clickable):
        self._clickable = clickable
        if clickable:
            self.setCursor(Qt.CursorShape.PointingHandCursor)

    def setElevation(self, level):
        self._elevation = level
        self.update()

    def enterEvent(self, event):
        if self._clickable:
            self._hover = True
            self._hover_anim.stop()
            self._hover_anim.setStartValue(self._hover_val)
            self._hover_anim.setEndValue(1.0)
            self._hover_anim.start()

    def leaveEvent(self, event):
        self._hover = False
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_val)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._clickable:
            self.clicked.emit()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = get_theme()
        r = self.rect().adjusted(0, 0, -1, -1)
        radius = 10.0
        path = QPainterPath()
        path.addRoundedRect(QRectF(r), radius, radius)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(th["bg_panel"])
        painter.drawPath(path)
        if self._hover_val > 0 and self._clickable:
            border = QColor(th["accent"])
            border.setAlpha(int(80 * self._hover_val))
            painter.setPen(QPen(border, 1.5))
        else:
            painter.setPen(QPen(th["border"], 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)


class ListWidgetItem(CardWidget):

    def __init__(self, title="", desc="", parent=None, show_chevron=False, show_toggle=False, toggle_checked=True, icon_key=""):
        super().__init__(parent)
        self.setClickable(True)
        self.setFixedHeight(68)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(14)
        self._icon_key = icon_key
        if icon_key:
            icon_lbl = QLabel()
            icon_lbl.setFixedSize(36, 36)
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            th = get_theme()
            icon_lbl.setPixmap(render_svg(icon_key, th["accent"], 22))
            self._icon_label = icon_lbl
            layout.addWidget(icon_lbl)
        else:
            self._icon_label = None
        info_widget = QWidget()
        info_widget.setStyleSheet("background: transparent;")
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(3)
        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.DemiBold))
        info_layout.addWidget(self.title_label)
        if desc:
            self.desc_label = QLabel(desc)
            self.desc_label.setFont(QFont("Microsoft YaHei", 8))
            info_layout.addWidget(self.desc_label)
        else:
            self.desc_label = None
        layout.addWidget(info_widget, 1)
        self.toggle = None
        if show_toggle:
            self.toggle = ToggleSwitch(toggle_checked)
            layout.addWidget(self.toggle)
        if show_chevron:
            chevron = SvgButton("chevron_right", 28, 18)
            chevron.setCursor(Qt.CursorShape.PointingHandCursor)
            layout.addWidget(chevron)
        self._action_widget = None

    def setActionWidget(self, widget):
        if self._action_widget:
            self.layout().removeWidget(self._action_widget)
        self._action_widget = widget
        self.layout().insertWidget(self.layout().count() - 1, widget)

    def update_theme(self):
        th = get_theme()
        self.title_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        if self.desc_label:
            self.desc_label.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        if self._icon_label:
            self._icon_label.setPixmap(render_svg(self._icon_key, th["accent"], 22))
        self.update()
        for child in self.findChildren(SvgButton):
            child.update_theme()
        if self.toggle:
            self.toggle.update()


class LogWidget(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        th = get_theme()
        br_c = f"rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()})"
        hs_c = f"rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()})"
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 10px;
                padding: 12px;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: {br_c};
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: {br_c};
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

    def update_theme(self):
        th = get_theme()
        br_c = f"rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()})"
        hs_c = f"rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()})"
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 10px;
                padding: 12px;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: {br_c};
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: {br_c};
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)


class ScanProgressBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0
        self._display_value = 0.0
        self.setFixedHeight(8)
        self._anim = QPropertyAnimation(self, b"disp_val")
        self._anim.setDuration(400)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_disp_val(self):
        return self._display_value

    def set_disp_val(self, v):
        self._display_value = v
        self.update()

    disp_val = pyqtProperty(float, get_disp_val, set_disp_val)

    def setValue(self, val):
        self._value = max(0, min(100, val))
        if self._anim.state() == QPropertyAnimation.State.Running:
            self._anim.stop()
        self._anim.setStartValue(self._display_value)
        self._anim.setEndValue(float(self._value))
        self._anim.start()

    def value(self):
        return self._value

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = get_theme()
        r = self.rect().adjusted(0, 0, -1, -1)
        radius = float(self.height()) / 2.0
        bg_path = QPainterPath()
        bg_path.addRoundedRect(QRectF(r), radius, radius)
        painter.fillPath(bg_path, th["border"])
        if self._display_value > 0.5:
            w = int(r.width() * self._display_value / 100.0)
            if w > 4:
                fill_rect = QRectF(0, 0, w, r.height())
                fill_path = QPainterPath()
                fill_path.addRoundedRect(fill_rect, radius, radius)
                grad = QLinearGradient(0, 0, w, 0)
                grad.setColorAt(0, th["accent"])
                grad.setColorAt(1, QColor(
                    min(255, th["accent"].red() + 30),
                    min(255, th["accent"].green() + 30),
                    min(255, th["accent"].blue() + 30),
                ))
                painter.fillPath(fill_path, QBrush(grad))


class NavButton(SvgButton):
    def __init__(self, icon_key="", target="", parent=None):
        super().__init__(icon_key, 44, 22, parent)
        self.target = target
        self.setFixedSize(44, 44)


class Sidebar(QWidget):
    navClicked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(64)
        self._buttons = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 16, 0, 16)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        nav_items = [
            ("home", "home", "仪表盘"),
            ("scan", "scan", "扫描"),
            ("notify", "bell", "通知中心"),
            ("behavior", "network", "行为链"),
            ("settings", "settings", "设置"),
            ("tool", "tool", "工具"),
        ]
        for target, icon, hint in nav_items:
            btn = NavButton(icon, target)
            btn.setToolTip(hint)
            btn.clicked.connect(lambda checked, t=target: self._on_nav(t))
            self._buttons[target] = btn
            layout.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch()
        about_btn = NavButton("info", "about")
        about_btn.setToolTip("关于")
        about_btn.clicked.connect(lambda: self._on_nav("about"))
        self._buttons["about"] = about_btn
        layout.addWidget(about_btn, 0, Qt.AlignmentFlag.AlignHCenter)

    def _on_nav(self, target):
        self.setActive(target)
        self.navClicked.emit(target)

    def setActive(self, target):
        for key, btn in self._buttons.items():
            btn.setActive(key == target)

    def update_theme(self):
        th = get_theme()
        self.setStyleSheet(f"background-color: rgb({th['bg_nav'].red()},{th['bg_nav'].green()},{th['bg_nav'].blue()}); border-right: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});")
        for btn in self._buttons.values():
            btn.update_theme()


class TitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(40)
        self._drag_pos = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 8, 0)
        layout.setSpacing(4)
        self.title_label = QLabel("SevenEndPointSecurity")
        self.title_label.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.DemiBold))
        app_icon_lbl = QLabel()
        app_icon_lbl.setPixmap(app_icon().pixmap(20, 20))
        app_icon_lbl.setFixedSize(20, 20)
        app_icon_lbl.setStyleSheet("background: transparent;")
        layout.addWidget(app_icon_lbl)
        layout.addSpacing(6)
        layout.addWidget(self.title_label)
        layout.addStretch()
        self.min_btn = SvgButton("minimize", 36, 16)
        self.min_btn.setToolTip("最小化")
        self.min_btn.setFixedSize(36, 28)
        self.close_btn = SvgButton("close", 36, 16)
        self.close_btn.setToolTip("关闭")
        self.close_btn.setFixedSize(36, 28)
        layout.addWidget(self.min_btn)
        layout.addWidget(self.close_btn)

    def update_theme(self):
        th = get_theme()
        self.setStyleSheet(f"background-color: rgb({th['bg_nav'].red()},{th['bg_nav'].green()},{th['bg_nav'].blue()}); border-bottom: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});")
        self.title_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        for btn in [self.min_btn, self.close_btn]:
            btn.update_theme()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()
            self.window()._drag_offset = event.globalPosition().toPoint() - self.window().pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self.window()._drag_offset)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None
        event.accept()


class ScrollPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(36, 24, 36, 24)
        self.content_layout.setSpacing(14)
        self.scroll.setWidget(self.content)
        layout.addWidget(self.scroll)

    def addWidget(self, widget):
        self.content_layout.addWidget(widget)

    def addStretch(self):
        self.content_layout.addStretch()

    def update_theme(self):
        th = get_theme()
        self.setStyleSheet(f"background-color: rgb({th['bg_window'].red()},{th['bg_window'].green()},{th['bg_window'].blue()});")
        self.content.setStyleSheet("background: transparent;")
        br_c = f"rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()})"
        hs_c = f"rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()})"
        self.scroll.setStyleSheet(f"""
            QScrollArea {{
                background-color: transparent;
                border: none;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: {br_c};
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: {br_c};
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {hs_c};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)


class HomePage(ScrollPage):

    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        status_card = CardWidget()
        status_card.setFixedHeight(220)
        sl = QVBoxLayout(status_card)
        sl.setContentsMargins(32, 28, 32, 28)
        sl.setSpacing(10)
        status_header = QHBoxLayout()
        status_header.setSpacing(12)
        self.shield_lbl = QLabel()
        self.shield_lbl.setPixmap(render_svg("shield_check", th["success"], 48))
        self.shield_lbl.setFixedSize(56, 56)
        self.shield_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.shield_lbl.setStyleSheet("background: transparent;")
        status_header.addWidget(self.shield_lbl)
        status_col = QVBoxLayout()
        status_col.setSpacing(2)
        status_title = QLabel("防护状态")
        status_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        status_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        status_col.addWidget(status_title)
        status_header.addLayout(status_col)
        status_header.addStretch()
        sl.addLayout(status_header)
        self.status_label = QLabel("初始化中...")
        self.status_label.setFont(QFont("Microsoft YaHei", 20, QFont.Weight.Bold))
        self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        sl.addWidget(self.status_label)
        self.status_sub = QLabel("引擎正在加载中，请稍候")
        self.status_sub.setFont(QFont("Microsoft YaHei", 10))
        self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        sl.addWidget(self.status_sub)
        self.addWidget(status_card)
        engine_card = CardWidget()
        engine_card.setFixedHeight(110)
        el = QVBoxLayout(engine_card)
        el.setContentsMargins(28, 20, 28, 20)
        el.setSpacing(10)
        engine_title = QLabel("引擎状态")
        engine_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        engine_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        el.addWidget(engine_title)
        self.engine_label = QLabel("扫描引擎正在初始化...")
        self.engine_label.setFont(QFont("Microsoft YaHei", 11))
        self.engine_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        el.addWidget(self.engine_label)
        self.engine_progress = ScanProgressBar()
        self.engine_progress.setValue(0)
        el.addWidget(self.engine_progress)
        self.addWidget(engine_card)
        log_card = CardWidget()
        ll = QVBoxLayout(log_card)
        ll.setContentsMargins(28, 20, 28, 20)
        ll.setSpacing(8)
        log_title = QLabel("运行日志")
        log_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        log_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        ll.addWidget(log_title)
        self.log_widget = LogWidget()
        self.log_widget.setFixedHeight(180)
        ll.addWidget(self.log_widget)
        self.addWidget(log_card)
        self.addStretch()
        self._log_timer = QTimer(self)
        self._log_timer.timeout.connect(self._refresh_log)
        self._log_timer.start(100)

    def _refresh_log(self):
        if _g_log_lines:
            text = "\n".join(_g_log_lines[-500:])
            if self.log_widget.toPlainText() != text:
                self.log_widget.setPlainText(text)
                sb = self.log_widget.verticalScrollBar()
                sb.setValue(sb.maximum())

    def update_status(self, ok, server_state=""):
        th = get_theme()
        if ok:
            if server_state == "noserver":
                self.status_label.setText("防护未能生效")
                self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()});")
                self.status_sub.setText("主动防御服务未能启动")
                self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
                self.shield_lbl.setPixmap(render_svg("shield_cross", th["danger"], 48))
            elif server_state == "server":
                self.status_label.setText("您的设备已受保护")
                self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['success'].red()},{th['success'].green()},{th['success'].blue()});")
                self.status_sub.setText("PASW 实时防护正在运行 (服务器已连接)")
                self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
                self.shield_lbl.setPixmap(render_svg("shield_check", th["success"], 48))
            else:
                self.status_label.setText("您的设备已受保护")
                self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['success'].red()},{th['success'].green()},{th['success'].blue()});")
                self.status_sub.setText("PASW 实时防护正在运行")
                self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
                self.shield_lbl.setPixmap(render_svg("shield_check", th["success"], 48))
        elif server_state == "init":
            self.status_label.setText("正在初始化...")
            self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});")
            self.status_sub.setText("扫描引擎正在加载中，请稍候")
            self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
            self.shield_lbl.setPixmap(render_svg("shield", th["accent"], 48))
        else:
            self.status_label.setText("存在风险")
            self.status_label.setStyleSheet(f"background: transparent; color: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()});")
            self.status_sub.setText("实时防护未开启，请检查设置")
            self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
            self.shield_lbl.setPixmap(render_svg("shield_cross", th["danger"], 48))

    def update_engine(self, text):
        self.engine_label.setText(text)

    def update_engine_progress(self, val):
        self.engine_progress.setValue(int(val * 100))

    def update_theme(self):
        super().update_theme()
        th = get_theme()
        self.status_sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        self.engine_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        self.log_widget.update_theme()


class ScanPage(ScrollPage):
    scanRequested = pyqtSignal(str)
    stopRequested = pyqtSignal()
    customScanRequested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        scan_card = CardWidget()
        sl = QVBoxLayout(scan_card)
        sl.setContentsMargins(24, 18, 24, 18)
        sl.setSpacing(14)
        scan_title = QLabel("扫描引擎")
        scan_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        scan_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        sl.addWidget(scan_title)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.btn_quick = self._make_btn("play", "快速扫描", th)
        self.btn_quick.clicked.connect(lambda: self.scanRequested.emit("quick"))
        btn_row.addWidget(self.btn_quick)
        self.btn_full = self._make_btn("scan", "全盘扫描", th)
        self.btn_full.clicked.connect(lambda: self.scanRequested.emit("full"))
        btn_row.addWidget(self.btn_full)
        self.btn_custom = self._make_btn("folder", "自定义扫描", th)
        self.btn_custom.clicked.connect(self.customScanRequested)
        btn_row.addWidget(self.btn_custom)
        self.btn_stop = self._make_btn("stop", "停止", th, danger=True)
        self.btn_stop.clicked.connect(self.stopRequested.emit)
        self.btn_stop.setVisible(False)
        btn_row.addWidget(self.btn_stop)
        btn_row.addStretch()
        sl.addLayout(btn_row)
        self.addWidget(scan_card)
        progress_card = CardWidget()
        pl = QVBoxLayout(progress_card)
        pl.setContentsMargins(24, 20, 24, 20)
        pl.setSpacing(10)
        prog_title = QLabel("扫描进度")
        prog_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        prog_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        pl.addWidget(prog_title)
        timer_row = QHBoxLayout()
        timer_row.setSpacing(20)
        self.timer_label = QLabel("00:00")
        self.timer_label.setFont(QFont("Microsoft YaHei", 22, QFont.Weight.Bold))
        self.timer_label.setStyleSheet(f"background: transparent; color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});")
        self.timer_label.setFixedWidth(100)
        self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        timer_row.addWidget(self.timer_label)
        prog_col = QVBoxLayout()
        prog_col.setSpacing(6)
        self.progress_bar = ScanProgressBar()
        prog_col.addWidget(self.progress_bar)
        self.progress_label = QLabel("就绪")
        self.progress_label.setFont(QFont("Microsoft YaHei", 9))
        self.progress_label.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        prog_col.addWidget(self.progress_label)
        self.current_file_label = QLabel("")
        self.current_file_label.setFont(QFont("Microsoft YaHei", 8))
        self.current_file_label.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        self.current_file_label.setWordWrap(False)
        prog_col.addWidget(self.current_file_label)
        self.stat_label = QLabel("已扫描: 0  |  威胁: 0")
        self.stat_label.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        self.stat_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        prog_col.addWidget(self.stat_label)
        timer_row.addLayout(prog_col, 1)
        pl.addLayout(timer_row)
        self.addWidget(progress_card)
        result_card = CardWidget()
        rl = QVBoxLayout(result_card)
        rl.setContentsMargins(24, 20, 24, 20)
        rl.setSpacing(10)
        result_header = QHBoxLayout()
        result_title = QLabel("扫描结果")
        result_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        result_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        result_header.addWidget(result_title)
        result_header.addStretch()
        self.select_all_chk = QCheckBox("全选")
        self.select_all_chk.setFont(QFont("Microsoft YaHei", 9))
        self.select_all_chk.setStyleSheet("background: transparent;")
        self.select_all_chk.toggled.connect(self._on_select_all)
        result_header.addWidget(self.select_all_chk)
        self.batch_quarantine_btn = QPushButton("批量隔离")
        self.batch_quarantine_btn.setFixedSize(80, 28)
        self.batch_quarantine_btn.setFont(QFont("Microsoft YaHei", 8))
        self.batch_quarantine_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.batch_quarantine_btn.setVisible(False)
        result_header.addWidget(self.batch_quarantine_btn)
        self.batch_delete_btn = QPushButton("批量删除")
        self.batch_delete_btn.setFixedSize(80, 28)
        self.batch_delete_btn.setFont(QFont("Microsoft YaHei", 8))
        self.batch_delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.batch_delete_btn.setVisible(False)
        result_header.addWidget(self.batch_delete_btn)
        self.batch_ignore_btn = QPushButton("批量忽略")
        self.batch_ignore_btn.setFixedSize(80, 28)
        self.batch_ignore_btn.setFont(QFont("Microsoft YaHei", 8))
        self.batch_ignore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.batch_ignore_btn.setVisible(False)
        result_header.addWidget(self.batch_ignore_btn)
        self.view_result_btn = QPushButton("查看报告")
        self.view_result_btn.setFixedSize(90, 30)
        self.view_result_btn.setFont(QFont("Microsoft YaHei", 9))
        self.view_result_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        result_header.addWidget(self.view_result_btn)
        rl.addLayout(result_header)
        self.virus_list_widget = QWidget()
        self.virus_list_layout = QVBoxLayout(self.virus_list_widget)
        self.virus_list_layout.setContentsMargins(0, 0, 0, 0)
        self.virus_list_layout.setSpacing(4)
        self._placeholder = QLabel("选择扫描模式后开始扫描")
        self._placeholder.setFont(QFont("Microsoft YaHei", 9))
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        self.virus_list_layout.addWidget(self._placeholder)
        rl.addWidget(self.virus_list_widget)
        self.addWidget(result_card)
        self.addStretch()
        self._scanning = False
        self._stop_requested = False
        self._scanned_count = 0
        self._threat_count = 0
        self._threat_list = []
        self._scan_start_time = 0
        self._scan_elapsed = 0
        self._timer_id = None

    def _on_select_all(self, checked):
        for i in range(self.virus_list_layout.count()):
            w = self.virus_list_layout.itemAt(i).widget()
            if w and hasattr(w, '_checkbox') and w._checkbox:
                w._checkbox.blockSignals(True)
                w._checkbox.setChecked(checked)
                w._checkbox.blockSignals(False)
                w._selected = checked
        self._update_batch_buttons()

    def _update_batch_buttons(self):
        has_selected = False
        for i in range(self.virus_list_layout.count()):
            w = self.virus_list_layout.itemAt(i).widget()
            if w and hasattr(w, '_selected') and w._selected:
                has_selected = True
                break
        self.batch_quarantine_btn.setVisible(has_selected)
        self.batch_delete_btn.setVisible(has_selected)
        self.batch_ignore_btn.setVisible(has_selected)

    def _make_btn(self, icon_key, text, th, danger=False):
        btn = QPushButton()
        btn.setFixedSize(110, 36)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_layout = QHBoxLayout(btn)
        btn_layout.setContentsMargins(12, 0, 12, 0)
        btn_layout.setSpacing(8)
        lbl_icon = QLabel()
        c = th["danger"] if danger else th["accent"]
        lbl_icon.setPixmap(render_svg(icon_key, c, 16))
        lbl_icon.setFixedSize(18, 18)
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_layout.addWidget(lbl_icon)
        lbl_text = QLabel(text)
        lbl_text.setFont(QFont("Microsoft YaHei", 9))
        lbl_text.setStyleSheet(f"background: transparent; color: rgb({c.red()},{c.green()},{c.blue()});")
        btn_layout.addWidget(lbl_text)
        btn_layout.addStretch()
        return btn

    def start_timer(self):
        self._scan_elapsed = 0
        if self._timer_id is None:
            self._timer_id = self.startTimer(1000)
        self._update_timer_display()

    def stop_timer(self):
        if self._timer_id is not None:
            self.killTimer(self._timer_id)
            self._timer_id = None

    def timerEvent(self, event):
        if self._scanning:
            self._scan_elapsed = int(time.time() - self._scan_start_time)
            self._update_timer_display()

    def _update_timer_display(self):
        elapsed = self._scan_elapsed if self._scanning else 0
        mm = elapsed // 60
        ss = elapsed % 60
        self.timer_label.setText(f"{mm:02d}:{ss:02d}")

    def _set_scanning_done(self, threat_count):
        self._scanning = False
        self.stop_timer()
        self.btn_stop.setVisible(False)
        self.progress_bar.setValue(100)
        self.progress_label.setText(f"扫描完成，发现 {threat_count} 个威胁")
        self.current_file_label.setText("")

    def update_theme(self):
        super().update_theme()
        th = get_theme()
        self.progress_bar.update()


class SettingsPage(ScrollPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        settings_list = [
            ("high_sensitivity", "高灵敏模式", "降低检测阈值，提高检出率", "scan"),
            ("auto_handle", "自动处理", "自动隔离检测到的威胁", "shield"),
            ("enhanced_mode", "增强防护", "启用更多检测引擎", "cpu"),
            ("realtime_protect", "实时防护", "实时监控文件系统（强制开启）", "lock"),
            ("process_protect", "进程防护", "监控并拦截恶意程序启动", "cpu"),
            ("file_protect", "文件防护", "监控文件创建、删除、重命名操作", "folder"),
            ("file_modify_monitor", "修改监控", "监控文件修改操作（关闭可减少误报）", "folder"),
            ("cloud_scan", "云端扫描", "启用云端哈希查询与AI推理检测", "server"),
            ("menu_scan", "右键菜单扫描", "在文件右键菜单中加入扫描选项", "list"),
            ("etw_telemetry", "遥测拦截（端点规则）", "ETW实时遥测按Rules端点规则拦截（测试版，可能不稳定且有误报）", "network"),
            ("privacy_enabled", "隐私保护", "不上报任何文件信息", "shield_check"),
        ]
        self._toggle_widgets = {}
        for key, title, desc, icon in settings_list:
            _init_on = key in ("realtime_protect", "process_protect", "cloud_scan", "file_protect", "file_modify_monitor")
            if key == "etw_telemetry":
                _init_on = bool(g_settings.get("etw_telemetry", False))
            item = ListWidgetItem(title, desc, show_toggle=True, toggle_checked=_init_on, icon_key=icon)
            item.toggle.toggled.connect(lambda c, k=key: self._on_toggle(k, c))
            self._toggle_widgets[key] = item
            self.addWidget(item)
        engine_card = CardWidget()
        el = QVBoxLayout(engine_card)
        el.setContentsMargins(24, 18, 24, 18)
        el.setSpacing(10)
        eg_header = QHBoxLayout()
        eg_header.setSpacing(8)
        eg_icon = QLabel()
        eg_icon.setPixmap(render_svg("cpu", th["accent"], 18))
        eg_icon.setFixedSize(20, 20)
        eg_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        eg_header.addWidget(eg_icon)
        eg_title = QLabel("引擎调用方式")
        eg_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        eg_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        eg_header.addWidget(eg_title)
        eg_header.addStretch()
        el.addLayout(eg_header)
        eg_desc = QLabel("代码模式调用 SevenEngine.py（依赖本机 Python 环境）；exe 模式调用打包好的 SevenEngine.exe（无需 Python）")
        eg_desc.setFont(QFont("Microsoft YaHei", 8))
        eg_desc.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        el.addWidget(eg_desc)
        self._engine_combo = QComboBox()
        self._engine_combo.setFont(QFont("Microsoft YaHei", 9))
        self._engine_combo.setFixedHeight(36)
        self._engine_combo.addItem("调用引擎代码 (SevenEngine.py)")
        self._engine_combo.addItem("调用打包引擎 (SevenEngine.exe)")
        self._engine_combo.setCurrentIndex(1 if g_settings.get("engine_mode", "exe") == "exe" else 0)
        self._engine_combo.setStyleSheet(f"""
            QComboBox {{
                background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 8px;
                padding: 0 36px 0 14px;
                font-family: "Microsoft YaHei";
            }}
            QComboBox:hover, QComboBox:on {{
                border: 2px solid rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 32px;
                border: none;
                background: transparent;
            }}
            QComboBox::down-arrow {{
                width: 0px;
                height: 0px;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 7px solid rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QComboBox::down-arrow:on {{
                border-top: 0px solid transparent;
                border-bottom: 7px solid rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
            QComboBox QAbstractItemView {{
                background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 8px;
                selection-background-color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
                selection-color: #ffffff;
                outline: 0;
                padding: 4px;
            }}
            QComboBox QAbstractItemView::item {{
                min-height: 34px;
                border-radius: 6px;
                padding: 0 10px;
            }}
        """)
        self._engine_combo.currentIndexChanged.connect(self._on_engine_mode)
        el.addWidget(self._engine_combo)
        self.addWidget(engine_card)
        api_card = CardWidget()
        al = QVBoxLayout(api_card)
        al.setContentsMargins(24, 18, 24, 18)
        al.setSpacing(10)
        api_header = QHBoxLayout()
        api_header.setSpacing(8)
        api_icon = QLabel()
        api_icon.setPixmap(render_svg("server", th["accent"], 18))
        api_icon.setFixedSize(20, 20)
        api_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        api_header.addWidget(api_icon)
        api_title = QLabel("云端 API Key")
        api_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        api_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        api_header.addWidget(api_title)
        api_header.addStretch()
        al.addLayout(api_header)
        api_row = QHBoxLayout()
        api_row.setSpacing(8)
        self.api_key_input = QLineEdit()
        self.api_key_input.setFixedHeight(34)
        self.api_key_input.setFont(QFont("Microsoft YaHei", 9))
        self.api_key_input.setPlaceholderText("输入云端 API Key (scan_xxxxx)")
        self.api_key_input.setText(CONFIG.get("cloud_api_key", ""))
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        api_row.addWidget(self.api_key_input, 1)
        save_btn = QPushButton("保存")
        save_btn.setFixedSize(64, 34)
        save_btn.setFont(QFont("Microsoft YaHei", 9))
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self._save_api_key)
        api_row.addWidget(save_btn)
        al.addLayout(api_row)
        self.addWidget(api_card)
        self.addStretch()

    def _save_api_key(self):
        key = self.api_key_input.text().strip()
        CONFIG["cloud_api_key"] = key
        if g_scanner and hasattr(g_scanner, 'cloud'):
            g_scanner.cloud.api_key = key
        _log(f"[设置] 云API Key已更新: {key[:8]}...")
        QMessageBox.information(self, "已保存", "API Key 已保存")

    def _on_engine_mode(self, idx):
        mode = "exe" if idx == 1 else "code"
        g_settings["engine_mode"] = mode
        _save_settings_json()
        _log("[设置] 引擎调用方式: {}".format("打包引擎 SevenEngine.exe" if mode == "exe" else "引擎代码 SevenEngine.py"))
        # 让已运行的扫描 worker 失效, 下次扫描按新模式重新拉起
        try:
            win = self.window()
            rm = getattr(win, '_realtime_monitor', None)
            if rm is not None:
                with rm._proc_lock:
                    if rm._scan_proc:
                        try:
                            rm._scan_proc.kill()
                        except Exception:
                            pass
                        rm._scan_proc = None
        except Exception:
            pass

    def _on_toggle(self, key, checked):
        global g_settings
        if key == "realtime_protect" and not checked:
            sw = self._toggle_widgets.get(key)
            if sw and sw.toggle:
                sw.toggle.blockSignals(True)
                sw.toggle.setChecked(True)
                sw.toggle.blockSignals(False)
            return
        g_settings[key] = checked
        _save_settings_json()
        _log(f"[设置] {key}: {'开启' if checked else '关闭'}")
        if key in ("file_protect", "file_modify_monitor"):
            fm = getattr(self, '_file_monitor', None) or getattr(self.window(), '_file_monitor', None)
            if fm:
                fm._send_command({"cmd": "set_config", "key": key, "value": checked})
        if key == "cloud_scan":
            CONFIG["cloud_scan_enabled"] = checked
            if g_scanner and hasattr(g_scanner, 'cloud'):
                pass
            if checked and not CONFIG.get("cloud_api_key", ""):
                QMessageBox.warning(self, "需要API Key", "请在下方输入云端 API Key 并保存")
        if key == "menu_scan":
            if checked:
                ok = install_context_menu()
                if not ok:
                    sw = self._toggle_widgets.get(key)
                    if sw and sw.toggle:
                        sw.toggle.blockSignals(True)
                        sw.toggle.setChecked(False)
                        sw.toggle.blockSignals(False)
                    g_settings[key] = False
                    QMessageBox.warning(self, "注册失败", "无法注册右键菜单，请检查权限")
            else:
                remove_context_menu()
        if key == "etw_telemetry":
            win = self.window()
            if checked:
                # 默认启动, 无需测试版确认弹窗
                try:
                    if getattr(win, '_etw_monitor', None) is None:
                        win._etw_monitor = EtwTelemetryMonitor(win)
                    win._etw_monitor.start()
                except Exception as e:
                    _log(f"[遥测拦截] 启动失败: {e}")
            else:
                try:
                    m = getattr(win, '_etw_monitor', None)
                    if m:
                        m.stop()
                        _log("[遥测拦截] 已关闭,Worker已停止")
                except Exception:
                    pass
        try:
            def _do():
                ApiClient.update_config(key, checked)
            threading.Thread(target=_do, daemon=True).start()
        except:
            pass

    def reload_settings(self):
        global g_settings
        for key, item in self._toggle_widgets.items():
            val = CONFIG.get(key, g_settings.get(key, False))
            if key == "realtime_protect":
                val = True
            if key == "cloud_scan":
                val = CONFIG.get("cloud_scan_enabled", True)
            g_settings[key] = val
            if item.toggle:
                item.toggle.setChecked(bool(val))

    def update_theme(self):
        super().update_theme()
        for item in self._toggle_widgets.values():
            item.update_theme()


class _ManageDialog(QDialog):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(620, 460)
        th = get_theme()
        self._th = th
        self.setStyleSheet(f"QDialog {{ background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()}); border-radius: 8px; }}")
        self._main_layout = QVBoxLayout(self)
        self._main_layout.setContentsMargins(0, 0, 0, 0)
        self._main_layout.setSpacing(0)
        header = QFrame()
        header.setFixedHeight(52)
        header.setStyleSheet(f"QFrame {{ background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()}); border-bottom: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()}); }}")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)
        title_label = QLabel(title)
        title_label.setFont(QFont("Microsoft YaHei", 11, QFont.Weight.Medium))
        title_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        hl.addWidget(title_label)
        hl.addStretch()
        close_btn = QPushButton()
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("QPushButton { background: transparent; border: none; } QPushButton:hover { background: rgb(232,72,72,30); border-radius: 4px; }")
        close_btn.setIcon(QIcon(render_svg("close", th['text_secondary'], 16)))
        close_btn.clicked.connect(self.reject)
        hl.addWidget(close_btn)
        self._main_layout.addWidget(header)
        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(20, 16, 20, 16)
        self._body_layout.setSpacing(12)
        self._main_layout.addWidget(self._body, 1)
        self._list_widget = QListWidget()
        self._list_widget.setFont(QFont("Microsoft YaHei", 9))
        self._list_widget.setStyleSheet(f"""
            QListWidget {{
                background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 6px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 8px 12px;
                border-bottom: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
            }}
            QListWidget::item:selected {{
                background: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()}, 25);
                color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
            QListWidget::item:hover {{
                background: rgb({th['bg_hover'].red()},{th['bg_hover'].green()},{th['bg_hover'].blue()});
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)
        self._body_layout.addWidget(self._list_widget, 1)
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(8)
        self._btn_bar = btn_bar
        self._body_layout.addLayout(btn_bar)
        self._extra_btns = []

    def _make_btn(self, text, color_key="accent"):
        th = self._th
        c = th[color_key]
        btn = QPushButton(text)
        btn.setFixedHeight(32)
        btn.setFont(QFont("Microsoft YaHei", 9))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: rgb({c.red()},{c.green()},{c.blue()});
                color: white;
                border: none;
                border-radius: 6px;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                background: rgb({max(0,c.red()-20)},{max(0,c.green()-20)},{max(0,c.blue()-20)});
            }}
            QPushButton:pressed {{
                background: rgb({max(0,c.red()-40)},{max(0,c.green()-40)},{max(0,c.blue()-40)});
            }}
            QPushButton:disabled {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
        """)
        return btn

    def _make_outline_btn(self, text):
        th = self._th
        btn = QPushButton(text)
        btn.setFixedHeight(32)
        btn.setFont(QFont("Microsoft YaHei", 9))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 6px;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                border-color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
                color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
        """)
        return btn


class WhitelistDialog(_ManageDialog):
    def __init__(self, scanner, parent=None):
        super().__init__("白名单管理 - 扫描排除列表", parent)
        self._scanner = scanner
        add_file_btn = self._make_outline_btn("添加文件")
        add_file_btn.clicked.connect(self._add_file)
        self._btn_bar.addWidget(add_file_btn)
        add_dir_btn = self._make_outline_btn("添加文件夹")
        add_dir_btn.clicked.connect(self._add_dir)
        self._btn_bar.addWidget(add_dir_btn)
        self._btn_bar.addStretch()
        remove_btn = self._make_btn("移除选中", "danger")
        remove_btn.clicked.connect(self._remove_selected)
        self._btn_bar.addWidget(remove_btn)
        close_btn = self._make_outline_btn("关闭")
        close_btn.clicked.connect(self.accept)
        self._btn_bar.addWidget(close_btn)
        self._load_entries()

    def _load_entries(self):
        self._list_widget.clear()
        if self._scanner and self._scanner.whitelist:
            for p in self._scanner.whitelist.get_paths():
                item_text = p
                if os.path.isdir(p):
                    item_text += "  [文件夹]"
                elif os.path.isfile(p):
                    item_text += "  [文件]"
                else:
                    item_text += "  [不存在]"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, p)
                self._list_widget.addItem(item)
        if self._list_widget.count() == 0:
            item = QListWidgetItem("（白名单为空，添加的文件/文件夹将在扫描时被跳过）")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list_widget.addItem(item)

    def _add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
        if path:
            if self._scanner and self._scanner.whitelist:
                self._scanner.whitelist.add_path(path)
                _log(f"[白名单] 添加文件: {path}")
            self._load_entries()

    def _add_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if path:
            if self._scanner and self._scanner.whitelist:
                self._scanner.whitelist.add_path(path)
                _log(f"[白名单] 添加文件夹: {path}")
            self._load_entries()

    def _remove_selected(self):
        item = self._list_widget.currentItem()
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path:
            return
        reply = QMessageBox.question(self, "确认移除", f"确定从白名单中移除？\n\n{path}",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        if self._scanner and self._scanner.whitelist:
            self._scanner.whitelist.remove_path(path)
            _log(f"[白名单] 移除: {path}")
        self._load_entries()


class QuarantineDialog(_ManageDialog):
    def __init__(self, parent=None):
        super().__init__("隔离区管理", parent)
        restore_btn = self._make_btn("恢复选中", "accent")
        restore_btn.clicked.connect(self._restore_selected)
        self._btn_bar.addWidget(restore_btn)
        delete_btn = self._make_btn("永久删除", "danger")
        delete_btn.clicked.connect(self._delete_selected)
        self._btn_bar.addWidget(delete_btn)
        self._btn_bar.addStretch()
        close_btn = self._make_outline_btn("关闭")
        close_btn.clicked.connect(self.accept)
        self._btn_bar.addWidget(close_btn)
        self._load_entries()

    def _load_entries(self):
        self._list_widget.clear()
        if not os.path.exists(QUARANTINE_DIR):
            item = QListWidgetItem("（隔离区目录不存在）")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list_widget.addItem(item)
            return
        items = []
        for f in os.listdir(QUARANTINE_DIR):
            fpath = os.path.join(QUARANTINE_DIR, f)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                mtime = os.path.getmtime(fpath)
                import time as _t
                date_str = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(mtime))
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f} KB"
                else:
                    size_str = f"{size/1024/1024:.1f} MB"
                orig_name = f.replace(".quarantine", "") if f.endswith(".quarantine") else f
                display = f"{orig_name}    {size_str}    {date_str}"
                items.append((display, fpath))
        if not items:
            item = QListWidgetItem("（隔离区为空）")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list_widget.addItem(item)
            return
        for display, fpath in items:
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, fpath)
            self._list_widget.addItem(item)

    def _restore_selected(self):
        item = self._list_widget.currentItem()
        if not item:
            return
        fpath = item.data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath):
            return
        orig_name = os.path.basename(fpath)
        if orig_name.endswith(".quarantine"):
            orig_name = orig_name[:-len(".quarantine")]
        dest_dir = QFileDialog.getExistingDirectory(self, "选择恢复目录")
        if not dest_dir:
            return
        dest = os.path.join(dest_dir, orig_name)
        if os.path.exists(dest):
            reply = QMessageBox.question(self, "文件已存在", "目标文件已存在，是否覆盖？",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return
            try:
                os.remove(dest)
            except:
                pass
        try:
            shutil.move(fpath, dest)
            _log(f"[隔离区] 恢复: {fpath} -> {dest}")
            _scan_log(f"[已恢复] {orig_name}")
            self._load_entries()
        except Exception as e:
            QMessageBox.warning(self, "恢复失败", str(e))

    def _delete_selected(self):
        item = self._list_widget.currentItem()
        if not item:
            return
        fpath = item.data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath):
            return
        reply = QMessageBox.question(self, "永久删除", "确定永久删除此文件？此操作不可撤销！",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            os.remove(fpath)
            _log(f"[隔离区] 永久删除: {fpath}")
            self._load_entries()
        except Exception as e:
            QMessageBox.warning(self, "删除失败", str(e))


class StartupDialog(_ManageDialog):
    def __init__(self, parent=None):
        super().__init__("启动项管理", parent)
        delete_btn = self._make_btn("删除选中", "danger")
        delete_btn.clicked.connect(self._delete_selected)
        self._btn_bar.addWidget(delete_btn)
        refresh_btn = self._make_outline_btn("刷新")
        refresh_btn.clicked.connect(self._load_entries)
        self._btn_bar.addWidget(refresh_btn)
        self._btn_bar.addStretch()
        close_btn = self._make_outline_btn("关闭")
        close_btn.clicked.connect(self.accept)
        self._btn_bar.addWidget(close_btn)
        self._load_entries()

    def _load_entries(self):
        self._list_widget.clear()
        self._items_data = []
        import winreg
        reg_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432Node\\Run"),
        ]
        for hive, path, source in reg_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, idx)
                        display = f"{name}\n    命令: {val[:80]}\n    来源: {source}"
                        item = QListWidgetItem(display)
                        item.setData(Qt.ItemDataRole.UserRole, len(self._items_data))
                        self._list_widget.addItem(item)
                        self._items_data.append({
                            "type": "registry",
                            "hive": hive,
                            "path": path,
                            "name": name,
                            "value": val,
                            "source": source,
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except:
                pass
        startup_dirs = [
            (os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'), "用户启动文件夹"),
            (os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), r'Microsoft\Windows\Start Menu\Programs\Startup'), "所有用户启动文件夹"),
        ]
        for dir_path, source in startup_dirs:
            if not os.path.exists(dir_path):
                continue
            for f in os.listdir(dir_path):
                fpath = os.path.join(dir_path, f)
                if os.path.isfile(fpath):
                    display = f"{f}\n    路径: {fpath}\n    来源: {source}"
                    item = QListWidgetItem(display)
                    item.setData(Qt.ItemDataRole.UserRole, len(self._items_data))
                    self._list_widget.addItem(item)
                    self._items_data.append({
                        "type": "folder",
                        "path": fpath,
                        "name": f,
                        "source": source,
                    })
        if self._list_widget.count() == 0:
            item = QListWidgetItem("（未找到启动项）")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list_widget.addItem(item)

    def _delete_selected(self):
        item = self._list_widget.currentItem()
        if not item:
            return
        idx = item.data(Qt.ItemDataRole.UserRole)
        if idx is None or not isinstance(idx, int) or idx >= len(self._items_data):
            return
        data = self._items_data[idx]
        name = data.get("name", "")
        reply = QMessageBox.question(self, "确认删除", f"确定删除启动项？\n\n{name}\n\n此操作不可撤销！",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            if data["type"] == "registry":
                import winreg
                hive = data["hive"]
                path = data["path"]
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(key, data["name"])
                    winreg.CloseKey(key)
                except Exception as e:
                    winreg.CloseKey(key)
                    raise e
                _log(f"[启动项] 删除注册表项: {data['name']}")
            elif data["type"] == "folder":
                os.remove(data["path"])
                _log(f"[启动项] 删除文件: {data['path']}")
            self._load_entries()
        except PermissionError:
            QMessageBox.warning(self, "权限不足", "需要管理员权限才能删除此启动项。")
        except Exception as e:
            QMessageBox.warning(self, "删除失败", str(e))


class ToolPage(ScrollPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        tools_info = [
            ("白名单管理", "管理扫描排除列表", "list"),
            ("隔离区管理", "查看/恢复/删除隔离文件", "lock"),
            ("服务器状态", "查看后端服务运行状态", "server"),
            ("学习引擎", "查看机器学习记录", "book"),
            ("系统信息", "查看系统安全状态", "cpu"),
            ("启动项管理", "查看开机启动项", "tool"),
        ]
        for title, desc, icon in tools_info:
            item = ListWidgetItem(title, desc, show_chevron=True, icon_key=icon)
            item.clicked.connect(lambda t=title: self._tool_click(t))
            self.addWidget(item)
        cmd_card = CardWidget()
        cl = QVBoxLayout(cmd_card)
        cl.setContentsMargins(24, 18, 24, 18)
        cl.setSpacing(10)
        cmd_header = QHBoxLayout()
        cmd_header.setSpacing(8)
        cmd_icon = QLabel()
        cmd_icon.setPixmap(render_svg("terminal", th["accent"], 18))
        cmd_icon.setFixedSize(20, 20)
        cmd_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cmd_header.addWidget(cmd_icon)
        cmd_title = QLabel("命令控制台")
        cmd_title.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        cmd_title.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        cmd_header.addWidget(cmd_title)
        cmd_header.addStretch()
        cl.addLayout(cmd_header)
        cmd_row = QHBoxLayout()
        cmd_row.setSpacing(8)
        self.cmd_input = QLineEdit()
        self.cmd_input.setFixedHeight(34)
        self.cmd_input.setFont(QFont("Microsoft YaHei", 9))
        self.cmd_input.setPlaceholderText("输入命令 (status, help)")
        cmd_row.addWidget(self.cmd_input, 1)
        self.cmd_btn = QPushButton("发送")
        self.cmd_btn.setFixedSize(64, 34)
        self.cmd_btn.setFont(QFont("Microsoft YaHei", 9))
        self.cmd_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cmd_btn.clicked.connect(self._send_cmd)
        cmd_row.addWidget(self.cmd_btn)
        cl.addLayout(cmd_row)
        self.addWidget(cmd_card)
        self.addStretch()

    def _tool_click(self, name):
        global g_scanner
        try:
            if name == "白名单管理":
                dlg = WhitelistDialog(g_scanner, self)
                dlg.exec()
            elif name == "隔离区管理":
                dlg = QuarantineDialog(self)
                dlg.exec()
            elif name == "启动项管理":
                dlg = StartupDialog(self)
                dlg.exec()
            elif name == "服务器状态":
                log = ""
                try:
                    s = ApiClient.get_status()
                    if s:
                        log = "服务器状态:\n" + "\n".join(f"  {k}: {v}" for k, v in s.items())
                    else:
                        log = "服务器未连接 (pedefenseserver.exe 未运行)"
                except:
                    log = "服务器未连接 (pedefenseserver.exe 未运行)"
                QMessageBox.information(self, name, log)
            elif name == "学习引擎":
                log = ""
                if g_scanner:
                    log = f"学习引擎记录数: {g_scanner.study.get_record_count()}"
                    threats = g_scanner.study.get_known_threats()
                    if threats:
                        log += "\n已知威胁:\n" + "\n".join(f"  {t.get('filepath','?')}" for t in threats[:10])
                else:
                    log = "引擎未就绪"
                QMessageBox.information(self, name, log)
            elif name == "系统信息":
                log = ""
                try:
                    import platform
                    log = f"系统: {platform.system()} {platform.version()}\n"
                    log += f"主机: {platform.node()}\n"
                    log += f"处理器: {platform.processor()}\n"
                    log += f"Python: {platform.python_version()}"
                except:
                    log = "无法获取系统信息"
                QMessageBox.information(self, name, log)
        except Exception as e:
            _log(f"[工具] {name} 异常: {e}")
            try:
                QMessageBox.warning(self, "错误", f"操作失败: {e}")
            except:
                pass

    def _send_cmd(self):
        cmd = self.cmd_input.text().strip()
        if not cmd:
            return
        cl = cmd.lower().strip()
        try:
            if cl == "status":
                msg = "服务器: " + ("已连接" if g_status.get("ok") else "未连接")
                msg += "\n引擎: " + ("就绪" if g_scanner else "未初始化")
                QMessageBox.information(self, "状态", msg)
            elif cl == "help":
                QMessageBox.information(self, "帮助", "可用: status, help")
            else:
                QMessageBox.information(self, "命令", "未知命令: " + cmd)
        except Exception as e:
            _log(f"[命令] 异常: {e}")
        self.cmd_input.setText("")

    def update_theme(self):
        super().update_theme()
        th = get_theme()
        for item in self.findChildren(ListWidgetItem):
            item.update_theme()
        self.cmd_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()});
                color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 8px;
                padding: 0 12px;
                font-family: "Microsoft YaHei";
            }}
            QLineEdit:focus {{
                border: 2px solid rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
        """)
        self.cmd_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
                border: none;
                border-radius: 8px;
                color: white;
                font-family: "Microsoft YaHei";
            }}
            QPushButton:hover {{
                background: rgb({max(0,th['accent'].red()-20)},{max(0,th['accent'].green()-20)},{max(0,th['accent'].blue()-20)});
            }}
        """)


class AboutPage(ScrollPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        info_card = CardWidget()
        il = QVBoxLayout(info_card)
        il.setContentsMargins(28, 24, 28, 24)
        il.setSpacing(12)
        about_title = QLabel("SevenEndPointSecurity")
        about_title.setFont(QFont("Microsoft YaHei", 16, QFont.Weight.Bold))
        about_title.setStyleSheet(f"background: transparent; color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});")
        il.addWidget(about_title)
        about_text = QLabel(
            "版本: v3.0.0\n"
            "基于 PyQt6 的主动防御与反病毒软件\n"
            "集成多引擎扫描、实时监控与云端协同\n\n"
            "扫描引擎: SevenEngine (SevenEngine\\SevenEngine.py)\n"
            "AI模型: LightGBM (EngineSET\\lightgbm.pda)\n\n"
            "Copyright 2024-2026 NewEra Studio"
        )
        about_text.setFont(QFont("Microsoft YaHei", 10))
        about_text.setWordWrap(True)
        about_text.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        il.addWidget(about_text)
        self.addWidget(info_card)
        self.addStretch()

    def update_theme(self):
        super().update_theme()
        th = get_theme()
        for label in self.findChildren(QLabel):
            if label.text() == "SevenEndPointSecurity":
                label.setStyleSheet(f"background: transparent; color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});")
            elif label.text().startswith("版本"):
                label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")


class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._anim_duration = 250
        self._old_opacity_eff = None
        self._new_opacity_eff = None
        self._old_anim = None
        self._new_anim = None
        self._pos_anim = None
        self._pending_widget = None
        self._is_animating = False

    def setCurrentWidget(self, widget):
        if self._is_animating:
            self._pending_widget = widget
            return
        if self.currentWidget() is widget:
            return
        if self.currentWidget() is None:
            super().setCurrentWidget(widget)
            return
        self._animate_switch(widget)

    def _animate_switch(self, new_widget):
        self._is_animating = True
        old_widget = self.currentWidget()
        w = self.width()
        h = self.height()
        offset = 24
        old_widget.setGraphicsEffect(None)
        new_widget.setGraphicsEffect(None)
        self._old_opacity_eff = QGraphicsOpacityEffect(old_widget)
        self._old_opacity_eff.setOpacity(1.0)
        old_widget.setGraphicsEffect(self._old_opacity_eff)
        self._new_opacity_eff = QGraphicsOpacityEffect(new_widget)
        self._new_opacity_eff.setOpacity(0.0)
        new_widget.setGraphicsEffect(self._new_opacity_eff)
        new_widget.move(offset, 0)
        super().setCurrentWidget(new_widget)
        self._old_anim = QPropertyAnimation(self._old_opacity_eff, b"opacity")
        self._old_anim.setDuration(self._anim_duration)
        self._old_anim.setStartValue(1.0)
        self._old_anim.setEndValue(0.0)
        self._old_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._new_anim = QPropertyAnimation(self._new_opacity_eff, b"opacity")
        self._new_anim.setDuration(self._anim_duration)
        self._new_anim.setStartValue(0.0)
        self._new_anim.setEndValue(1.0)
        self._new_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._pos_anim = QPropertyAnimation(new_widget, b"pos")
        self._pos_anim.setDuration(self._anim_duration)
        self._pos_anim.setStartValue(QPoint(offset, 0))
        self._pos_anim.setEndValue(QPoint(0, 0))
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._old_anim.start()
        self._new_anim.start()
        self._pos_anim.start()
        self._new_anim.finished.connect(self._on_anim_finished)

    def _on_anim_finished(self):
        old_w = None
        if self._old_opacity_eff:
            old_w = self._old_opacity_eff.parent()
        if old_w:
            old_w.setGraphicsEffect(None)
        if self._new_opacity_eff and self._new_opacity_eff.parent():
            self._new_opacity_eff.parent().setGraphicsEffect(None)
        self._old_opacity_eff = None
        self._new_opacity_eff = None
        self._old_anim = None
        self._new_anim = None
        self._pos_anim = None
        self._is_animating = False
        if self._pending_widget:
            pw = self._pending_widget
            self._pending_widget = None
            self.setCurrentWidget(pw)


class ThreatBlockDialog(QDialog):
    def __init__(self, file_path, threat_type, confidence, scan_engine, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self._result_action = "ignore"
        self._drag_offset = None
        th = get_theme()
        self._th = th
        self._file_path = file_path
        self._threat_type = threat_type
        self._confidence = confidence
        self._engine = scan_engine
        self.resize(520, 0)
        self.setStyleSheet(f"ThreatBlockDialog {{ background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()}); border: 1px solid #e0e0e0; border-radius: 10px; }}")
        self._container = QWidget(self)
        self._container.setStyleSheet("background: transparent; border: none;")
        cl = QVBoxLayout(self._container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        self._build_header(cl, th)
        self._build_body(cl, th)
        self._build_actions(cl, th)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._container)
        self._opacity = QGraphicsOpacityEffect(self._container)
        self._opacity.setOpacity(0.0)
        self._container.setGraphicsEffect(self._opacity)
        self._pos_anim = QPropertyAnimation(self._container, b"pos", self)
        self._pos_anim.setDuration(260)
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim = QPropertyAnimation(self._opacity, b"opacity", self)
        self._fade_anim.setDuration(260)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)

    def _build_header(self, layout, th):
        header = QFrame()
        header.setFixedHeight(56)
        header.setCursor(Qt.CursorShape.SizeAllCursor)
        header.setStyleSheet(f"QFrame {{ background: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()}); border-top-left-radius: 10px; border-top-right-radius: 10px; }}")
        header.installEventFilter(self)
        self._drag_header = header
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)
        hl.setSpacing(12)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(render_svg("shield_alert", QColor(255,255,255), 26))
        hl.addWidget(icon_lbl)
        title = QLabel("已拦截可疑文件")
        title.setFont(QFont("Microsoft YaHei", 12, QFont.Weight.DemiBold))
        title.setStyleSheet("color: white; background: transparent;")
        hl.addWidget(title)
        hl.addStretch()
        close_btn = QPushButton()
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("QPushButton { background: transparent; border: none; } QPushButton:hover { background: rgb(255,255,255,40); border-radius: 4px; }")
        close_btn.setIcon(QIcon(render_svg("close", QColor(255,255,255), 16)))
        close_btn.clicked.connect(self._on_ignore)
        hl.addWidget(close_btn)
        layout.addWidget(header)

    def eventFilter(self, obj, event):
        if obj is getattr(self, '_drag_header', None):
            if event.type() == event.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                self._drag_offset = event.globalPosition().toPoint() - self.pos()
                return True
            elif event.type() == event.Type.MouseMove and self._drag_offset is not None:
                if event.buttons() & Qt.MouseButton.LeftButton:
                    self.move(event.globalPosition().toPoint() - self._drag_offset)
                    return True
            elif event.type() == event.Type.MouseButtonRelease:
                self._drag_offset = None
                return True
        return super().eventFilter(obj, event)

    def _build_body(self, layout, th):
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 20, 24, 16)
        bl.setSpacing(14)
        threat_summary = QFrame()
        threat_summary.setStyleSheet(f"QFrame {{ background: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()}, 18); border-radius: 8px; }}")
        tsl = QHBoxLayout(threat_summary)
        tsl.setContentsMargins(16, 14, 16, 14)
        tsl.setSpacing(12)
        t_icon = QLabel()
        t_icon.setPixmap(render_svg("shield_cross", th['danger'], 28))
        tsl.addWidget(t_icon)
        tvl = QVBoxLayout()
        tvl.setSpacing(2)
        tname = QLabel(self._threat_type)
        tname.setFont(QFont("Microsoft YaHei", 11, QFont.Weight.DemiBold))
        tname.setStyleSheet(f"color: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()}); background: transparent;")
        tvl.addWidget(tname)
        tdesc = QLabel(f"威胁置信度 {self._confidence}%  ·  检测引擎: {self._engine}")
        tdesc.setFont(QFont("Microsoft YaHei", 9))
        tdesc.setStyleSheet(f"color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()}); background: transparent;")
        tvl.addWidget(tdesc)
        tsl.addLayout(tvl, 1)
        bl.addWidget(threat_summary)
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"QFrame {{ background: rgb({th['bg_window'].red()},{th['bg_window'].green()},{th['bg_window'].blue()}); border-radius: 6px; }}")
        dl = QVBoxLayout(detail_frame)
        dl.setContentsMargins(16, 14, 16, 14)
        dl.setSpacing(8)
        try:
            fsize = os.path.getsize(self._file_path)
            if fsize < 1024: size_str = f"{fsize} B"
            elif fsize < 1048576: size_str = f"{fsize/1024:.1f} KB"
            else: size_str = f"{fsize/1048576:.1f} MB"
        except: size_str = "未知"
        import datetime as _dt
        try:
            mtime = _dt.datetime.fromtimestamp(os.path.getmtime(self._file_path)).strftime("%Y-%m-%d %H:%M")
        except: mtime = "未知"
        details = [
            ("文件名", os.path.basename(self._file_path)),
            ("文件大小", size_str),
            ("修改时间", mtime),
            ("检测类型", self._threat_type),
            ("检测引擎", self._engine),
            ("置信度", f"{self._confidence}%"),
            ("完整路径", self._file_path),
        ]
        for label, val in details:
            row = QHBoxLayout()
            row.setSpacing(8)
            lk = QLabel(label)
            lk.setFixedWidth(70)
            lk.setFont(QFont("Microsoft YaHei", 9))
            lk.setStyleSheet(f"color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()}); background: transparent;")
            vv = QLabel(val)
            vv.setWordWrap(True)
            vv.setFont(QFont("Microsoft YaHei", 9))
            vv.setStyleSheet(f"color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()}); background: transparent;")
            row.addWidget(lk)
            row.addWidget(vv, 1)
            dl.addLayout(row)
        bl.addWidget(detail_frame)
        layout.addWidget(body, 1)

    def _build_actions(self, layout, th):
        bar = QWidget()
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(24, 0, 24, 20)
        bl.setSpacing(10)
        bl.addStretch()
        btn_ignore = self._make_btn("忽略", th, ghost=True)
        btn_ignore.clicked.connect(self._on_ignore)
        bl.addWidget(btn_ignore)
        btn_delete = self._make_btn("删除", th, danger=True)
        btn_delete.clicked.connect(self._on_delete)
        bl.addWidget(btn_delete)
        btn_quarantine = self._make_btn("隔离", th, primary=True)
        btn_quarantine.clicked.connect(self._on_quarantine)
        bl.addWidget(btn_quarantine)
        layout.addWidget(bar)

    def _make_btn(self, text, th, primary=False, danger=False, ghost=False):
        btn = QPushButton(text)
        btn.setFixedHeight(36)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        if primary:
            bg = f"rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()})"
            btn.setStyleSheet(f"QPushButton {{ background: {bg}; color: white; border: none; border-radius: 6px; padding: 0 24px; }} QPushButton:hover {{ background: rgb({th['accent'].red() - 20},{th['accent'].green() - 20},{th['accent'].blue() - 20}); }}")
        elif danger:
            btn.setStyleSheet(f"QPushButton {{ background: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()}); color: white; border: none; border-radius: 6px; padding: 0 20px; }} QPushButton:hover {{ background: rgb({th['danger'].red() - 20},{th['danger'].green() - 20},{th['danger'].blue() - 20}); }}")
        else:
            btn.setStyleSheet(f"QPushButton {{ background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()}); border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()}); border-radius: 6px; padding: 0 20px; }} QPushButton:hover {{ background: rgb({th['bg_hover'].red()},{th['bg_hover'].green()},{th['bg_hover'].blue()}); }}")
        return btn

    def _on_quarantine(self):
        self._result_action = "quarantine"
        self.accept()

    def _on_delete(self):
        self._result_action = "delete"
        self.accept()

    def _on_ignore(self):
        self._result_action = "block"
        try:
            mon = self._parent._realtime_monitor if hasattr(self._parent, '_realtime_monitor') else None
            if mon:
                mon._terminate_chain(self._pid, self._name, self._path)
                _scan_log(f"[EDR-用户拦截] {self._name} {self._path} 评分={self._score}")
                _log(f"[EDR] 用户选择拦截: {self._name}({self._pid}) 已终止进程链")
        except Exception as e:
            _log(f"[EDR] 拦截终止失败: {e}")
        self.reject()

    def start_animation(self):
        _toast_slide_up(self, self._container)
        self._fade_anim.start()

    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QPainterPath, QRegion
        from PyQt6.QtCore import QRectF
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, self.width(), self.height()), 10, 10)
        painter.setClipPath(path)
        painter.fillPath(path, self._th['bg_panel'])
        painter.end()

    def exec(self):
        self.show()
        self.raise_()
        self.activateWindow()
        return 0

    def showEvent(self, event):
        super().showEvent(event)
        _apply_rounded_mask(self, 10)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _apply_rounded_mask(self, 10)


class _ScanAnimIcon(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(68, 68)
        self._phase = 0.0
        self._mode = "scanning"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def _tick(self):
        self._phase += 0.022
        if self._phase >= 2.0:
            self._phase -= 2.0
        self.update()

    def set_mode(self, mode):
        self._mode = mode
        if mode != "scanning":
            self._timer.stop()
        else:
            if not self._timer.isActive():
                self._timer.start(16)
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        w, h = self.width(), self.height()
        p.scale(w / 48.0, h / 48.0)
        if self._mode == "safe":
            c = QColor(16, 185, 129)
            pen = QPen(c, 1.5)
            p.setPen(pen)
            p.setBrush(QColor(16, 185, 129, 20))
            p.drawEllipse(4, 4, 40, 40)
            pen = QPen(c, 2.2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(pen)
            path = QPainterPath()
            path.moveTo(15, 24)
            path.lineTo(21, 30)
            path.lineTo(33, 17)
            p.drawPath(path)
        elif self._mode == "danger":
            c = QColor(209, 52, 56)
            pen = QPen(c, 1.5)
            p.setPen(pen)
            p.setBrush(QColor(209, 52, 56, 20))
            p.drawEllipse(4, 4, 40, 40)
            pen = QPen(c, 2.0)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(pen)
            p.drawLine(16, 16, 32, 32)
            p.drawLine(32, 16, 16, 32)
        elif self._mode == "warning":
            c = QColor(202, 138, 4)
            pen = QPen(c, 1.5)
            p.setPen(pen)
            p.setBrush(QColor(202, 138, 4, 20))
            p.drawEllipse(4, 4, 40, 40)
            pen = QPen(c, 2.0)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(pen)
            p.drawLine(24, 14, 24, 26)
            p.drawPoint(24, 31)
        else:
            accent = QColor(0, 120, 215)
            pen = QPen(accent, 1.8)
            p.setPen(pen)
            p.setBrush(QColor(232, 244, 253, 128))
            p.drawRoundedRect(10, 6, 28, 36, 4, 4)
            pen = QPen(QColor(0, 120, 215, 102), 1.5)
            p.setPen(pen)
            p.drawLine(28, 6, 28, 14)
            p.drawLine(28, 14, 38, 14)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(0, 120, 215, 77))
            p.drawRoundedRect(QRectF(16, 18, 16, 2.5), 1.0, 1.0)
            p.setBrush(QColor(0, 120, 215, 51))
            p.drawRoundedRect(QRectF(16, 24, 12, 2.5), 1.0, 1.0)
            p.setBrush(QColor(0, 120, 215, 64))
            p.drawRoundedRect(QRectF(16, 30, 14, 2.5), 1.0, 1.0)
            t = self._phase
            if t > 1.0:
                t = 2.0 - t
            y = 8 + t * 30
            grad = QLinearGradient(0, y - 12, 0, y)
            grad.setColorAt(0, QColor(0, 120, 215, 0))
            grad.setColorAt(1, QColor(0, 120, 215, 89))
            p.setBrush(QBrush(grad))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(QRectF(4, y - 12, 40, 12), 1.5, 1.5)
            grad2 = QLinearGradient(0, y, 0, y + 12)
            grad2.setColorAt(0, QColor(0, 120, 215, 89))
            grad2.setColorAt(1, QColor(0, 120, 215, 0))
            p.setBrush(QBrush(grad2))
            p.drawRoundedRect(QRectF(4, y, 40, 12), 1.5, 1.5)
            p.setBrush(QColor(0, 120, 215, 191))
            p.drawRoundedRect(QRectF(4, y, 40, 2.5), 1.25, 1.25)
            p.setBrush(QColor(255, 255, 255, 153))
            p.drawRect(QRectF(4, y + 1, 40, 1))


class _SlidingProgress(QWidget):
    """无限循环扫描进度条(商业EDR风格):
    光带从左侧不可见处钻入,横穿后从右侧不可见处滑出消失,
    再从左侧不可见处重新进入,循环往复。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(4)
        self._offset = -0.35
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.timeout.connect(self._tick)
        self._timer.start(12)  # ~83fps 定时器,绘制随显示器刷新率合成,流畅不卡顿
        self._color = QColor(0, 120, 215)
        self._stopped = False

    def _tick(self):
        # 一个周期:-0.35(光带完全在左侧不可见) → 1.35(光带完全滑出右侧不可见)
        self._offset += 0.010
        if self._offset > 1.35:
            self._offset = -0.35
        self.update()

    def set_color(self, color):
        self._color = color
        self._stopped = True
        self._timer.stop()
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(245, 245, 245))
        p.drawRoundedRect(0, 0, w, h, 2, 2)
        if self._stopped:
            p.setBrush(self._color)
            p.drawRoundedRect(0, 0, w, h, 2, 2)
            return
        bar_w = w * 0.35
        x = self._offset * w
        grad = QLinearGradient(x, 0, x + bar_w, 0)
        c = self._color
        # 两端渐隐:进入/离开视口时自然浮现与消隐
        grad.setColorAt(0.0, QColor(c.red(), c.green(), c.blue(), 0))
        grad.setColorAt(0.25, QColor(c.red(), c.green(), c.blue(), 90))
        grad.setColorAt(0.6, c)
        grad.setColorAt(1.0, QColor(c.red(), c.green(), c.blue(), 0))
        p.setBrush(QBrush(grad))
        p.drawRoundedRect(QRectF(x, 0, bar_w, h), 2.0, 2.0)


class FileOpDialog(QDialog):
    def __init__(self, count, creates, deletes, modifies, renames, files, parent=None, ops=None, proc_name="", proc_pid=0, proc_path="", ransomware=False):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self._drag_offset = None
        self._result_action = "rollback"
        self._trusted_dir = ""
        self._ransomware = ransomware
        self.resize(540, 540)
        self.setWindowOpacity(0.0)
        self.setStyleSheet("FileOpDialog { background: #ffffff; border: 1px solid #e0e0e0; border-radius: 12px; }")
        self._container = QWidget(self)
        self._container.setStyleSheet("background: transparent; border: none;")
        cl = QVBoxLayout(self._container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        self._build_ui(cl, creates, deletes, modifies, renames, files, ops, proc_name, proc_pid, proc_path)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._container)
        self._pos_anim = QPropertyAnimation(self._container, b"pos", self)
        self._pos_anim.setDuration(260)
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setDuration(260)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)

    def _build_ui(self, layout, creates, deletes, modifies, renames, files, ops, proc_name, proc_pid, proc_path):
        drag_bar = QFrame()
        drag_bar.setFixedHeight(32)
        drag_bar.setCursor(Qt.CursorShape.SizeAllCursor)
        drag_bar.setStyleSheet("QFrame { background: transparent; border: none; }")
        drag_bar.installEventFilter(self)
        self._drag_bar = drag_bar
        dl = QHBoxLayout(drag_bar)
        dl.setContentsMargins(16, 0, 16, 0)
        dl.setSpacing(0)
        brand = QLabel("SevenEndPointSecurity")
        brand.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.DemiBold))
        brand.setStyleSheet("color: #0078D4; background: transparent;")
        dl.addWidget(brand)
        dl.addStretch()
        layout.addWidget(drag_bar)
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(32, 4, 32, 4)
        cl.setSpacing(6)
        icon_lbl = QLabel()
        if self._ransomware:
            icon_lbl.setPixmap(render_svg("shield", QColor(213, 0, 0), 36))
        else:
            icon_lbl.setPixmap(render_svg("shield", QColor(0, 120, 212), 36))
        icon_lbl.setFixedSize(36, 36)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(icon_lbl, alignment=Qt.AlignmentFlag.AlignCenter)
        if self._ransomware:
            title = QLabel("勒索软件行为拦截")
            title.setStyleSheet("color: #D50000; background: transparent;")
        else:
            title = QLabel("文件防护提示")
            title.setStyleSheet("color: #1a1a1a; background: transparent;")
        title.setFont(QFont("Microsoft YaHei", 13, QFont.Weight.DemiBold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(title)
        if self._ransomware:
            subtitle = QLabel("检测到3秒内快速修改多个文件，疑似勒索软件加密行为，已挂起相关进程")
            subtitle.setStyleSheet("color: #D50000; background: transparent;")
        else:
            subtitle = QLabel("检测到短时间内大量文件操作，可能存在风险")
            subtitle.setStyleSheet("color: #616161; background: transparent;")
        subtitle.setFont(QFont("Microsoft YaHei", 9))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        subtitle.setMaximumWidth(440)
        cl.addWidget(subtitle)
        if proc_name:
            proc_frame = QFrame()
            proc_frame.setStyleSheet("QFrame { background: #fff3e0; border-radius: 8px; }")
            pl = QHBoxLayout(proc_frame)
            pl.setContentsMargins(14, 6, 14, 6)
            pl.setSpacing(8)
            proc_icon = QLabel()
            proc_icon.setPixmap(render_svg("terminal", QColor(230, 81, 0), 16))
            proc_icon.setFixedSize(16, 16)
            pl.addWidget(proc_icon)
            proc_text = QLabel("操作进程：{} (PID:{})".format(proc_name, proc_pid))
            proc_text.setFont(QFont("Microsoft YaHei", 9))
            proc_text.setStyleSheet("color: #e65100; background: transparent;")
            pl.addWidget(proc_text, 1)
            cl.addWidget(proc_frame)
            if proc_path:
                path_lbl = QLabel()
                _fm_path = QFontMetrics(QFont("Consolas", 8))
                path_lbl.setText(_fm_path.elidedText(proc_path, Qt.TextElideMode.ElideMiddle, 430))
                path_lbl.setToolTip(proc_path)
                path_lbl.setFont(QFont("Consolas", 8))
                path_lbl.setStyleSheet("color: #9e9e9e; background: transparent; padding-left: 4px;")
                cl.addWidget(path_lbl)
        else:
            noprok_frame = QFrame()
            noprok_frame.setStyleSheet("QFrame { background: #e3f2fd; border-radius: 8px; }")
            nl = QHBoxLayout(noprok_frame)
            nl.setContentsMargins(14, 6, 14, 6)
            nl.setSpacing(8)
            noprok_icon = QLabel()
            noprok_icon.setPixmap(render_svg("shield", QColor(0, 120, 212), 16))
            noprok_icon.setFixedSize(16, 16)
            nl.addWidget(noprok_icon)
            noprok_text = QLabel("未检测到操作进程，可选择回滚文件操作")
            noprok_text.setFont(QFont("Microsoft YaHei", 9))
            noprok_text.setStyleSheet("color: #0078D4; background: transparent;")
            nl.addWidget(noprok_text, 1)
            cl.addWidget(noprok_frame)
        stat_frame = QFrame()
        stat_frame.setStyleSheet("QFrame { background: #f5f5f5; border-radius: 8px; }")
        sl = QHBoxLayout(stat_frame)
        sl.setContentsMargins(16, 6, 16, 6)
        sl.setSpacing(0)
        for label_text, val, color in [("创建", creates, "#107c10"), ("删除", deletes, "#d13438"), ("修改", modifies, "#0078D4"), ("移动", renames, "#ca5010")]:
            col = QVBoxLayout()
            col.setSpacing(2)
            num_lbl = QLabel(str(val))
            num_lbl.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.DemiBold))
            num_lbl.setStyleSheet(f"color: {color}; background: transparent;")
            num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(num_lbl)
            txt_lbl = QLabel(label_text)
            txt_lbl.setFont(QFont("Microsoft YaHei", 8))
            txt_lbl.setStyleSheet("color: #9e9e9e; background: transparent;")
            txt_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(txt_lbl)
            sl.addLayout(col)
        cl.addWidget(stat_frame)
        recent_lbl = QLabel("最近操作文件：")
        recent_lbl.setFont(QFont("Microsoft YaHei", 9))
        recent_lbl.setStyleSheet("color: #9e9e9e; background: transparent;")
        cl.addWidget(recent_lbl)
        _fm_file = QFontMetrics(QFont("Consolas", 8))
        for fp in files[:5]:
            item = QLabel(_fm_file.elidedText(fp, Qt.TextElideMode.ElideMiddle, 420))
            item.setToolTip(fp)
            item.setFont(QFont("Consolas", 8))
            item.setStyleSheet("color: #616161; background: #f5f5f5; border-radius: 4px; padding: 3px 8px;")
            cl.addWidget(item)
        cl.addStretch()
        combo_lbl = QLabel("处理方式：")
        combo_lbl.setFont(QFont("Microsoft YaHei", 9))
        combo_lbl.setStyleSheet("color: #616161; background: transparent;")
        cl.addWidget(combo_lbl)
        self._combo = QComboBox()
        self._combo.setFont(QFont("Microsoft YaHei", 9))
        self._combo.addItem("回滚并终止")
        self._combo.addItem("仅回滚")
        self._combo.addItem("忽略")
        self._combo.setStyleSheet("QComboBox { background: #ffffff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 6px 10px; color: #1a1a1a; } QComboBox::drop-down { border: none; width: 20px; } QComboBox QAbstractItemView { background: #ffffff; border: 1px solid #e0e0e0; selection-background-color: #0078D4; selection-color: #ffffff; }")
        cl.addWidget(self._combo)
        layout.addWidget(content, 1)
        footer = QWidget()
        footer.setFixedHeight(56)
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(32, 8, 32, 8)
        fl.setSpacing(10)
        fl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn = QPushButton("确认")
        btn.setFixedHeight(34)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        btn.setStyleSheet("QPushButton { background: #0078D4; color: #ffffff; border: none; border-radius: 6px; padding: 0 30px; min-width: 100px; } QPushButton:hover { background: #1a86d9; }")
        btn.clicked.connect(self._on_confirm)
        fl.addWidget(btn)
        layout.addWidget(footer)
        bottom = QWidget()
        bottom.setFixedHeight(20)
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(14, 0, 14, 4)
        bl.setSpacing(0)
        ver = QLabel("SevenEndPointSecurity")
        ver.setFont(QFont("Microsoft YaHei", 8))
        ver.setStyleSheet("color: rgba(158,158,158,180); background: transparent;")
        bl.addWidget(ver)
        bl.addStretch()
        tech = QLabel("文件防护")
        tech.setFont(QFont("Microsoft YaHei", 8))
        tech.setStyleSheet("color: rgba(158,158,158,180); background: transparent;")
        bl.addWidget(tech)
        layout.addWidget(bottom)

    def _on_confirm(self):
        idx = self._combo.currentIndex()
        if idx == 0:
            self._result_action = "rollback_terminate"
        elif idx == 1:
            self._result_action = "rollback"
        else:
            self._result_action = "ignore"
        self.accept()

    def eventFilter(self, obj, event):
        if obj is getattr(self, '_drag_bar', None):
            if event.type() == event.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                self._drag_offset = event.globalPosition().toPoint() - self.pos()
                return True
            elif event.type() == event.Type.MouseMove and self._drag_offset is not None:
                if event.buttons() & Qt.MouseButton.LeftButton:
                    self.move(event.globalPosition().toPoint() - self._drag_offset)
                    return True
            elif event.type() == event.Type.MouseButtonRelease:
                self._drag_offset = None
                return True
        return super().eventFilter(obj, event)

    def start_animation(self):
        end_pos = self._container.pos()
        start_pos = QPoint(end_pos.x(), end_pos.y() + 48)
        self._container.move(start_pos)
        self._pos_anim.setStartValue(start_pos)
        self._pos_anim.setEndValue(end_pos)
        self._fade_anim.start()
        self._pos_anim.start()

    def exec(self):
        self.show()
        self.raise_()
        self.activateWindow()
        return 0

    def showEvent(self, event):
        super().showEvent(event)
        _apply_rounded_mask(self, 12)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _apply_rounded_mask(self, 12)


class ScanProgressDialog(QDialog):
    scan_complete = pyqtSignal(str, int, str)
    dialog_closed = pyqtSignal(bool, str)

    def __init__(self, pid, name, path, monitor, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self._pid = pid
        self._name = name
        self._path = path
        self._monitor = monitor
        self._parent_win = parent
        self._result_action = "allow"
        self._should_resume = True
        self._drag_offset = None
        self._countdown = 120
        self._scanning = True
        self._threat_type = ""
        self._confidence = 0
        self._engine = "SE"
        self._vt = ""
        self.resize(520, 430)
        self.setWindowOpacity(0.0)
        self.setStyleSheet("ScanProgressDialog { background: #ffffff; border: 1px solid #e0e0e0; border-radius: 12px; }")
        self._container = QWidget(self)
        self._container.setStyleSheet("background: transparent; border: none;")
        cl = QVBoxLayout(self._container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        self._build_ui(cl)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._container)
        self._pos_anim = QPropertyAnimation(self._container, b"pos", self)
        self._pos_anim.setDuration(260)
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setDuration(260)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self.scan_complete.connect(self._on_scan_complete)
        t = threading.Thread(target=self._scan_thread, daemon=True)
        t.start()
        self._cd_timer = QTimer(self)
        self._cd_timer.timeout.connect(self._tick_countdown)
        self._cd_timer.start(1000)

    def _build_ui(self, layout):
        drag_bar = QFrame()
        drag_bar.setFixedHeight(32)
        drag_bar.setCursor(Qt.CursorShape.SizeAllCursor)
        drag_bar.setStyleSheet("QFrame { background: transparent; border: none; }")
        drag_bar.installEventFilter(self)
        self._drag_bar = drag_bar
        dl = QHBoxLayout(drag_bar)
        dl.setContentsMargins(16, 0, 16, 0)
        dl.setSpacing(0)
        brand = QLabel("SevenEndPointSecurity")
        brand.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.DemiBold))
        brand.setStyleSheet("color: #0078D4; background: transparent;")
        dl.addWidget(brand)
        dl.addStretch()
        layout.addWidget(drag_bar)
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(32, 4, 32, 4)
        cl.setSpacing(8)
        self._icon = _ScanAnimIcon()
        cl.addWidget(self._icon, alignment=Qt.AlignmentFlag.AlignCenter)
        self._title = QLabel("我们需要确保此文件是否安全")
        self._title.setFont(QFont("Microsoft YaHei", 12))
        self._title.setStyleSheet("color: #1a1a1a; background: transparent;")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setWordWrap(True)
        self._title.setMaximumWidth(440)
        cl.addWidget(self._title)
        self._subtitle = QLabel("为了确保此文件对您的计算机是否有害，我们已将其发送至病毒实验室进行检测")
        self._subtitle.setFont(QFont("Microsoft YaHei", 9))
        self._subtitle.setStyleSheet("color: #616161; background: transparent;")
        self._subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle.setWordWrap(True)
        self._subtitle.setMaximumWidth(440)
        cl.addWidget(self._subtitle)
        file_info = QFrame()
        file_info.setStyleSheet("QFrame { background: #f5f5f5; border-radius: 8px; }")
        fl = QHBoxLayout(file_info)
        fl.setContentsMargins(14, 6, 14, 6)
        fl.setSpacing(8)
        file_icon_lbl = QLabel()
        file_icon_lbl.setPixmap(render_svg("file", QColor(158, 158, 158), 16))
        file_icon_lbl.setFixedSize(16, 16)
        fl.addWidget(file_icon_lbl)
        _fm_name = QFontMetrics(QFont("Consolas", 9))
        fname_lbl = QLabel(_fm_name.elidedText(os.path.basename(self._path), Qt.TextElideMode.ElideMiddle, 400))
        fname_lbl.setToolTip(self._path)
        fname_lbl.setFont(QFont("Consolas", 9))
        fname_lbl.setStyleSheet("color: #616161; background: transparent;")
        fl.addWidget(fname_lbl, 1)
        cl.addWidget(file_info)
        self._progress = _SlidingProgress()
        cl.addWidget(self._progress)
        self._status_lbl = QLabel(f"预计等待 {self._countdown} 秒")
        self._status_lbl.setFont(QFont("Microsoft YaHei", 8))
        self._status_lbl.setStyleSheet("color: #9e9e9e; background: transparent;")
        self._status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_lbl.setMinimumHeight(16)
        cl.addWidget(self._status_lbl)
        layout.addWidget(content, 1)
        self._footer = QWidget()
        self._footer.setFixedHeight(50)
        self._footer.setVisible(False)
        self._footer_layout = QHBoxLayout(self._footer)
        self._footer_layout.setContentsMargins(32, 4, 32, 4)
        self._footer_layout.setSpacing(10)
        self._footer_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._footer)
        bottom = QWidget()
        bottom.setFixedHeight(20)
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(14, 0, 14, 4)
        bl.setSpacing(0)
        ver = QLabel("SevenEndPointSecurity")
        ver.setFont(QFont("Microsoft YaHei", 8))
        ver.setStyleSheet("color: rgba(158,158,158,180); background: transparent;")
        bl.addWidget(ver)
        bl.addStretch()
        tech = QLabel("可疑文件扫描")
        tech.setFont(QFont("Microsoft YaHei", 8))
        tech.setStyleSheet("color: rgba(158,158,158,180); background: transparent;")
        bl.addWidget(tech)
        layout.addWidget(bottom)

    def _tick_countdown(self):
        if not self._scanning:
            return
        self._countdown -= 1
        if self._countdown > 0:
            self._status_lbl.setText(f"预计等待 {self._countdown} 秒")
        else:
            self._status_lbl.setText("正在获取结果...")

    def _scan_thread(self):
        try:
            res, conf, vt = self._monitor._scan_file_subprocess(self._path, quick=True, timeout=10)
            if res.startswith("MALICIOUS"):
                self.scan_complete.emit(res, conf, vt)
                return
            res, conf, vt = self._monitor._scan_file_subprocess(self._path, quick=False, timeout=60)
        except Exception:
            res, conf, vt = "ERROR", 0, ""
        self.scan_complete.emit(res, conf, vt)

    def _on_scan_complete(self, res, conf, vt):
        self._scanning = False
        self._cd_timer.stop()
        if res.startswith("MALICIOUS"):
            self._should_resume = False
            self._vt = vt
            self._confidence = conf
            parts = res.split("|")
            if len(parts) >= 3:
                self._engine = parts[2]
            if len(parts) >= 2:
                self._threat_type = parts[1]
            else:
                self._threat_type = "MALICIOUS"
            chain = self._monitor._terminate_chain(self._pid, self._name, self._path)
            chain_desc = " -> ".join(f"{n}({p})" for n, p, _ in chain) if len(chain) > 1 else self._name
            _log(f"[拦截-进程] {chain_desc} {self._path} [{vt}] {conf}% ({self._engine})")
            _scan_log(f"[拦截-进程] {self._name} {self._path} [{vt}] {conf}%")
            _record_interception('进程拦截', self._name, self._path, threat_type=vt, confidence=conf, engine=self._engine, action='terminated', extra=f'PID:{self._pid} 链:{chain_desc}')
            _record_behavior(self._pid, self._name, self._path, 0, '扫描确认恶意', f'{vt} {conf}% {self._engine}')
            self._show_threat_result()
        elif res == "ERROR":
            self._should_resume = False
            self._show_error_result()
        else:
            self._should_resume = True
            self._show_safe_result()

    def _clear_footer(self):
        while self._footer_layout.count():
            item = self._footer_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _make_btn(self, text, bg, fg, border=None):
        btn = QPushButton(text)
        btn.setFixedHeight(34)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        style = f"QPushButton {{ background: {bg}; color: {fg}; border: none; border-radius: 6px; padding: 0 20px; min-width: 100px; }} QPushButton:hover {{ opacity: 0.85; }}"
        if border:
            style = f"QPushButton {{ background: {bg}; color: {fg}; border: 1px solid {border}; border-radius: 6px; padding: 0 20px; min-width: 100px; }} QPushButton:hover {{ background: #f5f5f5; }}"
        btn.setStyleSheet(style)
        return btn

    def _show_safe_result(self):
        self._icon.set_mode("safe")
        self._progress.set_color(QColor(16, 185, 129))
        self._progress.setVisible(False)
        self._status_lbl.setText("")
        self._title.setText("很好，文件正常")
        self._title.setStyleSheet("color: #10b981; background: transparent;")
        self._subtitle.setText("云端沙箱分析确认此文件安全，可以放心运行")
        self._clear_footer()
        btn = self._make_btn("启动程序", "#10b981", "#ffffff")
        btn.clicked.connect(self._on_allow)
        self._footer_layout.addWidget(btn)
        self._footer.setVisible(True)

    def _show_threat_result(self):
        self._icon.set_mode("danger")
        self._progress.set_color(QColor(209, 52, 56))
        self._progress.setVisible(False)
        self._status_lbl.setText("")
        self._title.setText("文件危险")
        self._title.setStyleSheet("color: #D13438; background: transparent;")
        threat_desc = f"检测到恶意软件：{self._vt}（置信度 {self._confidence}%）"
        self._subtitle.setText(threat_desc)
        self._subtitle.setMaximumWidth(420)
        self._clear_footer()
        btn_ignore = self._make_btn("忽略", "transparent", "#616161", "#e0e0e0")
        btn_ignore.clicked.connect(self._on_ignore)
        self._footer_layout.addWidget(btn_ignore)
        btn_delete = self._make_btn("删除", "#D13438", "#ffffff")
        btn_delete.clicked.connect(self._on_delete)
        self._footer_layout.addWidget(btn_delete)
        btn_quarantine = self._make_btn("隔离", "#0078D4", "#ffffff")
        btn_quarantine.clicked.connect(self._on_quarantine)
        self._footer_layout.addWidget(btn_quarantine)
        self._footer.setVisible(True)

    def _show_error_result(self):
        self._icon.set_mode("warning")
        self._progress.set_color(QColor(202, 138, 4))
        self._progress.setVisible(False)
        self._status_lbl.setText("")
        self._title.setText("分析超时")
        self._title.setStyleSheet("color: #CA8A04; background: transparent;")
        self._subtitle.setText("无法完成云端分析，建议拦截此文件以确保安全")
        self._clear_footer()
        btn_allow = self._make_btn("启动程序", "transparent", "#616161", "#e0e0e0")
        btn_allow.clicked.connect(self._on_allow)
        self._footer_layout.addWidget(btn_allow)
        btn_block = self._make_btn("拦截", "#D13438", "#ffffff")
        btn_block.clicked.connect(self._on_block)
        self._footer_layout.addWidget(btn_block)
        self._footer.setVisible(True)

    def _on_allow(self):
        self._result_action = "allow"
        self._should_resume = True
        self._relaunch_process()
        self.accept()

    def _relaunch_process(self):
        try:
            mon = self._monitor
            if mon:
                with mon._dedup_lock:
                    mon._recent_scanned[self._path] = time.time()
                # 先解除拦截标记再重启,避免僵尸检查竞态击杀刚重启的进程
                with mon._terminated_lock:
                    mon._terminated_paths.discard(self._path.lower())
                # 标记用户放行:会话内不再拦截
                mon._mark_user_allowed(self._path)
            os.startfile(self._path)
            _log(f"[拦截-进程] 重新启动安全程序: {self._path}")
        except Exception as e:
            _log(f"[拦截-进程] 重新启动失败 {self._path}: {e}")
            QMessageBox.warning(self, "启动失败", f"无法重新启动该程序：\n{e}")

    def _on_block(self):
        self._result_action = "block"
        self._should_resume = False
        self.accept()

    def _on_quarantine(self):
        self._result_action = "quarantine"
        self._should_resume = False
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            dest = os.path.join(QUARANTINE_DIR, os.path.basename(self._path) + ".quarantine")
            shutil.move(self._path, dest)
            _scan_log(f"[实时-已隔离] {self._path}")
            _log(f"[实时拦截] 已隔离: {self._path}")
            if self._parent_win:
                self._parent_win._tray_show("威胁已隔离", f"{os.path.basename(self._path)} 已移至隔离区")
        except Exception as e:
            _log(f"[实时拦截] 隔离失败 {self._path}: {e}")
            QMessageBox.warning(self, "隔离失败", str(e))
        self.accept()

    def _on_delete(self):
        self._result_action = "delete"
        self._should_resume = False
        try:
            os.remove(self._path)
            _scan_log(f"[实时-已删除] {self._path}")
            _log(f"[实时拦截] 已删除: {self._path}")
            if self._parent_win:
                self._parent_win._tray_show("威胁已删除", f"{os.path.basename(self._path)} 已删除")
        except Exception as e:
            _log(f"[实时拦截] 删除失败 {self._path}: {e}")
            QMessageBox.warning(self, "删除失败", str(e))
        self.accept()

    def _on_ignore(self):
        self._result_action = "ignore"
        self._should_resume = False
        _scan_log(f"[实时-已忽略] {self._path}")
        _log(f"[实时拦截] 用户忽略: {self._path}")
        self.reject()

    def eventFilter(self, obj, event):
        if obj is getattr(self, '_drag_bar', None):
            if event.type() == event.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                self._drag_offset = event.globalPosition().toPoint() - self.pos()
                return True
            elif event.type() == event.Type.MouseMove and self._drag_offset is not None:
                if event.buttons() & Qt.MouseButton.LeftButton:
                    self.move(event.globalPosition().toPoint() - self._drag_offset)
                    return True
            elif event.type() == event.Type.MouseButtonRelease:
                self._drag_offset = None
                return True
        return super().eventFilter(obj, event)

    def start_animation(self):
        end_pos = self._container.pos()
        start_pos = QPoint(end_pos.x(), end_pos.y() + 48)
        self._container.move(start_pos)
        self._pos_anim.setStartValue(start_pos)
        self._pos_anim.setEndValue(end_pos)
        self._fade_anim.start()
        self._pos_anim.start()

    def exec(self):
        self.show_nonmodal()
        return 0

    def showEvent(self, event):
        super().showEvent(event)
        _apply_rounded_mask(self, 12)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _apply_rounded_mask(self, 12)

    def show_nonmodal(self):
        QTimer.singleShot(10, self.start_animation)
        self.show()
        self.raise_()
        self.activateWindow()


class FileMonitor:
    def __init__(self, parent_window):
        self._parent = parent_window
        self._proc = None
        self._proc_lock = threading.Lock()
        self._stop_flag = threading.Event()
        self._reader_thread = None
        self._trusted_dirs = set()
        self._dialog_active = False
        self._rollback_event = threading.Event()
        self._rollback_count = 0

    def start(self):
        if self._proc:
            return
        self._stop_flag.clear()
        _env = dict(os.environ)
        _env['PYTHONIOENCODING'] = 'utf-8'
        try:
            self._proc = subprocess.Popen(
                _file_monitor_cmd(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=1, text=True,
                encoding='utf-8', errors='replace', cwd=BASE_DIR, env=_env
            )
        except Exception as e:
            _log("[文件监控] 启动子进程失败: {}".format(e))
            self._proc = None
            return
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()
        self._send_whitelist()
        self._send_config()

    def _send_whitelist(self):
        try:
            wl_paths = []
            if g_scanner is not None and g_scanner.whitelist:
                with g_scanner.whitelist.lock:
                    wl_paths = list(g_scanner.whitelist.paths)[:500]
            cmd = {"cmd": "set_whitelist", "paths": wl_paths}
            self._send_command(cmd)
        except Exception:
            pass

    def _send_config(self):
        try:
            self._send_command({"cmd": "set_config", "key": "file_protect", "value": g_settings.get("file_protect", True)})
            self._send_command({"cmd": "set_config", "key": "file_modify_monitor", "value": g_settings.get("file_modify_monitor", True)})
        except Exception:
            pass

    def _read_stderr(self):
        proc = self._proc
        if not proc:
            return
        while not self._stop_flag.is_set():
            try:
                line = proc.stderr.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if line:
                _log("[文件监控子进程] {}".format(line))

    def _send_command(self, cmd_dict):
        with self._proc_lock:
            if not self._proc or not self._proc.stdin:
                return
            try:
                self._proc.stdin.write(json.dumps(cmd_dict, ensure_ascii=False) + "\n")
                self._proc.stdin.flush()
            except Exception:
                pass

    def _read_loop(self):
        proc = self._proc
        if not proc:
            return
        while not self._stop_flag.is_set():
            try:
                line = proc.stdout.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("type") == "file_op_alert":
                count = msg.get("count", 0)
                creates = msg.get("creates", 0)
                deletes = msg.get("deletes", 0)
                modifies = msg.get("modifies", 0)
                renames = msg.get("renames", 0)
                files = msg.get("files", [])
                ops = msg.get("ops", [])
                proc_name = msg.get("proc_name", "")
                proc_pid = msg.get("proc_pid", 0)
                proc_path = msg.get("proc_path", "")
                ransomware = msg.get("ransomware", False)
                _gui_queue.put(lambda c=count, cr=creates, d=deletes, m=modifies, r=renames, f=list(files),
                               o=list(ops), pn=proc_name, pp=proc_pid, ppath=proc_path, rw=ransomware:
                               self._show_dialog(c, cr, d, m, r, f, o, pn, pp, ppath, rw))
            elif msg.get("type") == "rollback_result":
                self._rollback_count = msg.get("count", 0)
                self._rollback_failed = msg.get("failed", 0)
                self._rollback_failed_files = msg.get("failed_files", [])
                self._rollback_event.set()

    def _show_dialog(self, count, creates, deletes, modifies, renames, files, ops, proc_name, proc_pid, proc_path, ransomware=False):
        """托盘模式: 文件操作达阈值(20) -> 自动回滚 + 终止整链 + Ransom Block 通知(无需确认)。"""
        try:
            _log("[拦截-文件] 批量文件操作达到阈值({}次), 自动回滚+终止: {}".format(count, proc_name))
            _record_behavior(proc_pid, proc_name or '未知', proc_path or '', 0, '文件操作', f'创建:{creates} 删除:{deletes} 修改:{modifies} 重命名:{renames}')
            _edr_add_event(proc_pid, proc_name or 'Unknown.exe', proc_path or '', 'ransom_op', 5,
                           'Mass file ops x{}: create={} delete={} modify={} rename={}'.format(count, creates, deletes, modifies, renames))
            _record_interception('文件防护(勒索)', proc_name or 'Unknown.exe', proc_path or '',
                                 threat_type='Ransomware', action='blocked',
                                 extra='PID:{} 操作{}次(创建{} 删除{} 修改{} 重命名{})'.format(proc_pid, count, creates, deletes, modifies, renames))
            _notify("Ransom Block", "Ransom Block {}".format(proc_name or 'Unknown.exe'))
            # 自动回滚全部操作 + 终止整条进程链
            threading.Thread(target=self._do_rollback_and_terminate,
                             args=(ops, files, proc_name, proc_pid, proc_path, True),
                             daemon=True).start()
        except Exception as e:
            _log("[文件监控] 处理异常: {}".format(e))
            self._send_command({"cmd": "resume"})

    def _do_rollback_and_terminate(self, ops, files, proc_name, proc_pid, proc_path, ransomware=False):
        try:
            if proc_pid and proc_name and proc_name.lower() not in self._IDE_EXEMPT_NAMES:
                rm = getattr(self._parent, '_realtime_monitor', None)
                if rm:
                    chain = rm._terminate_chain(proc_pid, proc_name, proc_path, full=True)
                    if chain:
                        _log("[拦截-文件] 回滚并终止进程链: {}({}) {}".format(proc_name, proc_pid, proc_path))
                        _record_behavior(proc_pid, proc_name or '未知', proc_path or '', 0, '文件防护终止', f'回滚并终止 共{len(chain)}个进程')
                        for t_name, t_pid, t_path, t_access in chain:
                            _record_behavior(t_pid, t_name, t_path, proc_pid, '进程终止', f'文件防护 权限:0x{t_access:04x}')
                        if ransomware:
                            _record_interception('文件防护(勒索)', proc_name or '未知', proc_path or '',
                                threat_type='Ransomware', action='terminated',
                                extra=f'PID:{proc_pid} 回滚{len(ops)}个文件 终止{len(chain)}个进程')
                        else:
                            _record_interception('文件防护', proc_name or '未知', proc_path or '',
                                action='terminated',
                                extra=f'PID:{proc_pid} 回滚{len(ops)}个文件 终止{len(chain)}个进程')
            else:
                self._block_suspicious_processes(files)
            self._rollback_event.clear()
            self._rollback_count = 0
            self._rollback_failed = 0
            self._rollback_failed_files = []
            self._send_command({"cmd": "rollback", "ops": ops})
            self._rollback_event.wait(timeout=10)
            _failed = getattr(self, '_rollback_failed', 0)
            _log("[文件防护] 用户选择回滚并终止 {} 个文件操作, 实际回滚 {} 个, 失败 {} 个".format(
                len(ops), self._rollback_count, _failed))
            if _failed > 0:
                _ff = getattr(self, '_rollback_failed_files', [])
                _log("[文件防护] 回滚失败文件(无备份且无VSS): {}".format('; '.join(_ff[:5])))
            self._send_command({"cmd": "resume"})
        except Exception as e:
            _log("[文件防护] 回滚并终止异常: {}".format(e))

    def _do_rollback(self, ops, files, proc_name, proc_pid, proc_path):
        try:
            if proc_pid and proc_name and proc_name.lower() not in self._IDE_EXEMPT_NAMES:
                rm = getattr(self._parent, '_realtime_monitor', None)
                if rm:
                    chain = rm._terminate_chain(proc_pid, proc_name, proc_path, full=True)
                    if chain:
                        _log("[拦截-文件] 回滚前终止进程链: {}({}) {}".format(proc_name, proc_pid, proc_path))
                        _record_behavior(proc_pid, proc_name or '未知', proc_path or '', 0, '文件防护终止', f'仅回滚 终止{len(chain)}个进程')
                        for t_name, t_pid, t_path, t_access in chain:
                            _record_behavior(t_pid, t_name, t_path, proc_pid, '进程终止', f'文件防护 权限:0x{t_access:04x}')
            else:
                self._block_suspicious_processes(files)
            self._rollback_event.clear()
            self._rollback_count = 0
            self._rollback_failed = 0
            self._rollback_failed_files = []
            self._send_command({"cmd": "rollback", "ops": ops})
            self._rollback_event.wait(timeout=10)
            _failed = getattr(self, '_rollback_failed', 0)
            _log("[文件防护] 用户选择回滚 {} 个文件操作, 实际回滚 {} 个, 失败 {} 个".format(
                len(ops), self._rollback_count, _failed))
            if _failed > 0:
                _ff = getattr(self, '_rollback_failed_files', [])
                _log("[文件防护] 回滚失败文件(无备份且无VSS): {}".format('; '.join(_ff[:5])))
            self._send_command({"cmd": "resume"})
        except Exception as e:
            _log("[文件防护] 回滚异常: {}".format(e))

    _IDE_EXEMPT_NAMES = {"code.exe", "code - insiders.exe", "devenv.exe", "idea64.exe",
                         "idea.exe", "pycharm64.exe", "pycharm.exe", "webstorm64.exe",
                         "goland64.exe", "clion64.exe", "rider64.exe", "phpstorm64.exe",
                         "rubymine64.exe", "datagrip64.exe", "studio64.exe",
                         "trae.exe", "trae cn.exe", "trae so lo cn.exe", "cursor.exe",
                         "windsurf.exe", "zed.exe", "atom.exe", "sublime_text.exe",
                         "notepad++.exe", "vim.exe", "emacs.exe", "gvim.exe"}

    def _block_suspicious_processes(self, files):
        try:
            rm = getattr(self._parent, '_realtime_monitor', None)
            if not rm:
                return
            procs = rm._enum_processes()
            my_pid = os.getpid()
            parent_pid = 0
            my_info = procs.get(my_pid)
            if my_info:
                parent_pid = my_info[2]
            system_pids = set()
            for pid, info in list(procs.items()):
                p_name, p_path, _ = info
                if not p_path or is_system_path(p_path):
                    system_pids.add(pid)
                if p_name and p_name.lower() in self._IDE_EXEMPT_NAMES:
                    system_pids.add(pid)
            system_pids.add(my_pid)
            if parent_pid:
                system_pids.add(parent_pid)
            file_dirs = set()
            for fp in files:
                d = os.path.dirname(fp).lower()
                if d:
                    file_dirs.add(d)
            killed = []
            for pid, info in list(procs.items()):
                if pid in system_pids:
                    continue
                p_name, p_path, _ = info
                if not p_path:
                    continue
                p_lower = p_path.lower()
                should_kill = False
                for fd in file_dirs:
                    if fd in p_lower:
                        should_kill = True
                        break
                if should_kill:
                    chain = rm._terminate_chain(pid, p_name, p_path)
                    if chain:
                        killed.append((p_name, pid, p_path))
                        _record_behavior(pid, p_name, p_path, 0, '文件防护终止', f'阻止可疑进程 权限:0x{chain[0][3]:04x}' if chain else '')
                        for t_name, t_pid, t_path, t_access in chain:
                            _record_behavior(t_pid, t_name, t_path, pid, '进程终止', f'文件防护 权限:0x{t_access:04x}')
            if killed:
                for name, pid, path in killed:
                    _log("[拦截-文件] 终止进程 {}({}) {}".format(name, pid, path))
        except Exception as e:
            _log("[文件防护] 拦截进程异常: {}".format(e))

    def stop(self):
        self._stop_flag.set()
        with self._proc_lock:
            if self._proc:
                try:
                    self._proc.kill()
                except Exception:
                    pass
                self._proc = None


class EtwBetaNoticeDialog(QDialog):
    """遥测拦截开启前的全屏测试版提示。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        screen = QApplication.primaryScreen().geometry()
        self.setFixedSize(screen.width(), screen.height())
        self.move(screen.topLeft())
        self.setStyleSheet("EtwBetaNoticeDialog { background: rgba(8, 12, 20, 244); border: none; }")
        root = QVBoxLayout(self)
        root.addStretch()
        card = QFrame()
        card.setFixedSize(580, 470)
        card.setStyleSheet("QFrame#betaCard { background: #141d2b; border: 1px solid #2c3d57; border-radius: 16px; }")
        card.setObjectName("betaCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(44, 38, 44, 32)
        cl.setSpacing(14)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(render_svg("shield_alert", QColor(255, 184, 0), 56))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("background: transparent;")
        cl.addWidget(icon_lbl)
        title = QLabel("端点防护")
        title.setFont(QFont("Microsoft YaHei", 16, QFont.Weight.DemiBold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ffffff; background: transparent;")
        cl.addWidget(title)
        warn = QLabel("你正在试图启动一个测试功能")
        warn.setFont(QFont("Microsoft YaHei", 10))
        warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warn.setStyleSheet("color: #ffb800; background: transparent;")
        cl.addWidget(warn)
        body = QLabel(
            "测试功能的风险有误报、不稳定等\n\n"
            "请不要在日常使用中启动，本功能用于测试ETW和EPP防护")
        body.setFont(QFont("Microsoft YaHei", 9))
        body.setWordWrap(True)
        body.setStyleSheet("color: #b8c4d6; background: transparent; line-height: 160%;")
        cl.addWidget(body)
        cl.addSpacing(8)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        btn_cancel = QPushButton("取消")
        btn_cancel.setFixedHeight(38)
        btn_cancel.setMinimumWidth(120)
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.setStyleSheet("QPushButton { background: transparent; color: #8fa0b8; border: 1px solid #33455f; border-radius: 8px; padding: 0 24px; } QPushButton:hover { background: #1c2939; }")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("确认开启")
        btn_ok.setFixedHeight(38)
        btn_ok.setMinimumWidth(140)
        btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_ok.setStyleSheet("QPushButton { background: #ffb800; color: #1a1a1a; border: none; border-radius: 8px; padding: 0 24px; font-weight: 600; } QPushButton:hover { background: #ffc633; }")
        btn_ok.clicked.connect(self.accept)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        btn_row.addStretch()
        cl.addLayout(btn_row)
        root.addWidget(card, 0, Qt.AlignmentFlag.AlignCenter)
        root.addStretch()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(8, 12, 20, 244))
        super().paintEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            return
        super().keyPressEvent(event)


class EtwTelemetryMonitor:
    """ETW遥测拦截Worker管理:按Rules端点规则实时匹配。
    block命中 -> 终止整条攻击链 + 回滚落盘 + EDR样式告警; log命中 -> 仅入行为链。"""

    def __init__(self, parent_window):
        self._parent = parent_window
        self._proc = None
        self._proc_lock = threading.Lock()
        self._stop_flag = threading.Event()
        self._reader = None
        self._stderr = None
        self._dedup = {}
        self._dedup_lock = threading.Lock()

    def start(self):
        with self._proc_lock:
            if self._proc and self._proc.poll() is None:
                return
            self._stop_flag.clear()
            _env = dict(os.environ)
            _env['PYTHONIOENCODING'] = 'utf-8'
            try:
                self._proc = subprocess.Popen(
                    _etw_worker_cmd(),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=1, text=True,
                    encoding='utf-8', errors='replace', cwd=BASE_DIR, env=_env,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception as e:
                _log("[遥测拦截] Worker启动失败: {}".format(e))
                self._proc = None
                return
            self._reader = threading.Thread(target=self._read_loop, daemon=True, name='EtwTelemetry')
            self._reader.start()
            threading.Thread(target=self._read_stderr, daemon=True, name='EtwTelemetryErr').start()
            _log("[遥测拦截] ETW遥测Worker已启动")

    def stop(self):
        self._stop_flag.set()
        with self._proc_lock:
            if self._proc:
                try:
                    self._proc.kill()
                except Exception:
                    pass
                self._proc = None

    def _read_stderr(self):
        proc = self._proc
        if not proc or not proc.stderr:
            return
        while not self._stop_flag.is_set():
            try:
                line = proc.stderr.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if line:
                _log("[遥测Worker] {}".format(line[:300]))

    def _read_loop(self):
        proc = self._proc
        if not proc:
            return
        while not self._stop_flag.is_set():
            try:
                line = proc.stdout.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            mtype = msg.get("type")
            if mtype == "etw_alert":
                threading.Thread(target=self._handle_alert, args=(msg,), daemon=True).start()
            elif mtype == "etw_status":
                _log("[遥测拦截] {}".format(msg.get("msg", "")))
            elif mtype == "etw_error":
                _log("[遥测拦截] 错误: {}".format(msg.get("msg", "")))
                self._tray_warn(msg.get("msg", "ETW遥测Worker异常"))

    def _tray_warn(self, text):
        try:
            w = self._parent
            if hasattr(w, '_tray_show'):
                _gui_queue.put(lambda t=text: w._tray_show("遥测拦截", t))
        except Exception:
            pass

    def _handle_alert(self, msg):
        rule = msg.get("rule", "")
        kind = msg.get("kind", "")
        action = (msg.get("action") or "log").lower()
        severity = int(msg.get("severity") or 0)
        pid = int(msg.get("pid") or 0)
        ppid = int(msg.get("ppid") or 0)
        name = msg.get("name", "")
        path = msg.get("path", "")
        proc_name = msg.get("proc_name", "")
        proc_path = msg.get("proc_path", "")
        detail = msg.get("detail", "")
        note = msg.get("note", "")

        key = (rule, (path or detail or "").lower())
        now = time.time()
        with self._dedup_lock:
            if now - self._dedup.get(key, 0) < 60:
                return
            self._dedup[key] = now
            if len(self._dedup) > 500:
                self._dedup = {k: t for k, t in self._dedup.items() if now - t < 300}

        if action == "block" and severity >= 60 and pid:
            rm = getattr(self._parent, '_realtime_monitor', None)
            chain_desc = name or ''
            if rm:
                try:
                    chain = rm._terminate_chain(pid, name or os.path.basename(path) or 'unknown',
                                                path or '', full=True)
                    chain_desc = " -> ".join(f"{n}({p})" for n, p, _ in chain) or name
                except Exception:
                    pass
            _log(f"[遥测拦截] {rule} {kind} {name}({pid}) {path} {detail}")
            _scan_log(f"[遥测拦截] {rule} [{kind}] {name} 严重度:{severity}")
            _record_interception('遥测拦截(端点规则)', name or rule, path or detail,
                                 threat_type=rule, confidence=severity, engine='ETW遥测',
                                 action='terminated',
                                 extra=f'PID:{pid} 链:{chain_desc} 详情:{detail[:150]}')
            _record_behavior(pid, name or '未知', path or '', ppid, '遥测规则拦截',
                             f'{rule} {kind} {detail} {note}')
            # EDR 记分: 命中拦截规则 = 违规操作 +10
            _edr_add_event(pid, name or 'Unknown.exe', path or '', 'violation', 10,
                           'ETW rule hit [{}] {} {}'.format(rule, kind, detail))
            if ppid and ppid != pid:
                _record_behavior(ppid, proc_name or '未知', proc_path or '', 0,
                                 '攻击链父进程终止', f'遥测规则: {rule}')
                _edr_add_event(ppid, proc_name or 'Unknown.exe', proc_path or '', 'violation', 10,
                               'Child hit ETW rule [{}]'.format(rule))
            # 回滚该链落盘文件
            try:
                if rm and hasattr(rm, '_rollback_chain_drops'):
                    rb = rm._rollback_chain_drops({pid, ppid})
                    if rb:
                        _log(f"[遥测拦截-回滚] 已删除落盘文件 {len(rb)} 个")
            except Exception:
                pass
            done = threading.Event()
            _gui_queue.put(lambda: self._show_alert(pid, name, path or detail, severity,
                                                    [f"{rule}: {note or detail}"], done))
            done.wait(timeout=60)
        else:
            # log类规则:仅记录行为链; 敏感注册表/任务计划类命中计入 EDR 评分(+5/+10)
            _record_behavior(pid, name or proc_name or '未知', path or proc_path or '', ppid,
                             rule, f'{kind} {detail}'[:200])
            try:
                _k = (kind or '').lower()
                if _k.startswith('registry') and severity >= 50:
                    # 敏感注册表操作(非敏感不计入)
                    _edr_add_event(pid, name or proc_name or 'Unknown.exe', path or proc_path or '',
                                   'registry_sensitive', 5,
                                   'Sensitive registry: {} {}'.format(rule, detail))
                elif _k.startswith('process') and severity >= 60 and re.search(
                        r'schtasks|taskschd|reg\s+add|regedit|vssadmin|bcdedit|wbadmin|cipher\s+/w',
                        (detail or '').lower()):
                    _edr_add_event(pid, name or proc_name or 'Unknown.exe', path or proc_path or '',
                                   'task_sched', 10,
                                   'Persistence/system op: {}'.format(detail))
            except Exception:
                pass

    def _show_alert(self, pid, name, path, score, reasons, done_event):
        """托盘模式:ETW 拦截通知(与主防拦截一致), 拦截动作已在 _handle_alert 完成。"""
        try:
            _notify("Threat Block", "Threat Block {}".format(name or 'Unknown.exe'))
            _edr_report_chain(pid, name or 'Unknown.exe', path or '',
                              [('ETW rule hit', int(score or 0))] + [
                                  (str(r), 0) for r in (reasons or [])[:10]],
                              action='blocked')
        except Exception as e:
            _log(f"[遥测拦截] 通知异常: {e}")
        done_event.set()


class MBRGuard:
    """MBR保护:对 \\\\.\\PhysicalDrive0 前512字节做基线快照并周期校验。
    检测到篡改(引导型病毒/勒索软件/恶意驱动)立即告警,支持一键从基线恢复。
    基线仅在首次成功读取时建立,之后不随磁盘内容变化而更新。"""

    def __init__(self, parent_window):
        self._parent = parent_window
        self._stop = threading.Event()
        self._thread = None
        self._baseline = None
        self._baseline_lock = threading.Lock()
        self._alerted = False
        base_dir = os.path.join(BASE_DIR, 'Engine')
        try:
            os.makedirs(base_dir, exist_ok=True)
        except Exception:
            pass
        self._baseline_path = os.path.join(base_dir, 'mbr_guard.bak')

    # ---------------- 底层磁盘读写 ----------------
    def _open_disk(self, access):
        import ctypes
        from ctypes import wintypes
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        h = k32.CreateFileW("\\\\.\\PhysicalDrive0", access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            None, OPEN_EXISTING, 0, None)
        if not h or h == ctypes.c_void_p(-1).value:
            return None, k32
        return h, k32

    def _read_mbr(self):
        import ctypes
        from ctypes import wintypes
        h, k32 = self._open_disk(0x80000000)
        if not h:
            return None
        try:
            buf = ctypes.create_string_buffer(512)
            read = wintypes.DWORD(0)
            k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            if not k32.ReadFile(h, buf, 512, ctypes.byref(read), None) or read.value != 512:
                return None
            return buf.raw[:512]
        finally:
            try:
                k32.CloseHandle(h)
            except Exception:
                pass

    def _write_mbr(self, data):
        import ctypes
        from ctypes import wintypes
        h, k32 = self._open_disk(0x40000000)
        if not h:
            return False
        try:
            buf = ctypes.create_string_buffer(bytes(data), 512)
            written = wintypes.DWORD(0)
            k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            if not k32.WriteFile(h, buf, 512, ctypes.byref(written), None) or written.value != 512:
                return False
            try:
                k32.FlushFileBuffers(h)
            except Exception:
                pass
            return True
        finally:
            try:
                k32.CloseHandle(h)
            except Exception:
                pass

    # ---------------- 基线管理 ----------------
    def _load_or_create_baseline(self):
        with self._baseline_lock:
            if self._baseline is not None:
                return self._baseline
            try:
                if os.path.exists(self._baseline_path):
                    with open(self._baseline_path, 'rb') as f:
                        data = f.read(512)
                    if len(data) == 512:
                        self._baseline = data
                        return data
            except Exception:
                pass
            cur = self._read_mbr()
            if cur is None:
                return None
            self._baseline = cur
            try:
                with open(self._baseline_path, 'wb') as f:
                    f.write(cur)
                _log("[MBR保护] 已建立MBR基线快照")
            except Exception as e:
                _log(f"[MBR保护] 基线保存失败: {e}")
            return cur

    # ---------------- 主循环 ----------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='MBRGuard')
        self._thread.start()
        _log("[MBR保护] MBR防护已启动")

    def stop(self):
        self._stop.set()

    def _loop(self):
        fail_count = 0
        while not self._stop.is_set():
            try:
                baseline = self._load_or_create_baseline()
                if baseline is None:
                    # 无管理员权限或磁盘打开失败,降频重试
                    fail_count += 1
                    self._stop.wait(min(300, 30 * fail_count))
                    continue
                fail_count = 0
                cur = self._read_mbr()
                if cur is None:
                    self._stop.wait(60)
                    continue
                if cur != baseline:
                    self._handle_tamper(cur)
            except Exception:
                pass
            self._stop.wait(15)

    def _handle_tamper(self, cur):
        if self._alerted:
            return
        self._alerted = True
        cur_sha = hashlib.sha256(cur).hexdigest()[:16]
        _log(f"[MBR保护] 检测到MBR被篡改! 当前摘要:{cur_sha}")
        _record_interception('MBR保护', 'PhysicalDrive0 (MBR)', '', threat_type='Bootkit/MBR Tampering',
                             confidence=100, engine='MBRGuard', action='alerted',
                             extra='主引导记录被篡改,可能为勒索软件或引导型木马')
        _record_behavior(0, 'MBR篡改', '\\\\.\\PhysicalDrive0', 0, 'MBR被篡改', f'摘要:{cur_sha}')
        # 托盘模式: 自动从安全基线恢复 MBR, 不再弹窗询问
        with self._baseline_lock:
            data = self._baseline
        restored = False
        if data:
            restored = self._write_mbr(data)
        if restored:
            _log("[MBR保护] MBR已从基线自动恢复")
            _record_interception('MBR保护', 'PhysicalDrive0 (MBR)', '', threat_type='Bootkit/MBR Tampering',
                                 confidence=100, engine='MBRGuard', action='restored',
                                 extra='已从安全基线自动恢复MBR')
            _record_behavior(0, 'MBR篡改', '\\\\.\\PhysicalDrive0', 0, 'MBR已恢复', '已从基线恢复主引导记录')
        else:
            _log("[MBR保护] MBR自动恢复失败(需要管理员权限)")
        try:
            _name = _mbr_suspect_name()
            if restored:
                _notify("Threat Block", "Threat Block {}, Rolled back the MBR operation".format(_name))
            else:
                _notify("Threat Block", "Threat Block {}, MBR rollback failed (admin required)".format(_name))
        except Exception:
            pass


def _mbr_suspect_name():
    """尽力定位最近的可疑活动进程名(MBR 篡改源), 找不到则 Unknown.exe。"""
    try:
        with _g_behavior_lock:
            best, best_ts = None, 0.0
            for node in _g_behavior_tree.values():
                if not node.get('alive'):
                    continue
                nm = (node.get('name') or '').lower()
                p = (node.get('path') or '')
                if not nm or nm in EDR_EXEMPT_NAMES:
                    continue
                if p and is_system_path(p):
                    continue
                if node.get('last_seen', 0) > best_ts:
                    best, best_ts = node.get('name'), node.get('last_seen', 0)
        if best:
            return best
    except Exception:
        pass
    return 'Unknown.exe'


class RealtimeMonitor:
    def __init__(self, parent_window):
        self._parent = parent_window
        self._stop_flag = threading.Event()
        self._threads = []
        self._worker_script = None
        self._scan_proc = None
        self._proc_lock = threading.Lock()
        self._known_pids = set()
        self._self_pid = os.getpid()
        self._scan_exts = {'.exe', '.dll', '.sys', '.vbs', '.ps1', '.js', '.bat', '.cmd', '.py', '.pyw', '.scr', '.com', '.ocx', '.msi'}
        self._recent_scanned = {}
        self._dedup_lock = threading.Lock()
        self._terminated_paths = set()
        self._terminated_lock = threading.Lock()
        self._edr = None  # 由 PASWWindow 注入 BehaviorEDR 引用
        self._msi_scanned = {}  # msi路径 -> 上次分析时间(防重复扫描内嵌实例)
        self._user_allowed = {}  # 用户在扫描弹窗放行的路径 -> 时间(会话内信任1小时)
        self._init_native()
        self._seed_known_processes()

    def _init_native(self):
        self._native_ok = False
        try:
            import ctypes
            from ctypes import wintypes
            self._k32 = ctypes.windll.kernel32
            self._ntdll = ctypes.windll.ntdll
            self._k32.OpenProcess.restype = wintypes.HANDLE
            self._k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self._k32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._k32.TerminateProcess.restype = wintypes.BOOL
            self._k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self._k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            self._k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            self._k32.Process32FirstW.restype = wintypes.BOOL
            self._k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self._k32.Process32NextW.restype = wintypes.BOOL
            self._k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self._k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            self._k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            self._ntdll.NtSuspendProcess.restype = ctypes.c_long
            self._ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
            self._ntdll.NtResumeProcess.restype = ctypes.c_long
            self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
            self._ntdll.NtQueryInformationProcess.restype = ctypes.c_long
            self._ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            self._k32.ReadProcessMemory.restype = wintypes.BOOL
            self._k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
            self._k32.IsWow64Process.restype = wintypes.BOOL
            self._k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
            class _PE32(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD),
                            ("cntUsage", wintypes.DWORD),
                            ("th32ProcessID", wintypes.DWORD),
                            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                            ("th32ModuleID", wintypes.DWORD),
                            ("cntThreads", wintypes.DWORD),
                            ("th32ParentProcessID", wintypes.DWORD),
                            ("pcPriClassBase", ctypes.c_long),
                            ("dwFlags", wintypes.DWORD),
                            ("szExeFile", wintypes.WCHAR * 260)]
            self._PE32 = _PE32
            try:
                self._k32.OpenProcessToken.restype = wintypes.BOOL
                self._k32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
                self._advapi32 = ctypes.windll.advapi32
                self._advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
                self._advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_longlong)]
                self._advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
                self._advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
                self._advapi32.DuplicateTokenEx.restype = wintypes.BOOL
                self._advapi32.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
                self._k32.SetThreadToken.restype = wintypes.BOOL
                self._k32.SetThreadToken.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.HANDLE]
                class _LUID(ctypes.Structure):
                    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]
                class _TOKEN_PRIVILEGES(ctypes.Structure):
                    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                                ("Luid", _LUID),
                                ("Attributes", wintypes.DWORD)]
                hToken = wintypes.HANDLE()
                if self._k32.OpenProcessToken(self._k32.GetCurrentProcess(), 0x0020, ctypes.byref(hToken)):
                    luid = _LUID()
                    if self._advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                        tp = _TOKEN_PRIVILEGES()
                        tp.PrivilegeCount = 1
                        tp.Luid = luid
                        tp.Attributes = 0x00000002
                        self._advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
                    self._k32.CloseHandle(hToken)
            except:
                pass
            self._system_token = None
            try:
                snap = self._k32.CreateToolhelp32Snapshot(0x00000002, 0)
                _pe32 = self._PE32()
                _pe32.dwSize = ctypes.sizeof(self._PE32)
                _wl_pid = 0
                if self._k32.Process32FirstW(snap, ctypes.byref(_pe32)):
                    while True:
                        _n = _pe32.szExeFile
                        if _n and _n.lower() == 'winlogon.exe':
                            _wl_pid = _pe32.th32ProcessID
                            break
                        if not self._k32.Process32NextW(snap, ctypes.byref(_pe32)):
                            break
                self._k32.CloseHandle(snap)
                if _wl_pid:
                    _h_wl = self._k32.OpenProcess(0x0400, False, _wl_pid)
                    if _h_wl:
                        _h_tok = wintypes.HANDLE()
                        if self._k32.OpenProcessToken(_h_wl, 0x0002, ctypes.byref(_h_tok)):
                            _h_dup = wintypes.HANDLE()
                            if self._advapi32.DuplicateTokenEx(_h_tok, 0x0200, None, 2, 2, ctypes.byref(_h_dup)):
                                self._system_token = _h_dup.value
                            self._k32.CloseHandle(_h_tok)
                        self._k32.CloseHandle(_h_wl)
            except:
                pass
            self._native_ok = True
        except Exception:
            self._native_ok = False

    def _seed_known_processes(self):
        try:
            self._known_pids = set(self._enum_processes().keys())
        except:
            self._known_pids = set()

    def _enum_processes(self):
        result = {}
        if not self._native_ok:
            return result
        import ctypes
        TH32CS_SNAPPROCESS = 0x00000002
        h = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not h or h == ctypes.c_void_p(-1).value:
            return result
        pe = self._PE32()
        pe.dwSize = ctypes.sizeof(self._PE32)
        if self._k32.Process32FirstW(h, ctypes.byref(pe)):
            while True:
                pid = pe.th32ProcessID
                result[pid] = (pe.szExeFile, self._get_process_path(pid), pe.th32ParentProcessID)
                if not self._k32.Process32NextW(h, ctypes.byref(pe)):
                    break
        self._k32.CloseHandle(h)
        return result

    def _enum_processes_lite(self):
        """快速进程快照:仅取 名称/PID/PPID,不逐进程OpenProcess查路径。
        轮询主循环专用——路径由调用方只对"新出现进程"懒解析,
        避免每0.1s对全量进程查路径造成拦截延迟。"""
        result = {}
        if not self._native_ok:
            return result
        import ctypes
        TH32CS_SNAPPROCESS = 0x00000002
        h = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not h or h == ctypes.c_void_p(-1).value:
            return result
        pe = self._PE32()
        pe.dwSize = ctypes.sizeof(self._PE32)
        if self._k32.Process32FirstW(h, ctypes.byref(pe)):
            while True:
                result[pe.th32ProcessID] = (pe.szExeFile, None, pe.th32ParentProcessID)
                if not self._k32.Process32NextW(h, ctypes.byref(pe)):
                    break
        self._k32.CloseHandle(h)
        return result

    def _get_process_path(self, pid):
        try:
            import ctypes
            h = self._k32.OpenProcess(0x1000, False, pid)
            if not h:
                return ""
            buf = ctypes.create_unicode_buffer(260)
            size = ctypes.c_ulong(260)
            ok = self._k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
            self._k32.CloseHandle(h)
            return buf.value if ok else ""
        except:
            return ""

    _CMDLINE_SCRIPT_NAMES = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'powershell_ise.exe'}
    _CMDLINE_SCRIPT_EXTS = {'.bat', '.cmd', '.ps1', '.vbs', '.js'}
    _DANGEROUS_EXE_NAMES = {
        'reg.exe', 'regedit.exe', 'taskkill.exe', 'diskpart.exe',
        'dism.exe', 'bcdedit.exe', 'bcdboot.exe', 'vssadmin.exe',
        'wbadmin.exe', 'fsutil.exe', 'format.com', 'cipher.exe',
        'takeown.exe', 'icacls.exe', 'netsh.exe', 'sc.exe',
        'schtasks.exe', 'at.exe', 'regsvr32.exe', 'rundll32.exe',
        'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe',
        'shutdown.exe', 'attrib.exe', 'erase.exe',
    }

    _DANGEROUS_CMDS = [
        'taskkill', 'reg ', 'reg.exe', 'dism', 'bcdedit', 'bcdboot',
        'efi', 'diskpart', 'clean', 'del ', 'del/', 'rmdir', 'rd ',
        'rd/', 'remove-item', 'ri ', 'erase', 'format', 'cipher /w',
        'cipher/w', 'vssadmin', 'wbadmin', 'fsutil', 'takeown',
        'icacls', 'attrib', 'netsh', 'sc ', 'sc.exe', 'schtasks',
        'at ', 'crontab', 'regsvr32', 'rundll32', 'mshta', 'certutil',
        'bitsadmin', 'wmic', 'shutdown', 'reg add', 'reg delete',
        'reg import', 'reg load', 'reg restore', 'reg save',
    ]
    _DANGEROUS_PATTERNS = [
        'registry', 'autorun', 'startup', 'currentversion\\run',
        'currentversion/run', 'hklm', 'hkcu', 'hkey_',
        'schtask', 'schedule', 'task scheduler', 'at /',
        'inject', 'reflective', 'assembly::load', 'iex(',
        'invoke-expression', 'downloadstring', 'downloadfile',
        'start-process', 'hidden', '-enc ', '-encodedcommand',
        '-e ', '-w hidden', 'bypass', 'noprofile', 'exec',
        'frombase64string', ' decompress', 'gzstream', 'deflate',
    ]

    # 命令行/注册表/组策略/PowerShell/系统工具 → 行为链分类
    _OP_CATEGORY = {
        'cmd.exe': '命令行解释器', 'command.com': '命令行解释器',
        'powershell.exe': 'PowerShell执行', 'pwsh.exe': 'PowerShell执行',
        'powershell_ise.exe': 'PowerShell执行', 'wscript.exe': '脚本解释器',
        'cscript.exe': '脚本解释器', 'mshta.exe': 'HTA执行',
        'rundll32.exe': 'DLL调用', 'regsvr32.exe': 'DLL注册',
        'reg.exe': '注册表操作', 'regedit.exe': '注册表操作', 'regedt32.exe': '注册表操作',
        'regini.exe': '注册表操作',
        'schtasks.exe': '计划任务操作', 'at.exe': '计划任务操作',
        'sc.exe': '系统服务操作', 'net.exe': '系统服务操作', 'net1.exe': '系统服务操作',
        'netsh.exe': '网络配置操作', 'wmic.exe': 'WMI系统操作',
        'taskkill.exe': '进程终止操作', 'tskill.exe': '进程终止操作',
        'bcdedit.exe': '引导配置操作', 'bcdboot.exe': '引导配置操作',
        'diskpart.exe': '磁盘操作', 'vssadmin.exe': '卷影副本操作',
        'wbadmin.exe': '备份/恢复操作', 'fsutil.exe': '文件系统操作',
        'cipher.exe': '文件加密操作', 'format.com': '格式化操作',
        'shutdown.exe': '系统关机操作',
        'gpupdate.exe': '组策略操作', 'gpresult.exe': '组策略操作',
        'secedit.exe': '组策略/安全策略操作', 'lgpo.exe': '组策略操作',
        'certutil.exe': '证书工具操作', 'certreq.exe': '证书工具操作',
        'bitsadmin.exe': '后台传输操作', 'attrib.exe': '文件属性操作',
        'icacls.exe': 'ACL权限操作', 'takeown.exe': '所有权操作',
        'curl.exe': '网络下载操作', 'wget.exe': '网络下载操作',
    }

    def _classify_proc_op(self, name, path, pid):
        """识别cmd/powershell/注册表/组策略/系统工具类操作,返回(动作名, 详情)或None。"""
        try:
            n = (name or os.path.basename(path or '')).lower()
            cat = self._OP_CATEGORY.get(n)
            if not cat:
                return None
            cmdline = self._get_process_cmdline(pid)
            detail = cmdline[:300] if cmdline else f'路径: {path}'
            return (cat, detail)
        except Exception:
            return None

    def _get_process_cmdline(self, pid):
        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            h = self._k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h:
                return ""
            try:
                is_wow64 = wintypes.BOOL(0)
                self._k32.IsWow64Process(h, ctypes.byref(is_wow64))
                if is_wow64.value:
                    wow64_peb = ctypes.c_void_p()
                    status = self._ntdll.NtQueryInformationProcess(
                        h, 26, ctypes.byref(wow64_peb), ctypes.sizeof(wow64_peb), None)
                    if status != 0 or not wow64_peb.value:
                        return ""
                    peb_addr = wow64_peb.value
                    proc_params_addr = peb_addr + 0x10
                    params_ptr = ctypes.c_uint32()
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(proc_params_addr),
                                                        ctypes.byref(params_ptr), ctypes.sizeof(params_ptr), None):
                        return ""
                    if not params_ptr.value:
                        return ""
                    cmd_len_addr = params_ptr.value + 0x40
                    cmd_buf_ptr_addr = params_ptr.value + 0x44
                    cmd_len = ctypes.c_ushort()
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(cmd_len_addr),
                                                        ctypes.byref(cmd_len), ctypes.sizeof(cmd_len), None):
                        return ""
                    if cmd_len.value == 0 or cmd_len.value > 32768:
                        return ""
                    cmd_buf_ptr = ctypes.c_uint32()
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(cmd_buf_ptr_addr),
                                                        ctypes.byref(cmd_buf_ptr), ctypes.sizeof(cmd_buf_ptr), None):
                        return ""
                    if not cmd_buf_ptr.value:
                        return ""
                    cmd_buf = ctypes.create_unicode_buffer(cmd_len.value // 2 + 1)
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(cmd_buf_ptr.value),
                                                        cmd_buf, cmd_len.value, None):
                        return ""
                    result = cmd_buf.value
                else:
                    class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
                        _fields_ = [("Reserved1", ctypes.c_void_p),
                                    ("PebBaseAddress", ctypes.c_void_p),
                                    ("Reserved2_0", ctypes.c_void_p),
                                    ("Reserved2_1", ctypes.c_void_p),
                                    ("UniqueProcessId", ctypes.c_void_p),
                                    ("Reserved3", ctypes.c_void_p)]
                    pbi = _PROCESS_BASIC_INFORMATION()
                    status = self._ntdll.NtQueryInformationProcess(
                        h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
                    if status != 0 or not pbi.PebBaseAddress:
                        return ""
                    peb_addr = pbi.PebBaseAddress
                    proc_params_addr = peb_addr + 0x20
                    params_ptr = ctypes.c_void_p()
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(proc_params_addr),
                                                        ctypes.byref(params_ptr), ctypes.sizeof(params_ptr), None):
                        return ""
                    if not params_ptr.value:
                        return ""
                    cmd_len_addr = params_ptr.value + 0x70
                    cmd_buf_addr = params_ptr.value + 0x78
                    cmd_len = ctypes.c_ushort()
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(cmd_len_addr),
                                                        ctypes.byref(cmd_len), ctypes.sizeof(cmd_len), None):
                        return ""
                    if cmd_len.value == 0 or cmd_len.value > 32768:
                        return ""
                    cmd_buf = ctypes.create_unicode_buffer(cmd_len.value // 2 + 1)
                    if not self._k32.ReadProcessMemory(h, ctypes.c_void_p(cmd_buf_addr),
                                                        cmd_buf, cmd_len.value, None):
                        return ""
                    result = cmd_buf.value
                if result:
                    printable = sum(1 for c in result if c.isprintable() or c in '\t\r\n')
                    if len(result) > 0 and printable / len(result) < 0.5:
                        return ""
                return result
            finally:
                self._k32.CloseHandle(h)
        except:
            return ""

    def _check_dangerous_command(self, cmdline):
        if not cmdline:
            return None
        cl = cmdline.lower().strip()
        cl_no_space = cl.replace(' ', '').replace('\t', '')
        cl_deobf = cl.replace('^', '').replace('`', '').replace('"', '').replace("'", "")
        cl_deobf = re.sub(r'[{}\[\]()]', '', cl_deobf)
        checks = [cl, cl_no_space, cl_deobf, cl_deobf.replace(' ', '')]
        for check in checks:
            for cmd in self._DANGEROUS_CMDS:
                if cmd in check:
                    return cmd.strip()
            for pat in self._DANGEROUS_PATTERNS:
                if pat in check:
                    return pat
        return None

    def _suspend_process(self, pid):
        try:
            h = self._k32.OpenProcess(0x0800, False, pid)
            if h:
                self._ntdll.NtSuspendProcess(h)
                self._k32.CloseHandle(h)
                return True
        except:
            pass
        return False

    def _resume_process(self, pid):
        try:
            h = self._k32.OpenProcess(0x0800, False, pid)
            if h:
                self._ntdll.NtResumeProcess(h)
                self._k32.CloseHandle(h)
        except:
            pass

    def _pid_alive(self, pid):
        """进程是否仍存活(SYNCHRONIZE + WaitForSingleObject 0)。"""
        try:
            SYNCHRONIZE = 0x00100000
            QUERY_LIMITED = 0x1000
            WAIT_TIMEOUT = 0x00000102
            h = self._k32.OpenProcess(SYNCHRONIZE | QUERY_LIMITED, False, int(pid))
            if not h:
                return False
            try:
                return self._k32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
            finally:
                self._k32.CloseHandle(h)
        except Exception:
            return False

    def _endpoint_secondary_check(self, path, name='', pid=0, ppid=0):
        """端点二次研判:引擎判白后端点仍独立检查, 不做单点判决。
        返回 None=放行; (reason, score)=端点拦截。
        受信签名直接放行; EDR静态评分>=70拦截; 40~69记入事件账本参与链式累积。"""
        try:
            if not path or not os.path.exists(path):
                return None
            signer = None
            try:
                signer = _extract_signer(path)
            except Exception:
                signer = None
            if signer:
                _sl = signer.lower()
                if any(t in _sl for t in _TRUSTED_SIGNER_TOKENS):
                    return None
            _edr = self._edr
            score, reasons = 0, []
            if _edr is not None:
                try:
                    score, reasons = _edr.score_quick(int(pid or 0), name or os.path.basename(path), path, int(ppid or 0))
                except Exception:
                    score, reasons = 0, []
            if score >= EDR_SCORE_THRESHOLD:
                reason = 'Endpoint secondary verdict: score={} | {}'.format(score, ' | '.join(str(r) for r in reasons[:5]))
                _log("[端点研判] 引擎判白但端点独立研判拦截: {} 评分{} {}".format(
                    os.path.basename(path), score, reasons[:5]))
                return reason, score
            if score >= 40:
                # 未达拦截线: 记入事件账本, 链式累积仍可能触发回滚
                _edr_add_event(int(pid or 0), name or os.path.basename(path), path, 'violation', 5,
                               'Endpoint static score {} ({})'.format(score, '; '.join(str(r) for r in reasons[:3])))
            return None
        except Exception as e:
            _log("[端点研判] 异常: {}".format(e))
            return None

    def _terminate_process(self, pid):
        try:
            _impersonated = False
            if self._system_token:
                _impersonated = self._k32.SetThreadToken(None, self._system_token)
            h = self._k32.OpenProcess(0x0001, False, pid)
            _used_access = 0x0001
            if not h:
                h = self._k32.OpenProcess(0x0401, False, pid)
                _used_access = 0x0401
            if _impersonated:
                self._k32.SetThreadToken(None, None)
            if not h:
                return False, 0
            ok = self._k32.TerminateProcess(h, 1)
            self._k32.CloseHandle(h)
            return bool(ok), _used_access
        except:
            if _impersonated:
                try: self._k32.SetThreadToken(None, None)
                except: pass
            return False, 0

    _CHAIN_STOP_NAMES = {'explorer.exe','cmd.exe','powershell.exe','pwsh.exe','services.exe','lsass.exe','wininit.exe','csrss.exe','smss.exe','winlogon.exe','conhost.exe','sihost.exe','taskhostw.exe','userinit.exe','dwm.exe','fontdrvhost.exe','runtimebroker.exe','applicationframehost.exe','shellexperiencehost.exe','searchhost.exe','startmenuexperiencehost.exe','textinputhost.exe'}

    # full模式(银狐式整链拦截)仅豁免真·系统核心进程; cmd/powershell等解释器视为攻击链一环
    _SYS_CORE_STOP_NAMES = {'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
                            'lsass.exe', 'winlogon.exe', 'explorer.exe', 'sihost.exe',
                            'taskhostw.exe', 'userinit.exe', 'dwm.exe', 'ctfmon.exe',
                            'fontdrvhost.exe'}

    _IDE_NAMES = {'code.exe', 'code - insiders.exe', 'devenv.exe', 'idea64.exe',
                  'idea.exe', 'pycharm64.exe', 'pycharm.exe', 'webstorm64.exe',
                  'goland64.exe', 'clion64.exe', 'rider64.exe', 'phpstorm64.exe',
                  'rubymine64.exe', 'datagrip64.exe', 'studio64.exe',
                  'trae.exe', 'trae cn.exe', 'trae so lo cn.exe', 'cursor.exe',
                  'windsurf.exe', 'zed.exe', 'atom.exe', 'sublime_text.exe',
                  'notepad++.exe', 'vim.exe', 'emacs.exe', 'gvim.exe'}

    # 自家产品组件(名称+产品路径双匹配才豁免,防目录名伪装绕过)
    _SELF_PRODUCT_NAMES = {'sevenengine.exe', 'sevenmain.exe', 'sevenhips.exe', 'sevenedr.exe',
                           'sevenwatch.exe', 'sevenprotect.exe', 'sevenfile.exe', 'sevensystemprotect.exe',
                           'sevenprocessprotect.exe', 'sevenendpoint.exe', 'sevenend.exe',
                           'sevenendpointsecurity.exe', 'sevenendpointui.exe', 'pedefenseserver.exe',
                           'pedefense.exe', 'drvinstall.exe', 'sevenui.exe', 'sevenscanner.exe'}
    _SELF_PATH_TOKENS = ('sevenendpointsecurity', 'sevenhips', 'sevenedr', 'sevenwatch',
                         'sevenprotect', 'sevenmain', 'sevenengine')

    # 宿主/解释器豁免(与 _handle_new_process 豁免清单保持一致, 防快速拦截误杀)
    _SELF_EXEMPT_NAMES = {'pedefenseserver.exe', 'pedefense.exe', 'pasw.exe',
                          'sevenendpointsecurity.exe', 'sevenendpoint.exe', 'sevenend.exe'}
    _PY_EXEMPT_NAMES = {'python.exe', 'pythonw.exe', 'python3.exe', 'python3.13.exe',
                        'python3.12.exe', 'python314.exe', 'python313.exe', 'python312.exe',
                        'python311.exe', 'python310.exe', 'py.exe', 'pyw.exe'}

    def _fast_kill_allowed(self, name, path, ppid, debug=False):
        """快速拦截前的廉价豁免核验(必须与 _handle_new_process 的豁免清单完全一致)。
        返回 True = 可以快速击杀。"""
        try:
            if not path:
                return False
            _pl = path.lower()
            _fname = (os.path.basename(path) or name or '').lower()
            _ext = os.path.splitext(_fname)[1].lower()
            if _ext not in self._scan_exts:
                if debug: _log("[调试] {} 否决: ext {}".format(_fname, _ext))
                return False
            if is_system_path(path):
                if debug: _log("[调试] {} 否决: system path".format(_fname))
                return False
            if self._is_self_product(name, path):
                if debug: _log("[调试] {} 否决: self product".format(_fname))
                return False
            if self._is_user_allowed(path):
                if debug: _log("[调试] {} 否决: user allowed".format(_fname))
                return False
            if _fname in self._SELF_EXEMPT_NAMES:
                if debug: _log("[调试] {} 否决: self exempt".format(_fname))
                return False
            if _fname in self._PY_EXEMPT_NAMES and verify_name_path(_fname, path):
                if debug: _log("[调试] {} 否决: py exempt".format(_fname))
                return False
            if _fname in self._IDE_NAMES and verify_name_path(_fname, path):
                if debug: _log("[调试] {} 否决: IDE".format(_fname))
                return False
            if ppid == self._self_pid:
                if debug: _log("[调试] {} 否决: own child".format(_fname))
                return False
            if _pl.startswith(SEVENGINE_DIR.lower()):
                if debug: _log("[调试] {} 否决: enginedir".format(_fname))
                return False
            try:
                if os.path.normpath(path).lower() == os.path.normpath(sys.executable).lower():
                    if debug: _log("[调试] {} 否决: sys.executable".format(_fname))
                    return False
            except Exception:
                pass
            if g_scanner is not None and g_scanner.whitelist.contains(path):
                if debug: _log("[调试] {} 否决: whitelist".format(_fname))
                return False
            if debug: _log("[调试] {} 通过全部豁免 -> 允许快速拦截".format(_fname))
            return True
        except Exception as e:
            if debug: _log("[调试] fast_kill异常: {}".format(e))
            return False

    # 正常启动来源(父进程为这些时,系统工具不按名称击杀,走正常扫描弹窗流程)
    _NORMAL_LAUNCHER_NAMES = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe',
                              'openconsole.exe', 'windowsterminal.exe', 'wt.exe', 'explorer.exe',
                              'bash.exe', 'wsl.exe', 'userinit.exe', 'code.exe', 'rundll32.exe',
                              'sihost.exe', 'taskhostw.exe'}

    # 命令行中出现这些token => 无论来源直接击杀(针对安全组件的操作)
    _SELF_KILL_TOKENS = ('sevenendpoint', 'sevenengine', 'sevenmain', 'sevenhips', 'sevenedr',
                         'sevenwatch', 'sevenprotect', 'sevenfile', 'pedefense', 'msmpeng',
                         'mssense', 'nissrv', 'securityhealth')

    def _is_self_product(self, name, path):
        """自家产品组件判定:可执行名 ∈ 产品名集合 且 路径含产品目录token。"""
        try:
            n = (name or os.path.basename(path or '')).lower()
            if n not in self._SELF_PRODUCT_NAMES:
                return False
            p = (path or '').lower().replace('/', '\\')
            if not p:
                return False
            return any(tok in p for tok in self._SELF_PATH_TOKENS)
        except Exception:
            return False

    @staticmethod
    def _cmdline_plausible(cmd, tool_name):
        """系统工具命令行合理性检查:PEB乱码读取(如'淲秙Ǿ')视为不可读。"""
        try:
            if not cmd or not cmd.strip():
                return False
            c = cmd.strip()
            body = c
            low = (tool_name or '').lower()
            if low:
                if low.endswith('.exe'):
                    base = low[:-4]
                else:
                    base = low
                cl = c.lower()
                if cl.startswith(low):
                    body = c[len(low):]
                elif cl.startswith(base):
                    body = c[len(base):]
            body = body.strip()
            if body[:1] in ('"', "'"):
                body = body[1:].strip()
            if body.lower().startswith('.exe'):
                body = body[4:].lstrip('"').strip()
            for ch in body[:4]:
                o = ord(ch)
                if '\u4e00' <= ch <= '\u9fff' or 0xE000 <= o <= 0xF8FF or 0xAC00 <= o <= 0xD7AF:
                    return False  # CJK/私区/韩文乱码 => 不可读
            return True
        except Exception:
            return False

    def _terminate_chain(self, pid, name, path, full=False):
        """终止进程链。full=True:银狐式整链拦截——父进程链全部视为攻击链,
        仅在真·系统核心进程/IDE/自身处停手;否则沿用保守停手名单。"""
        terminated = []
        stop_names = self._SYS_CORE_STOP_NAMES if full else self._CHAIN_STOP_NAMES
        if name and name.lower() in self._IDE_NAMES and verify_name_path(name.lower(), path):
            _log("[拦截-文件] 拒绝终止IDE进程: {}({})".format(name, pid))
            return terminated
        try:
            procs = self._enum_processes()
        except:
            procs = {}
        my_pid = os.getpid()
        my_info = procs.get(my_pid)
        my_parent = my_info[2] if my_info else 0
        cur_pid = pid
        cur_name = name
        cur_path = path
        visited = set()
        for _ in range(6):
            if cur_pid in visited or cur_pid == 0:
                break
            if cur_pid == my_pid or cur_pid == my_parent:
                break
            if cur_name and cur_name.lower() in self._IDE_NAMES and verify_name_path(cur_name.lower(), cur_path):
                break
            if cur_name and cur_name.lower() in stop_names and verify_name_path(cur_name.lower(), cur_path):
                break
            visited.add(cur_pid)
            _ok, _access = self._terminate_process(cur_pid)
            if _ok:
                terminated.append((cur_name, cur_pid, cur_path, _access))
            info = procs.get(cur_pid)
            if not info:
                break
            ppid = info[2]
            if ppid == 0 or ppid == cur_pid:
                break
            pinfo = procs.get(ppid)
            if not pinfo:
                break
            p_name, p_path, _ = pinfo
            if not p_path or is_system_path(p_path):
                break
            if p_name.lower() in stop_names:
                break
            cur_pid = ppid
            cur_name = p_name
            cur_path = p_path
        return terminated

    def _rollback_chain_drops(self, pids):
        """攻击链回滚:链上进程登记的落盘文件逐个扫描, 威胁->隔离+通知, 干净->删除。"""
        removed = []
        try:
            targets = set()
            with _g_dropped_files_lock:
                for p in list(pids):
                    try:
                        targets |= _g_dropped_files.get(int(p), set())
                    except Exception:
                        continue
            for fp in targets:
                try:
                    if fp and os.path.isfile(fp) and not is_system_path(fp):
                        verdict = "CLEAN"
                        _t = ""
                        try:
                            if g_scanner:
                                verdict, _c, _t = g_scanner.scan_file(fp)
                        except Exception:
                            verdict = "CLEAN"
                        fname = os.path.basename(fp)
                        if verdict.startswith("MALICIOUS"):
                            # 链内威胁: 隔离并通知
                            try:
                                os.makedirs(QUARANTINE_DIR, exist_ok=True)
                                dest = os.path.join(QUARANTINE_DIR, fname + ".quarantine")
                                shutil.move(fp, dest)
                                _record_interception('攻击链文件隔离', fname, fp, threat_type=(_t or 'Threat'),
                                                     action='quarantined', extra=verdict)
                                _notify("Threat Quarantined", "Threat Quarantined {}".format(fname))
                                _log(f"[回滚-隔离] {fp} [{_t}]")
                            except Exception as e:
                                _log(f"[回滚] 隔离失败 {fp}: {e}")
                                try:
                                    os.remove(fp)
                                    removed.append(fp)
                                except Exception:
                                    pass
                        else:
                            # 纵深防御: 引擎判白后端点仍独立研判, 可疑则隔离而非删除
                            _sec = None
                            try:
                                _sec = self._endpoint_secondary_check(fp, fname, 0, 0)
                            except Exception:
                                _sec = None
                            if _sec:
                                try:
                                    os.makedirs(QUARANTINE_DIR, exist_ok=True)
                                    dest = os.path.join(QUARANTINE_DIR, fname + ".quarantine")
                                    shutil.move(fp, dest)
                                    _record_interception('攻击链文件隔离(端点研判)', fname, fp, threat_type='Suspicious Behavior',
                                                         confidence=int(_sec[1]), engine='Endpoint-Secondary',
                                                         action='quarantined', extra=_sec[0])
                                    _log(f"[回滚-隔离(端点研判)] {fp}")
                                except Exception as e:
                                    _log(f"[回滚] 隔离失败 {fp}: {e}")
                            else:
                                os.remove(fp)
                                removed.append(fp)
                except Exception:
                    continue
        except Exception:
            pass
        return removed

    def start(self):
        if self._threads:
            return
        self._stop_flag.clear()
        if self._native_ok:
            t = threading.Thread(target=self._process_loop, daemon=True)
            t.start()
            self._threads.append(t)
            t2 = threading.Thread(target=self._sensitive_op_loop, daemon=True)
            t2.start()
            self._threads.append(t2)
            # 引擎worker预热: 后台拉起并热身, 首次拦截不再等待解压+模型加载
            threading.Thread(target=self._ensure_worker, daemon=True, name='EnginePrewarm').start()
        else:
            _log("[实时防护] native初始化失败, 进程监控循环未启动!")
        _log("[实时防护] 进程监控循环启动状态: native_ok={}".format(self._native_ok))

    def stop(self):
        self._stop_flag.set()
        with self._proc_lock:
            if self._scan_proc:
                try: self._scan_proc.terminate()
                except: pass
                self._scan_proc = None

    def _ensure_worker(self):
        with self._proc_lock:
            if self._scan_proc and self._scan_proc.poll() is None:
                return self._scan_proc
            _env = dict(os.environ)
            _env['PYTHONIOENCODING'] = 'utf-8'
            try:
                self._scan_proc = subprocess.Popen(
                    _worker_cmd(),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, bufsize=1, text=True,
                    encoding='utf-8', errors='replace', cwd=BASE_DIR, env=_env
                )
            except Exception:
                self._scan_proc = None
                return None
            # 热身握手: 等引擎完成解压+模型加载(一次性成本)。
            # 否则首个扫描请求会撞上加载期, 超时->杀worker->再拉起->再加载, 恶性循环越跑越卡。
            _t0 = time.time()
            try:
                self._scan_proc.stdin.write(json.dumps({"path": "__warmup__"}) + "\n")
                self._scan_proc.stdin.flush()
            except Exception:
                try:
                    self._scan_proc.kill()
                except Exception:
                    pass
                self._scan_proc = None
                return None
            warm_box = {}
            def _warm_reader():
                try:
                    warm_box['line'] = self._scan_proc.stdout.readline()
                except Exception:
                    warm_box['line'] = None
            wt = threading.Thread(target=_warm_reader, daemon=True)
            wt.start()
            wt.join(timeout=90)
            if not warm_box.get('line') or self._scan_proc.poll() is not None:
                try:
                    self._scan_proc.kill()
                except Exception:
                    pass
                self._scan_proc = None
                _log("[扫描引擎] Worker 热身失败, 已放弃本次拉起")
                return None
            _log("[扫描引擎] Worker 就绪 ({:.1f}s)".format(time.time() - _t0))
            return self._scan_proc

    def _scan_file_subprocess(self, filepath, quick=False, timeout=8):
        proc = self._ensure_worker()
        if not proc:
            return "ERROR", 0, ""
        try:
            req = {"path": filepath}
            if quick:
                req["quick"] = True
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            result_box = {}
            def _reader():
                try:
                    line = proc.stdout.readline()
                    result_box['line'] = line
                except:
                    result_box['line'] = None
            rt = threading.Thread(target=_reader, daemon=True)
            rt.start()
            rt.join(timeout=timeout)
            if rt.is_alive():
                with self._proc_lock:
                    try:
                        if self._scan_proc: self._scan_proc.kill()
                    except: pass
                    self._scan_proc = None
                return "ERROR", 0, ""
            line = result_box.get('line')
            if not line:
                with self._proc_lock:
                    self._scan_proc = None
                return "ERROR", 0, ""
            data = json.loads(line)
            return data.get("result", "CLEAN"), data.get("conf", 0), data.get("vt", "")
        except Exception:
            with self._proc_lock:
                try:
                    if self._scan_proc: self._scan_proc.terminate()
                except: pass
                self._scan_proc = None
            return "ERROR", 0, ""

    def _sensitive_op_loop(self):
        _SENSITIVE_EXTS = {'.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.msi'}
        _DRIVER_EXTS = {'.sys', '.drv'}
        _drop_tracker = {}
        _drop_lock = threading.Lock()
        _seen_files = set()
        _last_scan_time = {}
        _driver_asked = set()
        def _get_watch_dirs():
            dirs = set()
            for env_key in ('TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'PROGRAMDATA'):
                val = os.environ.get(env_key)
                if val:
                    dirs.add(os.path.normpath(val))
            dirs.add(os.path.normpath(os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')))
            dirs.add(os.path.normpath(os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')))
            with self._terminated_lock:
                for tp in list(self._terminated_paths):
                    d = os.path.dirname(tp)
                    if d:
                        dirs.add(os.path.normpath(d))
            result = []
            for d in dirs:
                if os.path.isdir(d):
                    result.append(d)
            return result
        def _find_parent_process(filepath):
            try:
                file_dir = os.path.dirname(filepath).lower()
                procs = self._enum_processes()
                candidates = []
                for pid, info in procs.items():
                    if pid in (0, 4, self._self_pid):
                        continue
                    try:
                        name, path, ppid = info
                    except:
                        continue
                    if not path:
                        continue
                    pl = path.lower()
                    if pl.startswith(file_dir) and not is_system_path(path):
                        fname_lower = name.lower() if name else ''
                        if fname_lower in {'explorer.exe', 'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'dwm.exe'}:
                            continue
                        candidates.append((pid, name, path, ppid))
                if candidates:
                    candidates.sort(key=lambda x: x[0], reverse=True)
                    return candidates[0]
            except:
                pass
            return None
        def _ask_driver_install(filepath):
            fkey = filepath.lower()
            if fkey in _driver_asked:
                return 'block'
            _driver_asked.add(fkey)
            fname = os.path.basename(filepath)
            _log(f"[拦截-文件] 检测到驱动文件释放: {fname} ({filepath})")
            action = 'block'   # 托盘模式: 驱动释放直接拦截(+15分), 不再弹窗询问
            parent = _find_parent_process(filepath)
            parent_info = ''
            if parent:
                ppid, pname, ppath, _ = parent
                parent_info = f'来源进程: {pname}(PID:{ppid}) {ppath}'
                _record_behavior(ppid, pname, ppath, 0, '释放驱动', filepath)
                _edr_add_event(ppid, pname, ppath, 'driver_drop', 15,
                               'Dropped driver file: {}'.format(filepath))
            _record_interception('敏感操作(驱动安装)', fname, filepath, threat_type='Driver Drop', action='blocked', extra=f'已阻止 {parent_info}')
            try:
                os.remove(filepath)
                _log(f"[拦截-文件] 驱动释放已拦截并删除: {fname}")
            except Exception:
                _log(f"[拦截-文件] 驱动释放删除失败: {fname}")
            if parent:
                ppid, pname, ppath, _ = parent
                _ok, _acc = self._terminate_process(ppid)
                if _ok:
                    _log(f"[拦截-进程] 终止驱动释放进程: {pname}({ppid}) 权限:0x{_acc:04x}")
                    _notify("Threat Block", "Threat Block {}".format(pname or 'Unknown.exe'))
                    _edr_report_chain(ppid, pname, ppath,
                                      [('Dropped driver file: {}'.format(fname), 15),
                                       ('Driver install blocked + source terminated', 10)],
                                      action='blocked')
            else:
                _notify("Threat Block", "Threat Block {}".format(fname))
            return 'block'
        def _scan_dropped_file(filepath):
            try:
                if os.path.getsize(filepath) < 64:
                    return
            except:
                return
            ext = os.path.splitext(filepath)[1].lower()
            if ext in _DRIVER_EXTS:
                _ask_driver_install(filepath)
                return
            now = time.time()
            with _drop_lock:
                last = _last_scan_time.get(filepath, 0)
                if now - last < 30:
                    return
                _last_scan_time[filepath] = now
                parent_dir = os.path.dirname(filepath)
                _drop_tracker.setdefault(parent_dir, []).append(now)
                _drop_tracker[parent_dir] = [t for t in _drop_tracker[parent_dir] if now - t < 10]
                drop_count = len(_drop_tracker[parent_dir])
            if drop_count >= 3:
                fname = os.path.basename(filepath)
                _log(f"[拦截-文件] 检测到批量文件释放: {parent_dir} 近10秒释放{drop_count}个可执行文件")
                _record_interception('敏感操作(批量释放)', fname, filepath, threat_type='Mass Drop', action='blocked', extra=f'目录: {parent_dir} 10秒内释放{drop_count}个文件')
                _record_behavior(0, fname, filepath, 0, '批量释放文件', f'{parent_dir} ({drop_count}个)')
            parent = _find_parent_process(filepath)
            if parent:
                ppid, pname, ppath, _ = parent
                _record_behavior(ppid, pname, ppath, 0, '文件落盘', f'释放: {filepath}')
                _record_dropped_file(ppid, filepath)
                # EDR 记分: DLL释放 +5, 其他落盘 +5
                _drop_ext = os.path.splitext(filepath)[1].lower()
                _edr_add_event(ppid, pname, ppath,
                               'dll_drop' if _drop_ext == '.dll' else 'file_op', 5,
                               'Dropped file: {}'.format(filepath))
                try:
                    pres, pconf, pvt = self._scan_file_subprocess(ppath, quick=True, timeout=15)
                    if pres.startswith("MALICIOUS"):
                        _log(f"[拦截-文件] 释放源进程检测为恶意: {pname} [{pvt}] {pconf}%")
                        _record_interception('敏感操作(恶意源进程)', pname, ppath, threat_type=pvt, confidence=pconf, action='terminated', extra=f'PID:{ppid} 释放: {filepath}')
                        _ok, _acc = self._terminate_process(ppid)
                        if _ok:
                            _log(f"[拦截-进程] 终止恶意释放源: {pname}({ppid}) 权限:0x{_acc:04x}")
                        try:
                            os.remove(filepath)
                        except:
                            pass
                        return
                except:
                    pass
            try:
                res, conf, vt = self._scan_file_subprocess(filepath, quick=False, timeout=30)
                if res.startswith("MALICIOUS"):
                    fname = os.path.basename(filepath)
                    _log(f"[拦截-文件] 释放文件检测为恶意: {fname} [{vt}] {conf}%")
                    _record_interception('敏感操作(释放恶意文件)', fname, filepath, threat_type=vt, confidence=conf, action='blocked', extra=f'释放路径: {filepath}')
                    if parent:
                        _record_behavior(parent[0], parent[1], parent[2], 0, '文件落盘检出恶意', f'{fname} [{vt}] {conf}%')
                    else:
                        _record_behavior(0, fname, filepath, 0, '释放恶意文件', f'{vt} {conf}%')
                    try:
                        os.remove(filepath)
                    except:
                        pass
                else:
                    # 纵深防御: 引擎判白后端点仍独立研判
                    _sec = None
                    try:
                        _sec = self._endpoint_secondary_check(
                            filepath, (parent[1] if parent else ''), (parent[0] if parent else 0), 0)
                    except Exception:
                        _sec = None
                    if _sec:
                        fname = os.path.basename(filepath)
                        _log(f"[拦截-文件] 引擎判白但端点研判拦截释放文件: {fname} {_sec[1]}分")
                        _record_interception('敏感操作(端点二次研判)', fname, filepath, threat_type='Suspicious Behavior',
                                             confidence=int(_sec[1]), engine='Endpoint-Secondary',
                                             action='blocked', extra=_sec[0])
                        if parent:
                            _record_behavior(parent[0], parent[1], parent[2], 0, '端点研判拦截落盘', f'{fname} 评分{_sec[1]}')
                        try:
                            os.remove(filepath)
                        except Exception:
                            pass
            except:
                pass
        while not self._stop_flag.is_set():
            try:
                watch_dirs = _get_watch_dirs()
                for wdir in watch_dirs:
                    if not os.path.isdir(wdir):
                        continue
                    try:
                        for entry in os.scandir(wdir):
                            if self._stop_flag.is_set():
                                break
                            if not entry.is_file():
                                continue
                            ext = os.path.splitext(entry.name)[1].lower()
                            if ext not in _SENSITIVE_EXTS:
                                continue
                            fpath = entry.path
                            fkey = fpath.lower()
                            if fkey in _seen_files:
                                continue
                            try:
                                mtime = entry.stat().st_mtime
                                if time.time() - mtime > 30:
                                    _seen_files.add(fkey)
                                    continue
                            except:
                                continue
                            _seen_files.add(fkey)
                            if is_system_path(fpath):
                                continue
                            threading.Thread(target=_scan_dropped_file, args=(fpath,), daemon=True).start()
                    except:
                        pass
                if len(_seen_files) > 5000:
                    _seen_files.clear()
                if len(_driver_asked) > 200:
                    _driver_asked.clear()
            except:
                pass
            self._stop_flag.wait(2)

    def _process_loop(self):
        _hb = time.time()
        while not self._stop_flag.is_set():
            if time.time() - _hb > 60:
                _hb = time.time()
                _log("[实时防护][心跳] loop alive, known={}".format(len(self._known_pids)))
            if g_settings.get("process_protect", True):
                try:
                    current = self._enum_processes_lite()
                    # 本轮已退出的进程:冻结其行为链节点(停止继续记录)
                    exited_pids = self._known_pids - set(current.keys())
                    for _dpid in exited_pids:
                        _mark_process_exited(_dpid)
                    new_pids = set(current.keys()) - self._known_pids
                    for pid in new_pids:
                        if pid == self._self_pid or pid == 0:
                            continue
                        info = current.get(pid)
                        if not info:
                            continue
                        name, path, ppid = info
                        # 仅对新进程懒解析路径(轮询不再对全量进程OpenProcess,降低拦截延迟)
                        if not path:
                            path = self._get_process_path(pid)
                            if path:
                                current[pid] = (name, path, ppid)
                        if path:
                            with self._terminated_lock:
                                is_zombie = path.lower() in self._terminated_paths
                            if is_zombie and (self._is_self_product(name, path) or self._is_user_allowed(path)):
                                # 自家组件/用户放行的程序曾被误标记:解除拦截标记,不击杀
                                with self._terminated_lock:
                                    self._terminated_paths.discard(path.lower())
                            elif is_zombie:
                                _z_ok, _z_access = self._terminate_process(pid)
                                if _z_ok:
                                    _log(f"[拦截-进程] 恶意程序拦截 {name}({pid}) {path} 权限：0x{_z_access:04x}")
                                    _record_interception('进程拦截(重复启动)', name, path, action='terminated', extra=f'PID:{pid} 权限:0x{_z_access:04x}')
                                    _record_behavior(pid, name, path, ppid, '重复启动拦截', f'权限:0x{_z_access:04x}')
                                    # 重复拦截通知: Threat Block {exe}
                                    _notify("Threat Block", "Threat Block {}".format(name or 'Unknown.exe'))
                            else:
                                _fname_lower = name.lower()
                                _ext = os.path.splitext(path)[1].lower()
                                _is_cmd_proc = _fname_lower in self._CMDLINE_SCRIPT_NAMES or _ext in self._CMDLINE_SCRIPT_EXTS
                                _is_dangerous_exe = _fname_lower in self._DANGEROUS_EXE_NAMES
                                if _is_cmd_proc or _is_dangerous_exe:
                                    _ppname = ''
                                    _ppinfo = current.get(ppid)
                                    if _ppinfo:
                                        _ppname = (_ppinfo[0] or '').lower()
                                    _pp_is_sys = _ppname in _SYS_PROC_NAMES or (_ppinfo and _ppinfo[1] and is_system_path(_ppinfo[1]))
                                    _cmdline = self._get_process_cmdline(pid)
                                    _danger = None
                                    # PEB乱码读取(如'淲秙Ǿ')视为不可读,避免误判
                                    if _cmdline and not self._cmdline_plausible(_cmdline, _fname_lower):
                                        _cmdline = ''
                                    if _cmdline:
                                        _danger = self._check_dangerous_command(_cmdline)
                                    if not _danger and _ext in self._CMDLINE_SCRIPT_EXTS:
                                        try:
                                            _script_content = None
                                            for _enc in ('utf-8', 'gbk', 'latin-1'):
                                                try:
                                                    with open(path, 'r', encoding=_enc, errors='ignore') as _f:
                                                        _script_content = _f.read()
                                                    break
                                                except:
                                                    continue
                                            if _script_content:
                                                _danger = self._check_dangerous_command(_script_content)
                                                if _danger:
                                                    _cmdline = f'(script) {_script_content[:300]}'
                                        except:
                                            pass
                                    if not _danger and _fname_lower in self._CMDLINE_SCRIPT_NAMES and _cmdline:
                                        _script_paths = re.findall(r'[^\s"]+\.bat\b|[^\s"]+\.cmd\b|[^\s"]+\.ps1\b', _cmdline, re.IGNORECASE)
                                        for _arg in _script_paths:
                                            _arg = _arg.strip().strip('"').strip("'")
                                            if not os.path.isabs(_arg):
                                                try:
                                                    _ppinfo2 = current.get(ppid)
                                                    _ppdir = os.path.dirname(_ppinfo2[1]) if _ppinfo2 and _ppinfo2[1] else os.getcwd()
                                                    _arg = os.path.join(_ppdir, _arg)
                                                except:
                                                    pass
                                            if os.path.isfile(_arg):
                                                try:
                                                    _script_content = None
                                                    for _enc in ('utf-8', 'gbk', 'latin-1'):
                                                        try:
                                                            with open(_arg, 'r', encoding=_enc, errors='ignore') as _f:
                                                                _script_content = _f.read()
                                                            break
                                                        except:
                                                            continue
                                                    if _script_content:
                                                        _danger = self._check_dangerous_command(_script_content)
                                                        if _danger:
                                                            _cmdline = f'(script:{_arg}) {_script_content[:300]}'
                                                            break
                                                except:
                                                    pass
                                    if _is_dangerous_exe and not _danger:
                                        # 名称击杀仅在"父进程来源不可判正常"时执行:
                                        # 父进程=系统/shell等正常来源 -> 不按名称杀,走扫描弹窗流程;
                                        # 父进程未知(已退出/伪装)或可疑 -> 击杀。
                                        # 命令行针对安全组件 -> 无论如何击杀。
                                        _cmd_ok = self._cmdline_plausible(_cmdline, _fname_lower)
                                        _parent_norm = _pp_is_sys or (_ppname in self._NORMAL_LAUNCHER_NAMES)
                                        if _cmd_ok and _cmdline and any(t in _cmdline.lower() for t in self._SELF_KILL_TOKENS):
                                            _danger = _fname_lower + '(针对安全组件)'
                                        elif not _parent_norm:
                                            _danger = _fname_lower
                                            if not _cmdline:
                                                _cmdline = f'(no cmdline) {name}'
                                    if _danger:
                                        _ok, _access = self._terminate_process(pid)
                                        if _ok:
                                            _log(f"[拦截-命令] 危险命令拦截 {name}({pid}) 触发:{_danger} 命令:{_cmdline[:200]} 权限:0x{_access:04x}")
                                            _record_interception('命令拦截', name, path, threat_type='Dangerous Command', confidence=100, action='terminated', extra=f'PID:{pid} 触发:{_danger} 命令:{_cmdline[:150]}')
                                            _record_behavior(pid, name, path, ppid, '危险命令终止', f'触发:{_danger}')
                                            with self._terminated_lock:
                                                self._terminated_paths.add(path.lower())
                                            continue
                                    if not _danger and not is_system_path(path):
                                        # EDR: 任何脚本运行(cmd/bat/ps1/js/vbs/命令行) +5, 记录其命令
                                        _edr_add_event(pid, name, path, 'script_run', 5,
                                                       'Script execution: {}'.format((_cmdline or path)[:180]))
                                # 快速拦截: 廉价豁免不过 -> 立即在主循环击杀(抢在快跑型样本前面),
                                # 签名核验/研判/扫描流程交给 worker; 受信签名程序事后自动重新拉起
                                if self._fast_kill_allowed(name, path, ppid):
                                    _fk, _fa = self._terminate_process(pid)
                                    if _fk:
                                        _log(f"[拦截-进程] 快速拦截 {name}({pid}) {path} 权限:0x{_fa:04x}")
                                _record_behavior(pid, name, path, ppid, '进程启动', f'路径: {path}')
                                # 分类入链+终止处理全部放进工作线程,主循环只做发现与僵尸击杀
                                threading.Thread(target=self._on_new_process,
                                                 args=(pid, name, path, ppid, current.get(ppid)),
                                                 daemon=True).start()
                    self._known_pids = set(current.keys())
                except Exception:
                    _log("[进程循环] 异常: {}".format(traceback.format_exc()[-400:]))
            self._stop_flag.wait(0.02)

    def _on_new_process(self, pid, name, path, ppid, ppinfo):
        """工作线程:命令行/注册表/组策略/PowerShell/系统操作分类入链 + 终止处理。"""
        try:
            # 命令行/注册表/组策略/PowerShell/系统操作分类入链
            _op = self._classify_proc_op(name, path, pid)
            if _op:
                _record_behavior(pid, name, path, ppid, _op[0], _op[1])
                if ppid and ppid not in (0, self._self_pid) and ppinfo:
                    _record_behavior(ppid, ppinfo[0], ppinfo[1], 0, '派生子进程操作', f'{name} → {_op[0]}')
        except Exception:
            pass
        # MSI安装拦截:msiexec启动时提取MSI路径做EDR级分析,恶意则终止安装
        try:
            self._handle_msiexec_install(pid, name, path)
        except Exception:
            pass
        self._handle_new_process(pid, name, path, ppid)

    def _handle_msiexec_install(self, pid, name, path):
        """msiexec启动MSI:提取.msi路径→引擎全量分析→恶意终止msiexec并告警。"""
        try:
            if (name or '').lower() != 'msiexec.exe':
                return
            cmdline = self._get_process_cmdline(pid)
            if not cmdline:
                return
            m = re.search(r'([A-Za-z]:\\[^"\']*?\.msi)', cmdline, re.IGNORECASE)
            if not m:
                return  # /V、-Embedding等服务实例无MSI路径
            msi_path = m.group(1).strip().rstrip('"')
            if not os.path.isfile(msi_path):
                return
            now = time.time()
            with self._dedup_lock:
                last = self._msi_scanned.get(msi_path.lower(), 0)
                if now - last < 60:
                    return
                self._msi_scanned[msi_path.lower()] = now
                if len(self._msi_scanned) > 200:
                    self._msi_scanned = {k: t for k, t in self._msi_scanned.items() if now - t < 300}
            ppid = 0
            try:
                info = self._enum_processes().get(pid)
                if info:
                    ppid = info[2]
            except Exception:
                pass
            _record_behavior(pid, name, path, ppid, 'MSI安装分析', f'目标: {msi_path}')
            res, conf, vt = self._scan_file_subprocess(msi_path, quick=False, timeout=45)
            if res.startswith("MALICIOUS"):
                _ok, _acc = self._terminate_process(pid)
                _log(f"[拦截-MSI] 恶意MSI安装已终止: {msi_path} [{vt}] {conf}%")
                _scan_log(f"[拦截-MSI] {msi_path} [{vt}] {conf}%")
                _record_interception('MSI拦截', os.path.basename(msi_path), msi_path, threat_type=vt,
                                     confidence=conf, engine='MSI-EDR', action='terminated',
                                     extra=f'PID:{pid} msiexec已终止 权限:0x{_acc:04x}')
                _record_behavior(pid, name, path, ppid, 'MSI检出恶意', f'{vt} {conf}%')
                done = threading.Event()
                _gui_queue.put(lambda: self._show_msi_alert(pid, msi_path, conf,
                                                            [f'{vt}（置信度 {conf}%）'], done))
                done.wait(timeout=60)
            else:
                _record_behavior(pid, name, path, ppid, 'MSI安装', f'分析结果: {res}')
        except Exception:
            pass

    def _show_msi_alert(self, pid, msi_path, score, reasons, done_event):
        """托盘模式:MSI拦截通知(动作已在 _handle_msiexec_install 完成)。"""
        try:
            _notify("Threat Block", "Threat Block {}".format(os.path.basename(msi_path) or 'Unknown.exe'))
            _edr_report_chain(pid, os.path.basename(msi_path) or 'Unknown.exe', msi_path,
                              [('Malicious MSI package', int(score or 0))] + [
                                  (str(r), 0) for r in (reasons or [])[:10]],
                              action='blocked')
        except Exception:
            pass
        done_event.set()

    def _is_user_allowed(self, path):
        """用户在扫描弹窗点过'启动程序'的路径:1小时内不再拦截其重复启动。"""
        try:
            with self._dedup_lock:
                ts = self._user_allowed.get((path or '').lower(), 0)
            return ts and time.time() - ts < 3600
        except Exception:
            return False

    def _mark_user_allowed(self, path):
        try:
            with self._dedup_lock:
                self._user_allowed[(path or '').lower()] = time.time()
                if len(self._user_allowed) > 300:
                    now = time.time()
                    self._user_allowed = {k: t for k, t in self._user_allowed.items()
                                          if now - t < 3600}
        except Exception:
            pass

    def _handle_new_process(self, pid, name, path, ppid):
        try:
            global g_scanner
            if g_scanner is not None and g_scanner.whitelist.contains(path):
                return
            now = time.time()
            # 扫描判恶已拦截的路径再次启动: 直接击杀 + Threat Block 通知, 不再重复扫描流程
            with self._terminated_lock:
                _rep_blocked = path.lower() in self._terminated_paths
            if _rep_blocked:
                _ok, _acc = self._terminate_process(pid)
                if _ok:
                    _log(f"[拦截-进程] 重复启动拦截 {name}({pid}) {path}")
                    _record_interception('进程拦截(重复启动)', name, path, action='terminated', extra=f'PID:{pid} 权限:0x{_acc:04x}')
                    _record_behavior(pid, name, path, ppid, '重复启动拦截', f'权限:0x{_acc:04x}')
                    _notify("Threat Block", "Threat Block {}".format(name or 'Unknown.exe'))
                return
            with self._dedup_lock:
                last = self._recent_scanned.get(path, 0)
                if now - last < 60:
                    with self._terminated_lock:
                        if path.lower() not in self._terminated_paths:
                            return
                self._recent_scanned[path] = now
                if len(self._recent_scanned) > 1000:
                    _cutoff = now - 300
                    self._recent_scanned = {p: t for p, t in self._recent_scanned.items() if t > _cutoff}
            fname_lower = os.path.basename(path).lower()
            # 自家产品组件(名称+产品路径双匹配)完全豁免拦截
            if self._is_self_product(name, path):
                return
            # 用户在扫描弹窗放行过的程序:会话内信任,不再拦截其重复启动
            if self._is_user_allowed(path):
                _record_behavior(pid, name, path, ppid, '用户放行启动', '')
                return
            _self_exempt = self._SELF_EXEMPT_NAMES
            _py_exempt = self._PY_EXEMPT_NAMES
            if fname_lower in _self_exempt:
                return
            if fname_lower in _py_exempt and verify_name_path(fname_lower, path):
                return
            if fname_lower in self._IDE_NAMES and verify_name_path(fname_lower, path):
                return
            if ppid == self._self_pid:
                return
            if is_system_path(path):
                return
            try:
                if os.path.samefile(path, sys.executable):
                    return
            except:
                if os.path.normpath(path).lower() == os.path.normpath(sys.executable).lower():
                    return
            try:
                main_script = os.path.abspath(__file__)
                if os.path.normpath(path).lower() == os.path.normpath(main_script).lower():
                    return
            except:
                pass
            ext = os.path.splitext(path)[1].lower()
            if ext not in self._scan_exts:
                return
            try:
                if os.path.getsize(path) < 1:
                    return
            except:
                return
            # 可信签名快速放行(商业EDR标准):微软等受信厂商签名的程序不终止、不弹窗
            try:
                _sig_name = _extract_signer(path)
            except Exception:
                _sig_name = None
            if _sig_name:
                _sl = _sig_name.lower()
                if any(t in _sl for t in _TRUSTED_SIGNER_TOKENS):
                    _record_behavior(pid, name, path, ppid, '可信签名放行', f'签名者: {_sig_name}')
                    # 快速拦截可能已在主循环将其击杀: 核验为受信签名后自动重新拉起
                    try:
                        if not self._pid_alive(pid):
                            with self._dedup_lock:
                                self._recent_scanned[path] = time.time()
                            os.startfile(path)
                            _log(f"[拦截-进程] 受信签名程序已重新拉起: {name} {path}")
                    except Exception as e:
                        _log(f"[拦截-进程] 受信签名重拉失败 {path}: {e}")
                    return
            terminated_all = []
            _main_ok, _main_access = self._terminate_process(pid)
            if _main_ok:
                terminated_all.append((name, pid, path, _main_access))
                _record_behavior(pid, name, path, ppid, '进程终止', f'权限:0x{_main_access:04x}')
            # EDR行为评分(覆盖所有新启动的分支子进程):
            # 放在终止之后执行——拦截零延迟,评分只影响记录与告警
            _edr = self._edr
            if _edr is not None and g_settings.get("edr_protect", True):
                try:
                    _score, _reasons = _edr.score_quick(pid, name, path, ppid)
                    if _score >= EDR_SCORE_THRESHOLD:
                        _rj = '、'.join(_reasons[:6]) if _reasons else '行为评分超限'
                        _record_interception('EDR评分拦截', name, path, threat_type='Suspicious Behavior',
                                             confidence=_score, engine='行为EDR-新进程', action='terminated',
                                             extra=f'PID:{pid} 原因:{_rj}')
                        _record_behavior(pid, name, path, ppid, 'EDR高分拦截', f'评分:{_score} {_rj}')
                        _scan_log(f"[EDR] 新进程高分拦截 {name}({pid}) 评分:{_score} {_rj}")
                except Exception:
                    pass
            for _round in range(3):
                try:
                    procs = self._enum_processes()
                except:
                    procs = {}
                chain = self._terminate_chain(pid, name, path, full=True)
                for t in chain:
                    if t not in terminated_all:
                        terminated_all.append(t)
                kill_set = {pid}
                changed = True
                while changed:
                    changed = False
                    for cpid, cinfo in procs.items():
                        if cpid in kill_set:
                            continue
                        try:
                            _, _, cppid = cinfo
                            if cppid in kill_set:
                                kill_set.add(cpid)
                                changed = True
                        except:
                            pass
                for kpid in kill_set:
                    if kpid in (0, os.getpid(), pid):
                        continue
                    ki = procs.get(kpid)
                    if not ki:
                        continue
                    kn, kp, _ = ki
                    if kn and kn.lower() in self._IDE_NAMES:
                        continue
                    if kp and is_system_path(kp):
                        continue
                    _c_ok, _c_access = self._terminate_process(kpid)
                    if _c_ok:
                        e = (kn, kpid, kp, _c_access)
                        if e not in terminated_all:
                            terminated_all.append(e)
                if _round < 2:
                    time.sleep(0.1)
            for _t in terminated_all:
                _tn, _tp, _tpa, _ta = _t
                _log(f"[拦截-进程] 已终止 {_tn}({_tp}) {_tpa} 权限：0x{_ta:04x}")
                if _tp != pid:
                    _record_behavior(_tp, _tn, _tpa, 0, '攻击链父进程终止', f'权限:0x{_ta:04x}')
            if not terminated_all:
                _log(f"[拦截-进程] 终止失败(权限不足或进程保护) {name}({pid}) {path}")
            # 银狐式攻击链回滚:删除整条链释放的落盘文件
            try:
                _chain_pids = {pid} | {t[1] for t in terminated_all}
                _rb = self._rollback_chain_drops(_chain_pids)
                if _rb:
                    _log(f"[拦截-回滚] 攻击链回滚: 已删除落盘文件 {len(_rb)} 个: {'; '.join(_rb[:4])}")
                    _scan_log(f"[拦截-回滚] 攻击链回滚 {len(_rb)} 个落盘文件")
                    _record_interception('攻击链回滚', name, path, threat_type='Chain Rollback',
                                         confidence=0, engine='攻击链回滚', action='rolled_back',
                                         extra=f'PID:{pid} 回滚{len(_rb)}个落盘文件: {"; ".join(_rb[:3])}')
            except Exception:
                pass
            path_lower = path.lower()
            with self._terminated_lock:
                self._terminated_paths.add(path_lower)
            stop_watchdog = threading.Event()
            _wd_killed = set()
            def _watchdog():
                while not stop_watchdog.is_set():
                    try:
                        procs = self._enum_processes()
                        for wpid, winfo in procs.items():
                            if wpid in (0, os.getpid()):
                                continue
                            try:
                                wn, wp, _ = winfo
                            except:
                                continue
                            if wp and wp.lower() == path_lower:
                                _w_ok, _w_access = self._terminate_process(wpid)
                                if _w_ok:
                                    if wpid not in _wd_killed:
                                        _wd_killed.add(wpid)
                                        _log(f"[拦截-进程] 恶意程序拦截 {wn}({wpid}) {wp} 权限：0x{_w_access:04x}")
                                        _record_interception('进程拦截(看门狗)', wn, wp, action='terminated', extra=f'PID:{wpid} 权限:0x{_w_access:04x}')
                        # 注意:不再清理 _terminated_paths 中"当前无活进程"的路径。
                        # 否则其他进程的看门狗会把本恶意路径从黑名单中移除,
                        # 导致用户选择拦截/忽略后,重复启动被放行。
                    except:
                        pass
                    stop_watchdog.wait(0.1)
            wd_thread = threading.Thread(target=_watchdog, daemon=True)
            wd_thread.start()
            done_event = threading.Event()
            result_box = {}
            _gui_queue.put(lambda: self._parent._show_scan_dialog(pid, name, path, self, done_event, result_box))
            done_event.wait(timeout=120)
            if not done_event.is_set():
                _log(f"[拦截-进程] 扫描通知超时，保持终止: {name} {path}")
            stop_watchdog.set()
            action = result_box.get('action', '')
            if action == 'allow':
                with self._terminated_lock:
                    self._terminated_paths.discard(path_lower)
                # 扫描无威胁: 会话内信任该路径
                self._mark_user_allowed(path)
                _log(f"[拦截-进程] 扫描无威胁已放行: {name} {path}")
                # 放行 = 重新启动该进程(先解除拦截标记再重启, 避免看门狗竞态)
                try:
                    with self._dedup_lock:
                        self._recent_scanned[path] = time.time()
                    os.startfile(path)
                    _log(f"[拦截-进程] 重新启动放行程序: {path}")
                except Exception as e:
                    _log(f"[拦截-进程] 重新启动失败 {path}: {e}")
        except:
            pass


# ============================ 轻量行为EDR ============================
# 设计目标:对新进程 + 定时轮询全进程做行为评分,>=EDR_SCORE_THRESHOLD 终止进程链;
# DLL侧载/内存注入拦截;通过白名单避开系统/日常应用,降低误报。
# 绝不自动隔离/删除文件;仅告警+终止进程,文件原地不动。
EDR_SCORE_THRESHOLD = 70


class _EDRAlertDialog(QDialog):
    """EDR 告警弹窗:仅显示威胁已终止,提供「放行(重启进程)」/「忽略」。
    绝不删除/隔离文件。"""

    def __init__(self, pid, name, path, score, reasons, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self._pid = pid
        self._name = name
        self._path = path
        self._score = score
        self._reasons = reasons
        self._result_action = "ignore"  # ignore | allow(relaunch)
        self._drag_offset = None
        self.resize(520, 0)
        th = get_theme()
        self.setStyleSheet(f"_EDRAlertDialog {{ background: rgb({th['bg_panel'].red()},{th['bg_panel'].green()},{th['bg_panel'].blue()}); border: 1px solid #e0e0e0; border-radius: 12px; }}")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        container = QWidget(self)
        cl = QVBoxLayout(container)
        cl.setContentsMargins(28, 20, 28, 18)
        cl.setSpacing(12)
        # 顶部红色横条
        header = QFrame()
        header.setFixedHeight(48)
        header.setCursor(Qt.CursorShape.SizeAllCursor)
        header.setStyleSheet(f"QFrame {{ background: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()}); border-top-left-radius: 12px; border-top-right-radius: 12px; }}")
        header.installEventFilter(self)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(render_svg("shield_alert", QColor(255, 255, 255), 22))
        hl.addWidget(icon_lbl)
        title = QLabel("行为防护：检测到高风险程序")
        title.setFont(QFont("Microsoft YaHei", 11, QFont.Weight.DemiBold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hl.addWidget(title)
        hl.addStretch()
        cl.addWidget(header)
        # 文件信息
        info = QLabel(f"<b>{name}</b>  (PID:{pid})")
        info.setFont(QFont("Microsoft YaHei", 9))
        info.setStyleSheet(f"color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()}); background: transparent;")
        info.setWordWrap(True)
        cl.addWidget(info)
        _fm_edr_path = QFontMetrics(QFont("Consolas", 8))
        path_lbl = QLabel(_fm_edr_path.elidedText(path, Qt.TextElideMode.ElideMiddle, 450))
        path_lbl.setToolTip(path)
        path_lbl.setFont(QFont("Consolas", 8))
        path_lbl.setStyleSheet(f"color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()}); background: transparent;")
        cl.addWidget(path_lbl)
        # 评分与原因
        score_lbl = QLabel(f"风险评分：<b style='color:#D13438'>{score}</b> / 100")
        score_lbl.setFont(QFont("Microsoft YaHei", 9))
        score_lbl.setStyleSheet("background: transparent;")
        cl.addWidget(score_lbl)
        reason_text = "、".join(reasons[:6]) if reasons else "命中多条恶意行为特征"
        reason_lbl = QLabel(f"命中特征：{reason_text}")
        reason_lbl.setFont(QFont("Microsoft YaHei", 8))
        reason_lbl.setStyleSheet(f"color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()}); background: transparent;")
        reason_lbl.setWordWrap(True)
        cl.addWidget(reason_lbl)
        note = QLabel("进程已被终止，文件保留在原位（未删除、未隔离）")
        note.setFont(QFont("Microsoft YaHei", 8))
        note.setStyleSheet("color: #616161; background: transparent;")
        note.setWordWrap(True)
        cl.addWidget(note)
        # 按钮
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch()
        btn_block = QPushButton("拦截")
        btn_block.setFixedHeight(32)
        btn_block.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_block.setStyleSheet("QPushButton { background: #D13438; color: #ffffff; border: none; border-radius: 6px; padding: 0 18px; } QPushButton:hover { background: #B71C1C; }")
        btn_block.clicked.connect(self._on_ignore)
        btn_row.addWidget(btn_block)
        btn_allow = QPushButton("放行并重启程序")
        btn_allow.setFixedHeight(32)
        btn_allow.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_allow.setStyleSheet("QPushButton { background: #0078D4; color: #ffffff; border: none; border-radius: 6px; padding: 0 18px; } QPushButton:hover { background: #106ebe; }")
        btn_allow.clicked.connect(self._on_allow)
        btn_row.addWidget(btn_allow)
        cl.addLayout(btn_row)
        outer.addWidget(container)
        self._toast_container = container
        # 动画
        self._opacity = QGraphicsOpacityEffect(container)
        self._opacity.setOpacity(0.0)
        container.setGraphicsEffect(self._opacity)
        self._fade = QPropertyAnimation(self._opacity, b"opacity", self)
        self._fade.setDuration(240)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)

    def _on_ignore(self):
        self._result_action = "ignore"
        self.reject()

    def _on_allow(self):
        self._result_action = "allow"
        try:
            os.startfile(self._path)
        except Exception as e:
            _log(f"[EDR] 重启失败 {self._path}: {e}")
        self.accept()

    def eventFilter(self, obj, event):
        if obj is self.findChild(QFrame):
            if event.type() == event.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                self._drag_offset = event.globalPosition().toPoint() - self.pos()
                return True
            elif event.type() == event.Type.MouseMove and self._drag_offset is not None:
                if event.buttons() & Qt.MouseButton.LeftButton:
                    self.move(event.globalPosition().toPoint() - self._drag_offset)
                    return True
            elif event.type() == event.Type.MouseButtonRelease:
                self._drag_offset = None
                return True
        return super().eventFilter(obj, event)

    def start_animation(self):
        _toast_slide_up(self, getattr(self, '_toast_container', None) or self)
        self._fade.start()

    def exec(self):
        self.show()
        self.raise_()
        self.activateWindow()
        return 0

    def showEvent(self, event):
        super().showEvent(event)
        _apply_rounded_mask(self, 12)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _apply_rounded_mask(self, 12)


class BehaviorEDR:
    """轻量行为EDR:对新进程+定时轮询全进程做行为评分,DLL侧载/注入拦截。
    复用 RealtimeMonitor._enum_processes / _terminate_chain,纯ctypes无新依赖。"""

    def __init__(self, parent_window):
        self._parent = parent_window
        self._realtime = None
        self._stop = threading.Event()
        self._thread = None
        self._k32 = ctypes.windll.kernel32
        self._dedup = {}            # pid -> 上次评分时间(避免反复终止)
        self._dedup_lock = threading.Lock()
        self._inj_alerted = {}      # pid -> 已告警的DLL注入指纹(避免重复弹窗)
        self._inj_lock = threading.Lock()
        self._alert_active = False  # 弹窗并发保护
        self._alert_lock = threading.Lock()
        self._init_module_api()

    def set_realtime(self, mon):
        self._realtime = mon

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name='BehaviorEDR')
        self._thread.start()
        _log("[EDR] 行为防护已启动")

    def stop(self):
        self._stop.set()

    def _init_module_api(self):
        try:
            self._k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            self._k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            self._k32.Module32FirstW.restype = wintypes.BOOL
            self._k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self._k32.Module32NextW.restype = wintypes.BOOL
            self._k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self._k32.CloseHandle.argtypes = [wintypes.HANDLE]
            class _ME32W(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD),
                            ("th32ModuleID", wintypes.DWORD),
                            ("th32ProcessID", wintypes.DWORD),
                            ("GlblcntUsage", wintypes.DWORD),
                            ("ProccntUsage", wintypes.DWORD),
                            ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                            ("modBaseSize", wintypes.DWORD),
                            ("hModule", wintypes.HMODULE),
                            ("szModule", wintypes.WCHAR * 256),
                            ("szExePath", wintypes.WCHAR * 260)]
            self._ME32W = _ME32W
            self._module_ok = True
        except Exception:
            self._module_ok = False

    def _poll_loop(self):
        """定时轮询全进程(10s/次),仅做轻量路径/名称检查。
        PE解析和签名提取等重计算只在 score_quick(新进程入口)执行,避免轮询卡顿。"""
        while not self._stop.is_set():
            try:
                if (g_settings.get("edr_protect", True) and self._realtime
                        and getattr(self._realtime, '_native_ok', False)):
                    procs = self._realtime._enum_processes()
                    self_pid = self._realtime._self_pid
                    for pid, info in procs.items():
                        if pid in (0, 4) or pid == self_pid:
                            continue
                        try:
                            name, path, ppid = info
                        except Exception:
                            continue
                        if not path:
                            continue
                        fname_lower = (name or '').lower()
                        if fname_lower in EDR_EXEMPT_NAMES:
                            continue
                        # 自家产品组件豁免
                        try:
                            if self._realtime._is_self_product(name, path):
                                continue
                        except Exception:
                            pass
                        try:
                            if is_system_path(path):
                                continue
                        except Exception:
                            pass
                        now = time.time()
                        with self._dedup_lock:
                            last = self._dedup.get(pid, 0)
                            if now - last < 60:
                                continue
                            self._dedup[pid] = now
                        pl = path.lower().replace('/', '\\')
                        if any(tok in pl for tok in EDR_SUSPICIOUS_DIR_TOKENS):
                            try:
                                score, reasons = self._calc_score(path, name)
                                if score >= EDR_SCORE_THRESHOLD:
                                    self._handle_threat(pid, name, path, score, reasons, "行为EDR-轮询")
                            except Exception:
                                pass
            except Exception:
                pass
            self._stop.wait(10)

    # ---------------- 单进程打分 ----------------
    def _score_one(self, pid, name, path, ppid, from_poll=False):
        # 1) 去重:同pid 30s内只评一次
        now = time.time()
        with self._dedup_lock:
            last = self._dedup.get(pid, 0)
            if now - last < 30:
                # 即使跳过评分,也要做注入监控(对关键进程)
                self._maybe_check_injection(pid, name, path)
                return
            self._dedup[pid] = now
        # 清理过期去重项(防内存增长)
        if len(self._dedup) > 500:
            with self._dedup_lock:
                cutoff = now - 120
                self._dedup = {p: t for p, t in self._dedup.items() if t > cutoff}

        fname_lower = name.lower() if name else ''
        # 2) 系统路径直接豁免(保护 Windows/Program Files)
        try:
            if is_system_path(path):
                self._maybe_check_injection(pid, name, path)
                return
        except Exception:
            pass
        # 3) 名字白名单豁免(但关键进程仍检查注入) - 必须验证路径防改名逃逸
        if fname_lower in EDR_EXEMPT_NAMES and verify_name_path(fname_lower, path):
            self._maybe_check_injection(pid, name, path)
            return
        # 4) 可信签名者直接0分
        try:
            signer = _extract_signer(path)
            if signer:
                sl = signer.lower()
                TRUSTED = {'microsoft', 'google', 'apple', 'intel', 'nvidia', 'amd',
                           'oracle', 'adobe', 'tencent', 'alibaba', 'baidu', '360',
                           'kingsoft', 'wps', 'huawei', 'xiaomi', 'mozilla', 'opera',
                           'valve', 'epic', 'github', 'slack', 'zoom', 'dropbox',
                           'atlassian', 'discord', 'lenovo', 'realtek', 'samsung',
                           'vmware', 'citrix', 'kaspersky', 'symantec', 'mcafee',
                           ' sophos', 'trend micro'}
                if any(t in sl for t in TRUSTED):
                    self._maybe_check_injection(pid, name, path)
                    return
        except Exception:
            pass
        # 5) 计分
        score, reasons = self._calc_score(path, name)
        if score > 0:
            _log(f"[EDR] 评分 {name}({pid}) {path} = {score} [{', '.join(reasons)}]")
        if score >= EDR_SCORE_THRESHOLD:
            self._handle_threat(pid, name, path, score, reasons, "行为EDR")
        # 6) 注入监控(对关键/常用进程)
        self._maybe_check_injection(pid, name, path)

    def _calc_score(self, path, name):
        """组合各加分项,返回 (score, reasons)。单因素上限 EDR_MAX_SINGLE_FACTOR。"""
        score = 0
        reasons = []
        fname_lower = (name or os.path.basename(path)).lower()
        try:
            pl = path.lower().replace('/', '\\')
        except Exception:
            pl = ''
        ext = os.path.splitext(path)[1].lower()

        # (a) 偏僻位置
        in_suspicious_dir = any(tok in pl for tok in EDR_SUSPICIOUS_DIR_TOKENS)
        if in_suspicious_dir:
            score += 20
            reasons.append("落地于偏僻/可疑目录")

        # (b) 持久化位置(仅Startup自启动目录,不泛化AppData Roaming避免微信等误报)
        persistent = ('\\startup\\' in pl or '\\start menu\\programs\\startup' in pl
                      or '\\users\\public\\' in pl)
        if persistent:
            score += 25
            reasons.append("位于持久化/自启动位置")

        # (c) 文件名伪装(scvhost/svch0st/系统名落在非系统目录)
        try:
            is_non_sys_path = not is_system_path(path)
        except Exception:
            is_non_sys_path = True
        disguise_names = {'svchost.exe', 'csrss.exe', 'lsass.exe', 'explorer.exe',
                          'winlogon.exe', 'services.exe', 'spoolsv.exe', 'rundll32.exe',
                          'chrome.exe', 'msedge.exe'}
        fname_base = os.path.basename(pl)
        if is_non_sys_path and fname_base in disguise_names:
            score += 25
            reasons.append("系统进程名落在非系统目录(伪装)")
        # 拼写陷阱
        for trap in ('scvhost', 'svch0st', 'csrsv', 'lsas', 'iexplore.exe'):
            if trap in fname_lower and trap != fname_base:
                score += 25
                reasons.append("可疑拼写陷阱")
                break

        # (d) 双扩展(.exe.exe / .pdf.exe / .jpg.exe)
        if fname_lower.endswith(('.exe.exe', '.scr.scr', '.bat.bat', '.cmd.cmd')):
            score += 20
            reasons.append("双扩展名")
        elif re.search(r'\.(pdf|docx?|xlsx?|jpg|jpeg|png|txt|zip|mp3|mp4)\.exe$', fname_lower):
            score += 25
            reasons.append("文档/图片伪装成可执行")

        # (e) DLL->SYS / .sys 落在偏僻目录(银狐DLL转SYS持久化)
        if ext == '.sys' and in_suspicious_dir:
            score += 30
            reasons.append("驱动文件落于可疑目录")
        if fname_lower.endswith('.dll') and in_suspicious_dir:
            score += 15
            reasons.append("DLL落于可疑目录")

        # (f) 可疑API链(PE导入) - 仅对PE文件
        if ext in ('.exe', '.dll', '.sys', '.scr', '.ocx'):
            try:
                pe_info = _parse_pe_all(path)
                apis = set(pe_info.get('apis', []) or [])
                apis_lower = {a.lower() for a in apis}
                if apis:
                    for chain_name, chain_apis, weight in EDR_API_CHAINS:
                        chain_lower = {a.lower() for a in chain_apis}
                        if chain_lower.issubset(apis_lower):
                            score += weight
                            reasons.append(f"可疑API链({chain_name})")
                            break  # 只计最重的一条链
                    # 加壳段(高熵)
                    sections = pe_info.get('sections', []) or []
                    for (sname, sentropy, ssize, schar) in sections:
                        try:
                            if sentropy > 7.2 and ssize > 4096:
                                score += 15
                                reasons.append(f"高熵加壳段({sname})")
                                break
                        except Exception:
                            pass
                # 未签名PE
                signer = pe_info.get('signer')
                if not signer:
                    score += 15
                    reasons.append("PE未签名")
            except Exception:
                # _parse_pe_all 失败也算未签名嫌疑
                score += 10
                reasons.append("PE解析异常(疑似加壳/损坏)")

        # (f2) MSI内嵌PE分析(EDR评分覆盖.msi)
        if ext == '.msi':
            try:
                if os.path.isfile(path):
                    msi_info = _analyze_msi_embedded(path)
                    if msi_info:
                        if msi_info['injection_apis']:
                            score += 25
                            reasons.append("MSI内嵌注入API")
                        if msi_info['obfuscated_pe_count'] > 0:
                            score += 30
                            reasons.append("MSI内嵌混淆PE")
                        if msi_info.get('packed_section_count', 0) > 0:
                            score += 30
                            reasons.append("MSI内嵌加壳PE")
                        if msi_info.get('zero_import_pe_count', 0) > 0 and msi_info['total_apis'] <= 5:
                            score += 25
                            reasons.append("MSI内嵌零导入PE")
                    try:
                        if not _extract_msi_signer(path):
                            score += 10
                            reasons.append("MSI未签名")
                    except Exception:
                        pass
            except Exception:
                pass

        # (g) 文件时间过新 + 未签名 + 偏僻目录
        try:
            mtime = os.path.getmtime(path)
            if (now := time.time()) - mtime < 7 * 86400 and in_suspicious_dir:
                # 仅当前面已判定未签名才加分(避免对刚下载的合法安装包误报)
                if "未签名" in ' '.join(reasons):
                    score += 15
                    reasons.append("近期落地")
        except Exception:
            pass

        # 单因素上限:若只有一类因素,封顶EDR_MAX_SINGLE_FACTOR
        # (用 reasons 数量近似;若所有reasons都来自同一类则压分)
        return min(score, 100), reasons

    # ---------------- DLL侧载/注入检测 ----------------
    def _maybe_check_injection(self, pid, name, path):
        if not g_settings.get("dll_sideload_protect", True):
            return
        if not getattr(self, '_module_ok', False):
            return
        fname_lower = (name or '').lower()
        if fname_lower not in EDR_SYS_PROC_FOR_INJECTION:
            return
        try:
            self._check_sideload_injection(pid, name, path)
        except Exception:
            pass

    def _enum_modules(self, pid):
        """枚举pid进程加载的所有模块,返回 [(modname, modpath), ...]。纯ctypes。"""
        result = []
        TH32CS_SNAPMODULE = 0x00000008
        TH32CS_SNAPMODULE32 = 0x00000010
        h = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if not h or h == ctypes.c_void_p(-1).value:
            return result
        try:
            me = self._ME32W()
            me.dwSize = ctypes.sizeof(self._ME32W)
            if self._k32.Module32FirstW(h, ctypes.byref(me)):
                while True:
                    try:
                        modpath = me.szExePath or ''
                        modname = me.szModule or ''
                        if modpath:
                            result.append((modname, modpath))
                    except Exception:
                        pass
                    if not self._k32.Module32NextW(h, ctypes.byref(me)):
                        break
        finally:
            try:
                self._k32.CloseHandle(h)
            except Exception:
                pass
        return result

    def _check_sideload_injection(self, pid, name, path):
        """检测系统/关键进程是否加载了可疑DLL(侧载/注入)。
        判定需多重命中(降低误报):未签名DLL + 非系统目录 + 伪装名/偏僻位置。"""
        mods = self._enum_modules(pid)
        if not mods:
            return
        suspicious_dlls = []
        for modname, modpath in mods:
            mname = (modname or '').lower()
            mpl = modpath.lower().replace('/', '\\')
            # 跳过系统目录的DLL
            try:
                if is_system_path(modpath):
                    continue
            except Exception:
                pass
            # 跳过宿主自身目录的同级DLL(DLL planting的经典,但合法软件常用,保守)
            # 只关注落在可疑目录 或 伪装系统DLL名 的模块
            in_susp = any(tok in mpl for tok in EDR_SUSPICIOUS_DIR_TOKENS)
            is_system_dll_name = mname in EDR_SYSTEM_DLL_NAMES
            if not (in_susp or is_system_dll_name):
                continue
            # 检查签名
            try:
                signer = _extract_signer(modpath)
            except Exception:
                signer = None
            if signer:
                continue  # 已签名DLL放过
            suspicious_dlls.append((modname, modpath, in_susp, is_system_dll_name))

        if not suspicious_dlls:
            return

        # 去重指纹(避免同一组可疑DLL反复弹窗)
        fp = tuple(sorted(d[1].lower() for d in suspicious_dlls))
        with self._inj_lock:
            last = self._inj_alerted.get((pid, fp), 0)
            if time.time() - last < 300:
                return
            self._inj_alerted[(pid, fp)] = time.time()
        # 清理
        if len(self._inj_alerted) > 200:
            with self._inj_lock:
                cutoff = time.time() - 600
                self._inj_alerted = {k: t for k, t in self._inj_alerted.items() if t > cutoff}

        # 构造原因
        reasons = []
        for (mn, mp, insusp, issys) in suspicious_dlls[:4]:
            tag = []
            if issys:
                tag.append("系统DLL伪装名")
            if insusp:
                tag.append("可疑目录")
            tag.append("未签名")
            reasons.append(f"{mn}({'+'.join(tag)})")
        reason_str = f"DLL侧载/注入: {'; '.join(reasons)}"
        _log(f"[EDR-注入] {name}({pid}) 加载可疑DLL: {[d[1] for d in suspicious_dlls]}")
        # 注入类威胁:终止宿主进程链并告警(不删DLL文件)
        self._handle_threat(pid, name, path, 75, [reason_str], "DLL侧载拦截")

    # ---------------- 威胁处理 ----------------
    def _handle_threat(self, pid, name, path, score, reasons, engine):
        """终止进程链 + 回滚落盘 + 溯源HTML + 托盘通知(阈值70还原所有操作)。"""
        # 并发保护:同时只处理一个EDR告警
        with self._alert_lock:
            if self._alert_active:
                _log(f"[EDR] 已有告警在处理,本次仅终止: {name}({pid})")
                self._terminate_only(pid, name, path)
                return
            self._alert_active = True
        try:
            # 终止进程链(已有方法,带 _CHAIN_STOP_NAMES 上限保护)
            mon = self._realtime
            if mon:
                chain = mon._terminate_chain(pid, name, path, full=True)
                chain_desc = " -> ".join(f"{n}({p})" for n, p, _ in chain) if len(chain) > 1 else name
                _log(f"[EDR-拦截] {chain_desc} {path} 评分={score} [{engine}]")
                _scan_log(f"[EDR-拦截] {name} {path} 评分={score} [{engine}]")
                reason_txt = "、".join(reasons[:6]) if reasons else engine
                ttype = classify_threat(path, rule_name="EDR", heuristic=True)
                _scan_log(f"[EDR] 类型={ttype} 原因={reason_txt}")
                _record_interception('EDR行为拦截', name, path, threat_type=ttype, confidence=score, engine=engine, action='terminated', extra=f'PID:{pid} 链:{chain_desc} 原因:{reason_txt}')
                _record_behavior(pid, name, path, 0, 'EDR拦截', f'评分:{score} 原因:{reason_txt}')
                # 还原攻击链: 回滚整链落盘(链内威胁文件会被隔离并通知)
                try:
                    mon._rollback_chain_drops({pid})
                except Exception as e:
                    _log(f"[EDR] 回滚异常: {e}")
            # 托盘通知 + 溯源报告(非阻塞)
            done = threading.Event()
            _gui_queue.put(lambda: self._show_alert(pid, name, path, score, reasons, done))
            done.wait(timeout=10)
        finally:
            with self._alert_lock:
                self._alert_active = False

    def _terminate_only(self, pid, name, path):
        """无弹窗仅终止(并发时降级)。"""
        mon = self._realtime
        if mon:
            try:
                mon._terminate_chain(pid, name, path)
                _log(f"[EDR-拦截] {name}({pid}) {path} (静默终止)")
            except Exception:
                pass

    def _show_alert(self, pid, name, path, score, reasons, done_event):
        """托盘模式:EDR 拦截通知(终止/回滚动作已在 _handle_threat 完成)。"""
        try:
            _notify("Threat Block", "Threat Block {}".format(name or 'Unknown.exe'))
            _edr_report_chain(pid, name or 'Unknown.exe', path or '',
                              [('EDR behavior score {}'.format(int(score or 0)), int(score or 0))] + [
                                  (str(r), 0) for r in (reasons or [])[:10]],
                              action='blocked')
        except Exception as e:
            _log(f"[EDR] 通知异常: {e}")
        done_event.set()

    # ---------------- 供 RealtimeMonitor 新进程入口调用 ----------------
    def score_quick(self, pid, name, path, ppid):
        """新进程入口的快速评分(不复用30s去重,因为入口已做过path去重)。
        返回 (score, reasons)。仅评分,不终止。"""
        fname_lower = (name or '').lower()
        try:
            if is_system_path(path):
                return 0, []
        except Exception:
            pass
        # 自家产品组件豁免EDR评分
        try:
            if self._realtime is not None and self._realtime._is_self_product(name, path):
                return 0, []
        except Exception:
            pass
        if fname_lower in EDR_EXEMPT_NAMES and verify_name_path(fname_lower, path):
            return 0, []
        # 可信签名豁免
        try:
            signer = _extract_signer(path)
            if signer:
                sl = signer.lower()
                TRUSTED = {'microsoft', 'google', 'apple', 'intel', 'nvidia', 'amd',
                           'oracle', 'adobe', 'tencent', 'alibaba', 'baidu', '360',
                           'kingsoft', 'wps', 'huawei', 'xiaomi', 'mozilla', 'opera',
                           'valve', 'epic', 'github', 'slack', 'zoom', 'dropbox',
                           'atlassian', 'discord', 'lenovo', 'realtek', 'samsung',
                           'vmware', 'citrix', 'kaspersky', 'symantec', 'mcafee',
                           'sophos', 'trend micro'}
                if any(t in sl for t in TRUSTED):
                    return 0, []
        except Exception:
            pass
        return self._calc_score(path, name)


class NotificationCenterPage(ScrollPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        header_card = CardWidget()
        header_card.setFixedHeight(80)
        hl = QHBoxLayout(header_card)
        hl.setContentsMargins(28, 16, 28, 16)
        hl.setSpacing(12)
        bell_lbl = QLabel()
        bell_lbl.setPixmap(app_icon().pixmap(32, 32))
        bell_lbl.setFixedSize(40, 40)
        bell_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bell_lbl.setStyleSheet("background: transparent;")
        hl.addWidget(bell_lbl)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("通知中心")
        title.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        title.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        title_col.addWidget(title)
        self.count_label = QLabel("共 0 条拦截记录")
        self.count_label.setFont(QFont("Microsoft YaHei", 9))
        self.count_label.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        title_col.addWidget(self.count_label)
        hl.addLayout(title_col)
        hl.addStretch()
        self.refresh_btn = SvgButton("refresh", 36, 20)
        self.refresh_btn.setFixedSize(36, 36)
        self.refresh_btn.setToolTip("刷新")
        hl.addWidget(self.refresh_btn)
        self.clear_btn = SvgButton("trash", 36, 20)
        self.clear_btn.setFixedSize(36, 36)
        self.clear_btn.setToolTip("清空记录")
        hl.addWidget(self.clear_btn)
        self.addWidget(header_card)
        self.list_card = CardWidget()
        ll = QVBoxLayout(self.list_card)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        self.list_widget = QListWidget()
        self.list_widget.setFrameShape(QFrame.Shape.NoFrame)
        self.list_widget.setFont(QFont("Microsoft YaHei", 9))
        self.list_widget.setWordWrap(True)
        self.list_widget.setStyleSheet(f"""
            QListWidget {{
                background-color: transparent;
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                background: transparent;
                border-bottom: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                padding: 14px 20px;
            }}
            QListWidget::item:selected {{
                background-color: rgb({th['bg_hover'].red()},{th['bg_hover'].green()},{th['bg_hover'].blue()});
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)
        ll.addWidget(self.list_widget)
        self.addWidget(self.list_card)
        self.addStretch()
        self.refresh_btn.clicked.connect(self.refresh)
        self.clear_btn.clicked.connect(self._clear)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)
        self.refresh()

    @staticmethod
    def _wrap_line(text, fm, max_w):
        if fm.horizontalAdvance(text) <= max_w:
            return [text]
        result = []
        current = ''
        for char in text:
            if fm.horizontalAdvance(current + char) > max_w and current:
                result.append(current)
                current = char
            else:
                current += char
        if current:
            result.append(current)
        return result

    def refresh(self):
        th = get_theme()
        with _g_intercept_lock:
            records = list(reversed(_g_intercept_records))
        self.count_label.setText(f"共 {len(records)} 条拦截记录")
        self.list_widget.setUpdatesEnabled(False)
        self.list_widget.clear()
        font = QFont("Microsoft YaHei", 9)
        fm = QFontMetrics(font)
        list_w = self.list_widget.width() - 48
        if list_w < 400:
            list_w = 600
        line_h = fm.height() + 4
        for rec in records:
            time_str = rec.get('time_str', '')
            rtype = rec.get('type', '')
            name = rec.get('name', '')
            path = rec.get('path', '')
            ttype = rec.get('threat_type', '')
            conf = rec.get('confidence', 0)
            engine = rec.get('engine', '')
            action = rec.get('action', '')
            extra = rec.get('extra', '')
            action_text = {'terminated': '已终止', 'blocked': '已阻止', 'failed': '终止失败', 'allowed': '已放行'}.get(action, action)
            conf_str = f" {conf}%" if conf else ""
            ttype_str = f" [{ttype}]" if ttype else ""
            engine_str = f" ({engine})" if engine else ""
            l1 = f"{time_str}  {rtype}"
            l2 = f"    {name}  {path}"
            l3 = f"    {action_text}{conf_str}{ttype_str}{engine_str}"
            all_lines = []
            all_lines.extend(self._wrap_line(l1, fm, list_w))
            all_lines.extend(self._wrap_line(l2, fm, list_w))
            all_lines.extend(self._wrap_line(l3, fm, list_w))
            if extra:
                all_lines.extend(self._wrap_line(f"    {extra}", fm, list_w))
            display = '\n'.join(all_lines)
            item = QListWidgetItem(display)
            item.setFont(font)
            item_h = max(70, len(all_lines) * line_h + 28)
            item.setSizeHint(QSize(0, item_h))
            if action in ('terminated', 'blocked', 'failed'):
                item.setForeground(th['danger'])
            else:
                item.setForeground(th['success'])
            self.list_widget.addItem(item)
        self.list_widget.setUpdatesEnabled(True)

    def _clear(self):
        global _g_intercept_records
        with _g_intercept_lock:
            _g_intercept_records.clear()
        self.refresh()

    def update_theme(self):
        super().update_theme()
        self.refresh()


class BehaviorChainWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self._scene.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.NoIndex)
        self._view = QGraphicsView(self._scene)
        self._view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._view.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self._view.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self._view.setBackgroundBrush(QBrush(QColor(255, 255, 255)))
        self._view.setFrameShape(QFrame.Shape.NoFrame)
        self._view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self._view.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.MinimalViewportUpdate)
        self._view.setOptimizationFlag(QGraphicsView.OptimizationFlag.DontSavePainterState, True)
        self._view.setOptimizationFlag(QGraphicsView.OptimizationFlag.DontAdjustForAntialiasing, True)
        self._view.setCacheMode(QGraphicsView.CacheModeFlag.CacheBackground)
        self._view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        th = get_theme()
        self._view.setStyleSheet(f"""
            QGraphicsView {{
                background-color: transparent;
                border: none;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._view)
        self._selected_pid = None
        self._name_font = QFont("Microsoft YaHei", 9, QFont.Weight.Bold)
        self._path_font = QFont("Microsoft YaHei", 8)
        self._act_font = QFont("Microsoft YaHei", 8)

    def show_chain(self, pid):
        self._selected_pid = pid
        self._draw()

    @staticmethod
    def _elide_path(path, max_len=42):
        """长路径中间省略,避免节点被超长文件名撑宽撑高。"""
        if not path or len(path) <= max_len:
            return path or ''
        head = max_len * 2 // 5
        return path[:head] + '...' + path[-(max_len - head):]

    def _calc_text_height(self, text, font, max_width):
        fm = QFontMetrics(font)
        total = 0
        for line in text.split('\n'):
            br = fm.boundingRect(QRect(0, 0, max_width, 10000), int(Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap), line)
            total += br.height() + 2
        return total

    def _calc_optimal_width(self, node, tree, visited=None):
        if visited is None:
            visited = set()
        pid = node['pid']
        if pid in visited:
            return 180
        visited.add(pid)
        padding = 12
        min_w = 180
        max_w = 320
        fm_name = QFontMetrics(self._name_font)
        fm_path = QFontMetrics(self._path_font)
        fm_act = QFontMetrics(self._act_font)
        name = node.get('name', '')
        path = node.get('path', '')
        actions = node.get('actions', [])
        path_short = self._elide_path(path)
        act_lines = [f"{a['time_str']} {a['action']}" for a in actions[-4:]]
        w = fm_name.horizontalAdvance(name)
        w = max(w, fm_name.horizontalAdvance(f"PID:{pid}"))
        w = max(w, fm_path.horizontalAdvance(path_short))
        for al in act_lines:
            w = max(w, fm_act.horizontalAdvance(al))
        optimal = max(min_w, min(w + padding * 2, max_w))
        for child in node.get('children', []):
            cpid = child['pid']
            if cpid in tree:
                optimal = max(optimal, self._calc_optimal_width(tree[cpid], tree, visited))
            else:
                cname = child.get('name', '')
                cpath = child.get('path', '')
                cw = fm_name.horizontalAdvance(cname)
                cw = max(cw, fm_name.horizontalAdvance(f"PID:{cpid}"))
                cw = max(cw, fm_path.horizontalAdvance(self._elide_path(cpath)))
                optimal = max(optimal, max(min_w, min(cw + padding * 2, max_w)))
        return optimal

    def _draw(self):
        th = get_theme()
        self._view.setUpdatesEnabled(False)
        self._scene.clear()
        if self._selected_pid is None:
            no_data = self._scene.addText("请从左侧列表选择一个被拦截的进程")
            no_data.setDefaultTextColor(QColor(130, 130, 140))
            no_data.setFont(QFont("Microsoft YaHei", 11))
            no_data.setPos(40, 40)
            self._view.setSceneRect(QRectF(0, 0, 400, 100))
            self._view.setUpdatesEnabled(True)
            return
        with _g_behavior_lock:
            tree = dict(_g_behavior_tree)
        if self._selected_pid not in tree:
            no_data = self._scene.addText("该进程的行为链数据已过期")
            no_data.setDefaultTextColor(QColor(130, 130, 140))
            no_data.setFont(QFont("Microsoft YaHei", 11))
            no_data.setPos(40, 40)
            self._view.setSceneRect(QRectF(0, 0, 400, 100))
            self._view.setUpdatesEnabled(True)
            return
        root_node = tree[self._selected_pid]
        node_w = self._calc_optimal_width(root_node, tree)
        max_x = [0]
        max_y = [0]
        self._draw_horizontal(root_node, tree, 40, 40, 0, th, max_x, max_y, node_w)
        self._view.setSceneRect(QRectF(0, 0, max(max_x[0] + 60, 400), max(max_y[0] + 60, 200)))
        self._view.setUpdatesEnabled(True)
        self._view.viewport().update()

    def _draw_horizontal(self, node, tree, x, y, depth, th, max_x, max_y, node_w):
        gap_x = 50
        gap_y = 20
        padding = 10
        text_max_w = node_w - padding * 2
        pid = node['pid']
        name = node.get('name', '')
        path = node.get('path', '')
        actions = node.get('actions', [])
        alive = node.get('alive', True)
        status_txt = '' if alive else '（已退出）'
        name_text = f"{name}{status_txt}\nPID:{pid}"
        name_h = self._calc_text_height(name_text, self._name_font, text_max_w)
        path_short = self._elide_path(path)
        path_h = self._calc_text_height(path_short, self._path_font, text_max_w)
        act_lines = []
        for a in actions[-4:]:
            act_lines.append(f"{a['time_str']} {a['action']}")
        act_text = '\n'.join(act_lines) if act_lines else '无行为记录'
        act_h = self._calc_text_height(act_text, self._act_font, text_max_w)
        node_h = name_h + path_h + act_h + padding * 2 + 6
        node_h = max(node_h, 60)
        rect_item = QGraphicsRectItem(0, 0, node_w, node_h)
        rect_item.setPos(x, y)
        rect_item.setPen(QPen(th['danger'] if depth == 0 else th['accent'], 2 if depth == 0 else 1.5))
        if depth == 0:
            rect_item.setBrush(QBrush(QColor(255, 235, 235)))
        else:
            rect_item.setBrush(QBrush(QColor(240, 245, 255)))
        self._scene.addItem(rect_item)
        name_item = self._scene.addText(name_text)
        name_item.setDefaultTextColor(QColor(32, 32, 35))
        name_item.setFont(self._name_font)
        name_item.setTextWidth(text_max_w)
        name_item.setPos(x + padding, y + padding)
        path_item = self._scene.addText(path_short)
        path_item.setDefaultTextColor(QColor(130, 130, 140))
        path_item.setFont(self._path_font)
        path_item.setTextWidth(text_max_w)
        path_item.setPos(x + padding, y + padding + name_h)
        act_item = self._scene.addText(act_text)
        act_item.setDefaultTextColor(QColor(100, 100, 110))
        act_item.setFont(self._act_font)
        act_item.setTextWidth(text_max_w)
        act_item.setPos(x + padding, y + padding + name_h + path_h + 4)
        if x + node_w > max_x[0]:
            max_x[0] = x + node_w
        if y + node_h > max_y[0]:
            max_y[0] = y + node_h
        children = node.get('children', [])
        child_y = y
        for child in children:
            cpid = child['pid']
            cname = child.get('name', '')
            cpath = child.get('path', '')
            child_x = x + node_w + gap_x
            if cpid in tree:
                child_node = tree[cpid]
                child_h = self._calc_subtree_height(child_node, tree, node_w, gap_x, gap_y)
                mid_y = child_y + child_h / 2
                line = QGraphicsLineItem(x + node_w, y + node_h / 2, child_x, mid_y)
                line.setPen(QPen(QColor(200, 200, 210), 1.5))
                self._scene.addItem(line)
                self._draw_horizontal(child_node, tree, child_x, child_y, depth + 1, th, max_x, max_y, node_w)
                child_y += child_h + gap_y
            else:
                cpath_short = self._elide_path(cpath)
                c_name_text = f"{cname}\nPID:{cpid}"
                c_name_h = self._calc_text_height(c_name_text, self._name_font, text_max_w)
                c_path_h = self._calc_text_height(cpath_short, self._path_font, text_max_w)
                c_node_h = c_name_h + c_path_h + padding * 2 + 6
                c_node_h = max(c_node_h, 60)
                rect2 = QGraphicsRectItem(0, 0, node_w, c_node_h)
                rect2.setPos(child_x, child_y)
                rect2.setBrush(QBrush(QColor(255, 250, 240)))
                rect2.setPen(QPen(QColor(200, 180, 120), 1.5))
                self._scene.addItem(rect2)
                n2 = self._scene.addText(c_name_text)
                n2.setDefaultTextColor(QColor(130, 100, 50))
                n2.setFont(self._name_font)
                n2.setTextWidth(text_max_w)
                n2.setPos(child_x + padding, child_y + padding)
                n3 = self._scene.addText(cpath_short)
                n3.setDefaultTextColor(QColor(130, 100, 50))
                n3.setFont(self._path_font)
                n3.setTextWidth(text_max_w)
                n3.setPos(child_x + padding, child_y + padding + c_name_h)
                mid_y = child_y + c_node_h / 2
                line = QGraphicsLineItem(x + node_w, y + node_h / 2, child_x, mid_y)
                line.setPen(QPen(QColor(200, 200, 210), 1.5))
                self._scene.addItem(line)
                if child_x + node_w > max_x[0]:
                    max_x[0] = child_x + node_w
                if child_y + c_node_h > max_y[0]:
                    max_y[0] = child_y + c_node_h
                child_y += c_node_h + gap_y

    def _calc_subtree_height(self, node, tree, node_w, gap_x, gap_y):
        padding = 10
        text_max_w = node_w - padding * 2
        name = node.get('name', '')
        pid = node['pid']
        path = node.get('path', '')
        actions = node.get('actions', [])
        name_text = f"{name}\nPID:{pid}"
        name_h = self._calc_text_height(name_text, self._name_font, text_max_w)
        path_short = self._elide_path(path)
        path_h = self._calc_text_height(path_short, self._path_font, text_max_w)
        act_lines = [f"{a['time_str']} {a['action']}" for a in actions[-4:]]
        act_text = '\n'.join(act_lines) if act_lines else '无行为记录'
        act_h = self._calc_text_height(act_text, self._act_font, text_max_w)
        self_h = max(name_h + path_h + act_h + padding * 2 + 6, 60)
        children = node.get('children', [])
        if not children:
            return self_h
        total = 0
        for child in children:
            cpid = child['pid']
            if cpid in tree:
                total += self._calc_subtree_height(tree[cpid], tree, node_w, gap_x, gap_y) + gap_y
            else:
                cname = child.get('name', '')
                cpath = child.get('path', '')
                c_name_text = f"{cname}\nPID:{cpid}"
                c_name_h = self._calc_text_height(c_name_text, self._name_font, text_max_w)
                c_path_h = self._calc_text_height(self._elide_path(cpath), self._path_font, text_max_w)
                total += max(c_name_h + c_path_h + padding * 2 + 6, 60) + gap_y
        return max(total - gap_y, self_h)


class BehaviorChainPage(ScrollPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        th = get_theme()
        header_card = CardWidget()
        header_card.setFixedHeight(70)
        hl = QHBoxLayout(header_card)
        hl.setContentsMargins(28, 16, 28, 16)
        hl.setSpacing(12)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(render_svg("network", th["accent"], 28))
        icon_lbl.setFixedSize(36, 36)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("background: transparent;")
        hl.addWidget(icon_lbl)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("行为链拓扑")
        title.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        title.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        title_col.addWidget(title)
        sub = QLabel("选择被拦截的进程查看其行为链")
        sub.setFont(QFont("Microsoft YaHei", 9))
        sub.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});")
        title_col.addWidget(sub)
        hl.addLayout(title_col)
        hl.addStretch()
        self.addWidget(header_card)
        main_card = CardWidget()
        main_card.setMinimumHeight(520)
        ml = QHBoxLayout(main_card)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)
        list_container = QWidget()
        list_container.setFixedWidth(280)
        ll = QVBoxLayout(list_container)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        list_header = QLabel("已拦截进程")
        list_header.setFixedHeight(36)
        list_header.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Medium))
        list_header.setStyleSheet(f"background: transparent; color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()}); padding-left: 16px;")
        ll.addWidget(list_header)
        self.proc_list = QListWidget()
        self.proc_list.setFrameShape(QFrame.Shape.NoFrame)
        self.proc_list.setFont(QFont("Microsoft YaHei", 9))
        self.proc_list.setWordWrap(True)
        self.proc_list.setStyleSheet(f"""
            QListWidget {{
                background-color: transparent;
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                background: transparent;
                border-bottom: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                padding: 14px 16px;
            }}
            QListWidget::item:selected {{
                background-color: rgb({th['bg_hover'].red()},{th['bg_hover'].green()},{th['bg_hover'].blue()});
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 0;
            }}
            QScrollBar::handle:vertical {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-height: 40px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 8px;
                margin: 0 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 4px;
                min-width: 40px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
        """)
        ll.addWidget(self.proc_list)
        ml.addWidget(list_container)
        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setStyleSheet(f"background: rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});")
        ml.addWidget(sep)
        self.chain_widget = BehaviorChainWidget()
        self.chain_widget.setMinimumHeight(480)
        ml.addWidget(self.chain_widget, 1)
        main_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.addWidget(main_card)
        self.proc_list.itemClicked.connect(self._on_select)
        self._last_record_count = -1
        self._timer = QTimer(self)
        self._timer.setSingleShot(False)
        self._timer.timeout.connect(self._refresh_list_lazy)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(50, self._refresh_list)
        self._timer.start(3000)

    def hideEvent(self, event):
        super().hideEvent(event)
        self._timer.stop()

    def _refresh_list_lazy(self):
        with _g_intercept_lock:
            count = len(_g_intercept_records)
        if count != self._last_record_count:
            self._refresh_list()

    def _refresh_list(self):
        with _g_intercept_lock:
            records = list(reversed(_g_intercept_records))
        intercept_recs = [r for r in records if '拦截' in r.get('type', '') or '敏感' in r.get('type', '')]
        self._last_record_count = len(_g_intercept_records)
        current_item = self.proc_list.currentItem()
        current_data = current_item.data(Qt.ItemDataRole.UserRole) if current_item else None
        self.proc_list.setUpdatesEnabled(False)
        self.proc_list.clear()
        font = QFont("Microsoft YaHei", 9)
        fm = QFontMetrics(font)
        list_w = self.proc_list.width() - 32
        if list_w < 200:
            list_w = 248
        line_h = fm.height() + 4
        restore_idx = -1
        for idx, rec in enumerate(intercept_recs):
            time_str = rec.get('time_str', '')
            rtype = rec.get('type', '')
            name = rec.get('name', '')
            ttype = rec.get('threat_type', '')
            conf = rec.get('confidence', 0)
            extra = rec.get('extra', '')
            pid_str = ''
            if 'PID:' in extra:
                try:
                    pid_str = extra.split('PID:')[1].split()[0].rstrip(',')
                except:
                    pass
            conf_str = f" {conf}%" if conf else ""
            ttype_str = f" [{ttype}]" if ttype else ""
            l1 = f"{time_str}  {rtype}"
            l2 = f"    {name}{ttype_str}{conf_str}"
            l3 = f"    PID:{pid_str}" if pid_str else ""
            all_lines = []
            for seg in [l1, l2, l3]:
                if not seg:
                    continue
                if fm.horizontalAdvance(seg) <= list_w:
                    all_lines.append(seg)
                else:
                    cur = ''
                    for ch in seg:
                        if fm.horizontalAdvance(cur + ch) > list_w and cur:
                            all_lines.append(cur)
                            cur = ch
                        else:
                            cur += ch
                    if cur:
                        all_lines.append(cur)
            display = '\n'.join(all_lines)
            item = QListWidgetItem(display)
            item.setFont(font)
            item.setData(Qt.ItemDataRole.UserRole, rec)
            item_h = max(60, len(all_lines) * line_h + 24)
            item.setSizeHint(QSize(0, item_h))
            self.proc_list.addItem(item)
            if current_data and rec == current_data:
                restore_idx = idx
        self.proc_list.setUpdatesEnabled(True)
        if restore_idx >= 0:
            self.proc_list.setCurrentRow(restore_idx)

    def _on_select(self, item):
        rec = item.data(Qt.ItemDataRole.UserRole)
        if not rec:
            return
        extra = rec.get('extra', '')
        pid = 0
        if 'PID:' in extra:
            try:
                pid_str = extra.split('PID:')[1].split()[0].rstrip(',')
                pid = int(pid_str)
            except:
                pass
        if pid:
            self.chain_widget.show_chain(pid)
        else:
            name = rec.get('name', '')
            with _g_behavior_lock:
                for p, node in _g_behavior_tree.items():
                    if node.get('name', '') == name:
                        self.chain_widget.show_chain(p)
                        return

    def update_theme(self):
        super().update_theme()
        self._refresh_list()


class SevenEndPointWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setMinimumSize(900, 600)
        self.resize(960, 640)
        self._drag_offset = None
        self._maximized = False
        self._normal_geometry = None
        self._window_radius = 10
        screen = QApplication.primaryScreen().geometry()
        self.move((screen.width() - self.width()) // 2, (screen.height() - self.height()) // 2)
        self.setWindowTitle("SevenEndPointSecurity")
        self.setWindowIcon(app_icon())
        self._shadow_margin = 24
        self._root_widget = QWidget(self)
        self._root_layout = QVBoxLayout(self._root_widget)
        self._root_layout.setContentsMargins(0, 0, 0, 0)
        self._root_layout.setSpacing(0)
        self._shadow_effect = QGraphicsDropShadowEffect(self._root_widget)
        self._shadow_effect.setBlurRadius(30)
        self._shadow_effect.setColor(QColor(0, 0, 0, 55))
        self._shadow_effect.setOffset(0, 2)
        self._root_widget.setGraphicsEffect(self._shadow_effect)
        # 窗口焦点阴影:聚焦=深阴影,失焦=浅阴影(深↔淡平滑过渡)
        self._shadow_focused = {'blur': 46, 'alpha': 115, 'dy': 7}
        self._shadow_defocus = {'blur': 18, 'alpha': 36, 'dy': 2}
        self._shadow_anim = QVariantAnimation(self)
        self._shadow_anim.setDuration(280)
        self._shadow_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._shadow_anim.valueChanged.connect(self._apply_shadow_t)
        self._apply_shadow_t(1.0)  # 初始为聚焦深阴影
        self.title_bar = TitleBar(self._root_widget)
        self._root_layout.addWidget(self.title_bar)
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        self.sidebar = Sidebar(self._root_widget)
        body_layout.addWidget(self.sidebar)
        self.stacked = AnimatedStackedWidget()
        self.stacked.setStyleSheet("background: transparent;")
        body_layout.addWidget(self.stacked, 1)
        self._root_layout.addLayout(body_layout, 1)
        self.home_page = HomePage(self._root_widget)
        self.scan_page = ScanPage(self._root_widget)
        self.notify_page = NotificationCenterPage(self._root_widget)
        self.behavior_page = BehaviorChainPage(self._root_widget)
        self.settings_page = SettingsPage(self._root_widget)
        self.tool_page = ToolPage(self._root_widget)
        self.about_page = AboutPage(self._root_widget)
        self.pages = {
            "home": self.home_page,
            "scan": self.scan_page,
            "notify": self.notify_page,
            "behavior": self.behavior_page,
            "settings": self.settings_page,
            "tool": self.tool_page,
            "about": self.about_page,
        }
        for page in self.pages.values():
            self.stacked.addWidget(page)
        self.sidebar.navClicked.connect(self.navigateTo)
        self.title_bar.min_btn.clicked.connect(self.showMinimized)
        self.title_bar.close_btn.clicked.connect(self._on_close)
        self.scan_page.scanRequested.connect(self._start_scan)
        self.scan_page.stopRequested.connect(self._stop_scan)
        self.scan_page.customScanRequested.connect(self._custom_scan)
        self.scan_page.view_result_btn.clicked.connect(self._show_full_report)
        self.scan_page.batch_quarantine_btn.clicked.connect(self._batch_quarantine)
        self.scan_page.batch_delete_btn.clicked.connect(self._batch_delete)
        self.scan_page.batch_ignore_btn.clicked.connect(self._batch_ignore)
        self.sidebar.setActive("home")
        self._apply_theme()
        self._scanning = False
        self._stop_requested = False
        self._scanned_count = 0
        self._threat_count = 0
        self._threat_list = []
        self._last_ui_update = 0
        self._current_nav = "home"
        self._realtime_monitor = None
        self._edr = None  # BehaviorEDR 实例(由 _start_realtime_monitor 创建)
        self._file_monitor = None
        self._mbr_guard = None
        self._etw_monitor = None
        self._scan_dialog_active = False
        self._gui_timer = QTimer(self)
        self._gui_timer.timeout.connect(_exec_gui)
        self._gui_timer.start(50)
        QTimer.singleShot(500, self._init_engine)

    def navigateTo(self, target):
        if target in self.pages:
            self.stacked.setCurrentWidget(self.pages[target])
            self.sidebar.setActive(target)
            self._current_nav = target

    def _custom_scan(self):
        from PyQt6.QtWidgets import QFileDialog
        path = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if path:
            self._start_scan(path)

    def _start_scan(self, mode):
        global g_scanner
        if self._scanning:
            return
        if not g_scanner:
            self.scan_page.progress_label.setText("引擎未就绪，请稍候")
            _log("[扫描] 引擎未就绪")
            return
        self._scanning = True
        self._stop_requested = False
        self._scanned_count = 0
        self._threat_count = 0
        self._threat_list = []
        self._last_ui_update = 0
        self.scan_page._scanning = True
        self.scan_page._scan_start_time = time.time()
        self.scan_page.btn_stop.setVisible(True)
        self.scan_page.progress_label.setText("扫描中...")
        self.scan_page.progress_bar.setValue(0)
        self.scan_page.start_timer()
        self._clear_virus_list()
        _scan_log(f"=== 开始扫描 ({mode}) ===")
        _log(f"[扫描] 开始扫描 ({mode})")
        threading.Thread(target=self._run_scan, args=(mode,), daemon=True).start()

    def _stop_scan(self):
        if self._scanning:
            self._stop_requested = True
            self.scan_page.progress_label.setText("正在停止...")

    def _run_scan(self, mode_or_path):
        global g_scanner
        try:
            if mode_or_path == "quick":
                dirs = ['C:\\Program Files', 'C:\\Program Files (x86)',
                        os.path.join(os.environ.get("USERPROFILE", ""), 'Downloads'),
                        os.path.join(os.environ.get("USERPROFILE", ""), 'Desktop')]
            elif mode_or_path == "full":
                import string
                dirs = [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]
            elif os.path.isdir(mode_or_path):
                dirs = [mode_or_path]
            elif os.path.isfile(mode_or_path):
                dirs = []
                self._scan_single_file(mode_or_path)
            else:
                dirs = []
            for d in dirs:
                if self._stop_requested:
                    break
                if os.path.isdir(d):
                    self._scan_dir(d)
        except Exception as e:
            _gui_queue.put(lambda: self.scan_page.progress_label.setText("扫描错误"))
            _log(f"[扫描] 错误: {e}")
        finally:
            self._scanning = False
            _gui_queue.put(lambda: self.scan_page._set_scanning_done(self._threat_count))
            _scan_log(f"=== 扫描结束: {self._scanned_count} 文件, {self._threat_count} 威胁 ===")
            _log(f"[扫描] 完成: {self._scanned_count} 文件, {self._threat_count} 威胁")

    def _scan_dir(self, dpath):
        norm_path = os.path.normpath(dpath).lower().replace('/', '\\')
        system_roots = ['c:\\windows', 'c:\\$recycle.bin', 'c:\\system volume information']
        for sr in system_roots:
            if norm_path == sr or norm_path.startswith(sr + '\\'):
                _log(f"[扫描] 跳过系统目录: {dpath}")
                return
        _skip_dir_names = {
            '$recycle.bin', 'system volume information', 'winsxs',
            'inetcache', 'assembly', 'pasw', 'pedefense',
            '__pycache__', 'node_modules', '.git', '.svn',
            'esd', 'drvpath', 'drivers', 'driverstore',
            '$windows.~ws', '$windows.~q', 'windows.old',
            'programdata', 'windows defender', 'avast software',
        }
        _skip_path_parts = {
            'windows\\system32', 'windows\\syswow64', 'windows\\assembly',
            'windows\\installer', 'windows\\winsxs', 'windows\\servicing',
            'windows\\softwaredistribution', 'windows\\temp',
            'program files\\windowsapps', 'program files (x86)\\windowsapps',
            'appdata\\local\\temp', 'appdata\\local\\microsoft\\windows\\inetcache',
            'appdata\\local\\microsoft\\windows\\webcache',
            'appdata\\local\\packages',
            'esd\\', 'drvpath\\', 'drivers\\', 'driverstore\\',
            '$windows.~ws\\', '$windows.~q\\', 'windows.old\\',
            'programdata\\', 'windows defender\\', 'avast software\\',
        }
        scan_exts = {'.exe', '.dll', '.sys', '.vbs', '.ps1', '.js', '.bat', '.cmd', '.py', '.pyw', '.msi'}
        import queue as _queue_mod
        # exe 模式: 只起一个 SevenEngine 常驻进程, 避免多进程重复加载引擎; code 模式保留多 worker
        _n_workers = 1 if _engine_use_exe() else 8
        _file_q = _queue_mod.Queue(maxsize=500)
        _stop_flag = threading.Event()
        _lock = threading.Lock()
        _procs = []
        try:
            for _ in range(_n_workers):
                _p = subprocess.Popen(
                    _worker_cmd(),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, bufsize=1, text=True,
                    encoding='utf-8', errors='replace', cwd=BASE_DIR
                )
                # 热身: 等引擎解压+模型加载完成, 首个文件不再白等13秒
                try:
                    _p.stdin.write(json.dumps({"path": "__warmup__"}) + "\n")
                    _p.stdin.flush()
                    _p.stdout.readline()
                except Exception:
                    pass
                _procs.append(_p)
        except Exception as _e:
            _log(f"[扫描] 启动子进程失败: {_e}")
            for _p in _procs:
                try: _p.terminate()
                except: pass
            return

        def _walk_producer():
            try:
                for root, dirs, files in os.walk(dpath):
                    if self._stop_requested:
                        break
                    pruned = []
                    for d in dirs:
                        dl = d.lower()
                        if dl in _skip_dir_names:
                            continue
                        full = os.path.normpath(os.path.join(root, d)).lower().replace('/', '\\')
                        if any(sp in full for sp in _skip_path_parts):
                            continue
                        pruned.append(d)
                    dirs[:] = pruned
                    for f in files:
                        if self._stop_requested:
                            break
                        ext = os.path.splitext(f)[1].lower()
                        if ext not in scan_exts:
                            continue
                        fp = os.path.join(root, f)
                        # 白名单：不入队扫描（覆盖整目录白名单与单文件白名单）
                        try:
                            if g_scanner is not None and g_scanner.whitelist.contains(fp):
                                continue
                        except Exception:
                            pass
                        while True:
                            try:
                                _file_q.put(fp, timeout=5)
                                break
                            except:
                                if self._stop_requested:
                                    break
            finally:
                for _ in range(_n_workers):
                    _file_q.put(None)

        def _manage_worker(idx):
            _proc = _procs[idx]
            _stdin = _proc.stdin
            _stdout = _proc.stdout
            while True:
                try:
                    fp = _file_q.get(timeout=2)
                except:
                    if _stop_flag.is_set():
                        return
                    continue
                if fp is None:
                    return
                if self._stop_requested:
                    continue
                try:
                    _stdin.write(json.dumps({"path": fp}) + "\n")
                    _stdin.flush()
                    line = _stdout.readline()
                except Exception:
                    return
                if not line:
                    return
                try:
                    data = json.loads(line)
                    res = data.get("result", "CLEAN")
                    conf = data.get("conf", 0)
                    vt = data.get("vt", "")
                except:
                    res, conf, vt = "ERROR", 0, ""
                with _lock:
                    self._scanned_count += 1
                _update_ui = (time.time() - self._last_ui_update >= 0.05)
                if _update_ui:
                    self._last_ui_update = time.time()
                    _gui_queue.put(lambda p=fp: self.scan_page.current_file_label.setText(
                        QFontMetrics(self.scan_page.current_file_label.font()).elidedText(
                            p, Qt.TextElideMode.ElideMiddle, max(200, self.scan_page.current_file_label.width() - 8))))
                if res.startswith("MALICIOUS"):
                    with _lock:
                        self._threat_count += 1
                    _gui_queue.put(lambda c=self._scanned_count, t=self._threat_count: self.scan_page.stat_label.setText(f"已扫描: {c}  |  威胁: {t}"))
                    _scan_log(f"[!] 发现威胁: {fp} [{vt}] {conf}%")
                    _log(f"[威胁] {os.path.basename(fp)} [{vt}] {conf}%")
                    self._add_threat_item(os.path.basename(fp), vt, conf, fp)
                if _update_ui:
                    _gui_queue.put(lambda c=self._scanned_count, t=self._threat_count: self.scan_page.stat_label.setText(f"已扫描: {c}  |  威胁: {t}"))

        _walk_t = threading.Thread(target=_walk_producer, daemon=True)
        _walk_t.start()
        _mgr_threads = []
        for i in range(_n_workers):
            _t = threading.Thread(target=_manage_worker, args=(i,), daemon=True)
            _t.start()
            _mgr_threads.append(_t)
        try:
            while True:
                if self._stop_requested:
                    _stop_flag.set()
                    for _p in _procs:
                        try: _p.terminate()
                        except: pass
                    break
                _walk_alive = _walk_t.is_alive()
                _mgr_alive = any(t.is_alive() for t in _mgr_threads)
                if not _walk_alive and not _mgr_alive:
                    break
                time.sleep(0.1)
        finally:
            _stop_flag.set()
            while not _file_q.empty():
                try: _file_q.get_nowait()
                except: break
            for _ in range(_n_workers):
                try: _file_q.put_nowait(None)
                except: pass
            for _p in _procs:
                try: _p.stdin.close()
                except: pass
                try: _p.kill()
                except: pass
            for _t in _mgr_threads:
                _t.join(timeout=5)

    def _scan_single_file(self, fp):
        global g_scanner
        try:
            # 白名单：跳过扫描，不计入已扫描数、不弹威胁
            if g_scanner is not None and g_scanner.whitelist.contains(fp):
                _scan_log(f"[白名单-跳过] {fp}")
                return
            _gui_queue.put(lambda p=fp: self.scan_page.current_file_label.setText(
                QFontMetrics(self.scan_page.current_file_label.font()).elidedText(
                    p, Qt.TextElideMode.ElideMiddle, max(200, self.scan_page.current_file_label.width() - 8))))
            res, conf, vt = g_scanner.scan_file(fp)
            self._scanned_count += 1
            _gui_queue.put(lambda c=self._scanned_count, t=self._threat_count: self.scan_page.stat_label.setText(f"已扫描: {c}  |  威胁: {t}"))
            _gui_queue.put(lambda v=100: self.scan_page.progress_bar.setValue(v))
            if res.startswith("MALICIOUS"):
                self._threat_count += 1
                _gui_queue.put(lambda c=self._scanned_count, t=self._threat_count: self.scan_page.stat_label.setText(f"已扫描: {c}  |  威胁: {t}"))
                _scan_log(f"[!] 发现威胁: {fp} [{vt}] {conf}%")
                _log(f"[威胁] {os.path.basename(fp)} [{vt}] {conf}%")
                self._add_threat_item(os.path.basename(fp), vt, conf, fp)
            else:
                _scan_log(f"[安全] {fp}")
        except Exception as _ex:
            _log(f"[扫描异常] {fp}: {_ex}")

    def _clear_virus_list(self):
        _gui_queue.put(self._do_clear_virus_list)

    def _do_clear_virus_list(self):
        for i in reversed(range(self.scan_page.virus_list_layout.count())):
            w = self.scan_page.virus_list_layout.itemAt(i).widget()
            if w and w != self.scan_page._placeholder:
                w.setParent(None)
                w.deleteLater()
        self.scan_page._placeholder.setText("暂无威胁发现")
        self.scan_page._placeholder.setVisible(True)

    def _add_threat_item(self, name, vt, conf, path):
        _gui_queue.put(lambda n=name, v=vt, c=conf, p=path: self._do_add_threat_item(n, v, c, p))

    def _do_add_threat_item(self, name, vt, conf, path):
        self.scan_page._placeholder.setVisible(False)
        self._threat_list.append((name, vt, conf, path))
        th = get_theme()
        row = CardWidget()
        row.setClickable(True)
        row.setFixedHeight(52)
        row._threat_path = path
        row._selected = False
        row._checkbox = QCheckBox()
        row._checkbox.setStyleSheet("background: transparent;")
        row._checkbox.toggled.connect(lambda c, r=row: self._on_threat_check(r, c))
        layout = QHBoxLayout(row)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)
        layout.addWidget(row._checkbox)
        name_label = QLabel(name[:35] + ("..." if len(name) > 35 else ""))
        name_label.setFont(QFont("Microsoft YaHei", 9))
        name_label.setStyleSheet(f"background: transparent; color: rgb({th['text_primary'].red()},{th['text_primary'].green()},{th['text_primary'].blue()});")
        name_label.setFixedWidth(200)
        layout.addWidget(name_label)
        vt_label = QLabel(f"[{vt or '未知'}] {conf}%")
        vt_label.setFont(QFont("Microsoft YaHei", 9))
        vt_label.setStyleSheet(f"background: transparent; color: rgb({th['danger'].red()},{th['danger'].green()},{th['danger'].blue()});")
        layout.addWidget(vt_label, 1)
        quarantine_btn = QPushButton("隔离")
        quarantine_btn.setFixedSize(52, 26)
        quarantine_btn.setFont(QFont("Microsoft YaHei", 8))
        quarantine_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        quarantine_btn.clicked.connect(lambda checked, p=path, r=row: self._quarantine_file(p, r))
        layout.addWidget(quarantine_btn)
        delete_btn = QPushButton("删除")
        delete_btn.setFixedSize(52, 26)
        delete_btn.setFont(QFont("Microsoft YaHei", 8))
        delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        delete_btn.clicked.connect(lambda checked, p=path, r=row: self._delete_threat(p, r))
        layout.addWidget(delete_btn)
        ignore_btn = QPushButton("忽略")
        ignore_btn.setFixedSize(52, 26)
        ignore_btn.setFont(QFont("Microsoft YaHei", 8))
        ignore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ignore_btn.clicked.connect(lambda checked, r=row: self._ignore_threat(r))
        layout.addWidget(ignore_btn)
        self.scan_page.virus_list_layout.addWidget(row)

    def _remove_threat_row(self, row):
        try:
            self.scan_page.virus_list_layout.removeWidget(row)
            row.setParent(None)
            row.deleteLater()
        except:
            pass
        self.scan_page._update_batch_buttons()

    def _on_threat_check(self, row, checked):
        row._selected = checked
        self.scan_page._update_batch_buttons()

    def _quarantine_file(self, path, row=None):
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            dest = os.path.join(QUARANTINE_DIR, os.path.basename(path) + ".quarantine")
            shutil.move(path, dest)
            _scan_log(f"[已隔离] {path}")
            _log(f"[隔离] {path} -> {dest}")
            if row:
                self._remove_threat_row(row)
        except Exception as e:
            _log(f"[隔离失败] {path}: {e}")
            QMessageBox.warning(self, "隔离失败", str(e))

    def _delete_threat(self, path, row=None):
        try:
            os.remove(path)
            _scan_log(f"[已删除] {path}")
            _log(f"[删除] {path}")
            if row:
                self._remove_threat_row(row)
        except Exception as e:
            _log(f"[删除失败] {path}: {e}")
            QMessageBox.warning(self, "删除失败", str(e))

    def _ignore_threat(self, row=None):
        _scan_log(f"[已忽略] 威胁项")
        _log(f"[忽略] 威胁项")
        if row:
            self._remove_threat_row(row)

    def _get_selected_rows(self):
        rows = []
        for i in range(self.scan_page.virus_list_layout.count()):
            w = self.scan_page.virus_list_layout.itemAt(i).widget()
            if w and hasattr(w, '_selected') and w._selected:
                rows.append(w)
        return rows

    def _batch_quarantine(self):
        rows = self._get_selected_rows()
        if not rows:
            return
        reply = QMessageBox.question(self, "批量隔离", f"确认隔离 {len(rows)} 个威胁文件？",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        success = 0
        for row in rows:
            path = getattr(row, '_threat_path', None)
            if path:
                try:
                    os.makedirs(QUARANTINE_DIR, exist_ok=True)
                    dest = os.path.join(QUARANTINE_DIR, os.path.basename(path) + ".quarantine")
                    shutil.move(path, dest)
                    _scan_log(f"[已隔离] {path}")
                    success += 1
                except Exception as e:
                    _log(f"[隔离失败] {path}: {e}")
            self._remove_threat_row(row)
        _log(f"[批量操作] 隔离 {success}/{len(rows)} 个文件")

    def _batch_delete(self):
        rows = self._get_selected_rows()
        if not rows:
            return
        reply = QMessageBox.question(self, "批量删除", f"确认永久删除 {len(rows)} 个威胁文件？\n此操作不可恢复！",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        success = 0
        for row in rows:
            path = getattr(row, '_threat_path', None)
            if path:
                try:
                    os.remove(path)
                    _scan_log(f"[已删除] {path}")
                    success += 1
                except Exception as e:
                    _log(f"[删除失败] {path}: {e}")
            self._remove_threat_row(row)
        _log(f"[批量操作] 删除 {success}/{len(rows)} 个文件")

    def _batch_ignore(self):
        rows = self._get_selected_rows()
        if not rows:
            return
        for row in rows:
            _scan_log(f"[已忽略] {getattr(row, '_threat_path', '?')}")
            self._remove_threat_row(row)
        _log(f"[批量操作] 忽略 {len(rows)} 个文件")
        self.scan_page.select_all_chk.blockSignals(True)
        self.scan_page.select_all_chk.setChecked(False)
        self.scan_page.select_all_chk.blockSignals(False)

    def _show_full_report(self):
        if not self._threat_list:
            QMessageBox.information(self, "扫描结果", "未发现威胁")
            return
        report = f"扫描完成\n已扫描: {self._scanned_count} 文件\n发现威胁: {self._threat_count} 个\n\n"
        for i, (name, vt, conf, path) in enumerate(self._threat_list, 1):
            report += f"{i}. {name}\n   类型: {vt or '未知'}\n   置信度: {conf}%\n   路径: {path}\n\n"
        _show_log_dialog("扫描结果报告", [report])

    def _apply_theme(self):
        th = get_theme()
        bg = f"rgb({th['bg_window'].red()},{th['bg_window'].green()},{th['bg_window'].blue()})"
        self.setStyleSheet("background: transparent;")
        self._root_widget.setObjectName("_root")
        radius = 0 if self._maximized else self._window_radius
        self._root_widget.setStyleSheet(
            f"QWidget#_root {{ background-color: {bg}; border-radius: {radius}px; "
            f"border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()}); }}"
        )
        self.title_bar.update_theme()
        self.sidebar.update_theme()
        for page in self.pages.values():
            page.update_theme()
        self.scan_page.view_result_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid rgb({th['border'].red()},{th['border'].green()},{th['border'].blue()});
                border-radius: 8px;
                color: rgb({th['text_secondary'].red()},{th['text_secondary'].green()},{th['text_secondary'].blue()});
                font-family: "Microsoft YaHei";
            }}
            QPushButton:hover {{
                border-color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
                color: rgb({th['accent'].red()},{th['accent'].green()},{th['accent'].blue()});
            }}
        """)

    def _apply_shadow_t(self, t):
        """t: 0.0=失焦浅阴影 → 1.0=聚焦深阴影(平滑过渡)。"""
        try:
            t = max(0.0, min(1.0, float(t)))
            f, u = self._shadow_focused, self._shadow_defocus
            self._shadow_effect.setBlurRadius(u['blur'] + (f['blur'] - u['blur']) * t)
            self._shadow_effect.setOffset(0, u['dy'] + (f['dy'] - u['dy']) * t)
            self._shadow_effect.setColor(QColor(0, 0, 0, int(u['alpha'] + (f['alpha'] - u['alpha']) * t)))
        except Exception:
            pass

    def _set_window_focused(self, focused):
        try:
            self._shadow_anim.stop()
            cur = self._shadow_anim.currentValue()
            start = float(cur) if cur is not None else (1.0 if focused else 0.0)
            self._shadow_anim.setStartValue(start)
            self._shadow_anim.setEndValue(1.0 if focused else 0.0)
            self._shadow_anim.start()
        except Exception:
            self._apply_shadow_t(1.0 if focused else 0.0)

    def changeEvent(self, event):
        try:
            if event.type() == QEvent.Type.ActivationChange:
                self._set_window_focused(self.isActiveWindow())
        except Exception:
            pass
        super().changeEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self._maximized:
            th = get_theme()
            painter.fillRect(self.rect(), th["bg_window"])

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, '_root_widget'):
            m = self._shadow_margin if not self._maximized else 0
            self._root_widget.setGeometry(m, m, self.width() - 2 * m, self.height() - 2 * m)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = event.globalPosition().toPoint() - self.pos()

    def mouseMoveEvent(self, event):
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            if self._maximized:
                self._maximized = False
                if self._normal_geometry:
                    self.setGeometry(self._normal_geometry)
            self.move(event.globalPosition().toPoint() - self._drag_offset)

    def mouseReleaseEvent(self, event):
        self._drag_offset = None

    def _init_engine(self):
        global g_scanner, g_status
        _log(">>> 正在初始化扫描引擎...")
        self.home_page.update_status(False, "init")
        threading.Thread(target=self._init_worker, daemon=True).start()

    def _init_worker(self):
        global g_scanner, g_status
        try:
            _gui_queue.put(lambda: self.home_page.update_engine("正在连接服务器..."))
            _gui_queue.put(lambda: self.home_page.update_engine_progress(0.1))
            server_ok = False
            try:
                t = ApiClient.get_status()
                if t:
                    g_status = {"ok": True, "msg": "服务器已连接"}
                    server_ok = True
                    _log(">>> [API] 服务器已运行")
                else:
                    _log(">>> [API] 后端未运行 (pedefenseserver.exe 未启动)")
            except:
                _log(">>> [API] 后端未运行 (pedefenseserver.exe 未启动)")
            _gui_queue.put(lambda: self.home_page.update_engine("正在加载引擎组件..."))
            _gui_queue.put(lambda: self.home_page.update_engine_progress(0.3))
            _log(">>> [引擎] 特征库就绪 (SevenEngine)")
            _gui_queue.put(lambda: self.home_page.update_engine("正在初始化扫描引擎..."))
            _gui_queue.put(lambda: self.home_page.update_engine_progress(0.6))
            g_scanner = Scanner()
            _log(">>> [引擎] 扫描引擎就绪")
            _gui_queue.put(lambda: self.home_page.update_engine("扫描引擎就绪"))
            _gui_queue.put(lambda: self.home_page.update_engine_progress(1.0))
            if server_ok:
                _gui_queue.put(lambda: self.home_page.update_status(True, "server"))
            else:
                _gui_queue.put(lambda: self.home_page.update_status(True, "noserver"))
            _log(">>> [引擎] 防护已生效")
            _gui_queue.put(lambda: self._start_server_monitor(server_ok))
            _gui_queue.put(lambda: self._start_realtime_monitor())
        except Exception as e:
            _log(f">>> [引擎] 初始化失败: {e}")
            _gui_queue.put(lambda: self.home_page.update_status(False))

    def _start_realtime_monitor(self):
        if self._realtime_monitor:
            self._realtime_monitor.stop()
        if self._edr:
            try:
                self._edr.stop()
            except Exception:
                pass
        self._realtime_monitor = RealtimeMonitor(self)
        self._realtime_monitor.start()
        # 创建并启动行为EDR,双向注入引用
        try:
            self._edr = BehaviorEDR(self)
            self._realtime_monitor._edr = self._edr
            self._edr.set_realtime(self._realtime_monitor)
            self._edr.start()
        except Exception as e:
            _log(f"[EDR] 启动失败(实时监控仍正常运行): {e}")
            self._edr = None
        try:
            if self._file_monitor:
                self._file_monitor.stop()
            self._file_monitor = FileMonitor(self)
            self._file_monitor.start()
        except Exception as e:
            _log(f"[文件监控] 启动失败: {e}")
            self._file_monitor = None
        try:
            if self._mbr_guard:
                self._mbr_guard.stop()
            self._mbr_guard = MBRGuard(self)
            self._mbr_guard.start()
        except Exception as e:
            _log(f"[MBR保护] 启动失败: {e}")
            self._mbr_guard = None
        try:
            if g_settings.get("etw_telemetry", False):
                if not self._etw_monitor:
                    self._etw_monitor = EtwTelemetryMonitor(self)
                self._etw_monitor.start()
        except Exception as e:
            _log(f"[遥测拦截] 启动失败: {e}")

    def _show_scan_dialog(self, pid, name, path, monitor, done_event, result_box):
        """托盘模式: 扫描前阻止通知(Process Scan) -> 后台扫描 -> Process Scanned Released/Blocked。"""
        self._scan_dialog_active = True
        try:
            _notify("Process Scan", "Suspicious Process Scan {}".format(name))

            def _work():
                res, conf, vt = "ERROR", 0, ""
                try:
                    res, conf, vt = monitor._scan_file_subprocess(path, quick=False, timeout=60)
                except Exception:
                    pass

                def _finish():
                    try:
                        self._scan_dialog_active = False
                        if res.startswith("MALICIOUS"):
                            result_box['resume'] = False
                            result_box['action'] = 'block'
                            try:
                                _notify("Process Scanned", "Suspicious Process Scanned , {} Blocked".format(name))
                                _record_interception('Realtime Scan Intercept', name, path, threat_type=vt or 'Suspicious',
                                                     action='blocked', extra=vt or res)
                            except Exception as e:
                                _log(f"[扫描通知] 记录失败: {e}")
                        elif res.startswith("CLEAN") or res == "WHITELIST":
                            # 引擎判白(含 CLEAN|LightGBM-White / WHITELIST) -> 端点二次研判后放行
                            # 纵深防御: 引擎判白后端点仍独立研判, 不做单点判决
                            _sec = None
                            try:
                                _sec = monitor._endpoint_secondary_check(path, name, pid, 0)
                            except Exception as e:
                                _log(f"[端点研判] 调用异常: {e}")
                            if _sec:
                                result_box['resume'] = False
                                result_box['action'] = 'block'
                                try:
                                    _notify("Process Scanned", "Suspicious Process Scanned , {} Blocked".format(name))
                                    _record_interception('端点二次研判拦截', name, path, threat_type='Suspicious Behavior',
                                                         confidence=int(_sec[1]), engine='Endpoint-Secondary',
                                                         action='blocked', extra=_sec[0])
                                except Exception as e:
                                    _log(f"[扫描通知] 记录失败: {e}")
                            else:
                                result_box['resume'] = True
                                result_box['action'] = 'allow'
                                try:
                                    _notify("Process Scanned", "Suspicious Process Scanned , {} Released".format(name))
                                    _record_interception('Realtime Scan Released', name, path, threat_type='Clean',
                                                         action='released', extra='clean')
                                except Exception as e:
                                    _log(f"[扫描通知] 记录失败: {e}")
                        else:
                            # 扫描超时/错误: 保守拦截
                            result_box['resume'] = False
                            result_box['action'] = 'block'
                            try:
                                _notify("Process Scanned", "Suspicious Process Scanned , {} Blocked".format(name))
                                _record_interception('Realtime Scan Intercept', name, path, threat_type='Unknown',
                                                     action='blocked', extra='scan error: {}'.format(res))
                            except Exception as e:
                                _log(f"[扫描通知] 记录失败: {e}")
                        done_event.set()
                    except Exception as e:
                        _log(f"[扫描通知] 处理异常: {e}")
                        result_box['resume'] = False
                        result_box['action'] = 'block'
                        done_event.set()

                _gui_queue.put(_finish)

            threading.Thread(target=_work, daemon=True, name='ScanNotify').start()
        except Exception as e:
            _log(f"[扫描通知] 异常: {e}")
            result_box['resume'] = True
            result_box['action'] = 'allow'
            self._scan_dialog_active = False
            done_event.set()

    def _show_threat_block(self, file_path, threat_type, confidence, engine):
        try:
            dialog = ThreatBlockDialog(file_path, threat_type, confidence, engine, self)
            _toast_place(dialog)
            def _on_threat_closed():
                action = dialog._result_action
                if action == "quarantine":
                    try:
                        os.makedirs(QUARANTINE_DIR, exist_ok=True)
                        dest = os.path.join(QUARANTINE_DIR, os.path.basename(file_path) + ".quarantine")
                        shutil.move(file_path, dest)
                        _scan_log(f"[实时-已隔离] {file_path}")
                        _log(f"[实时拦截] 已隔离: {file_path}")
                        self._tray_show("威胁已隔离", f"{os.path.basename(file_path)} 已移至隔离区")
                    except Exception as e:
                        _log(f"[实时拦截] 隔离失败 {file_path}: {e}")
                elif action == "delete":
                    try:
                        os.remove(file_path)
                        _scan_log(f"[实时-已删除] {file_path}")
                        _log(f"[实时拦截] 已删除: {file_path}")
                        self._tray_show("威胁已删除", f"{os.path.basename(file_path)} 已删除")
                    except Exception as e:
                        _log(f"[实时拦截] 删除失败 {file_path}: {e}")
                else:
                    _scan_log(f"[实时-已忽略] {file_path}")
                    _log(f"[实时拦截] 用户忽略: {file_path}")
            dialog.finished.connect(lambda _: _on_threat_closed())
            QTimer.singleShot(10, dialog.start_animation)
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
        except Exception as e:
            _log(f"[实时拦截] 弹窗异常: {e}")

    def _tray_show(self, title, msg):
        if hasattr(self, '_tray') and self._tray:
            try:
                # 通知气泡统一使用应用新图标(替代系统/旧SVG图标)
                self._tray.showMessage(title, msg, app_icon(), 4000)
            except Exception:
                try:
                    self._tray.showMessage(title, msg, QSystemTrayIcon.MessageIcon.Warning, 4000)
                except Exception:
                    pass

    def _start_server_monitor(self, initial_state):
        self._last_server_ok = initial_state
        if hasattr(self, '_server_check_timer'):
            self._server_check_timer.stop()
        self._server_check_timer = QTimer(self)
        self._server_check_timer.timeout.connect(self._check_server_status)
        self._server_check_timer.start(3000)

    def _check_server_status(self):
        def _do_check():
            ok = False
            try:
                t = ApiClient.get_status()
                if t:
                    ok = True
            except:
                pass
            if not ok:
                try:
                    result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq pedefenseserver.exe', '/NH'],
                                          capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                    if 'pedefenseserver.exe' in result.stdout.lower():
                        ok = True
                except:
                    pass
            if ok != self._last_server_ok:
                self._last_server_ok = ok
                if ok:
                    _log(">>> [API] 服务器已连接")
                    _gui_queue.put(lambda: self.home_page.update_status(True, "server"))
                else:
                    _log(">>> [API] 服务器已断开")
                    _gui_queue.put(lambda: self.home_page.update_status(True, "noserver"))
        threading.Thread(target=_do_check, daemon=True).start()

    def _on_close(self):
        if hasattr(self, '_tray') and self._tray:
            self.hide()
            self._tray.show()
            self._tray_show("SevenEndPointSecurity", "程序已最小化到托盘，右键托盘图标可退出")
        else:
            _on_app_exit(self)

    def closeEvent(self, event):
        if hasattr(self, '_tray') and self._tray:
            event.ignore()
            self.hide()
            self._tray.show()
            self._tray_show("SevenEndPointSecurity", "程序已最小化到托盘，右键托盘图标可退出")
        else:
            event.accept()
            _on_app_exit(self)


def _setup_tray(app, window):
    try:
        tray_icon = app_icon()
        if tray_icon.isNull():
            icon_pix = QPixmap(64, 64)
            icon_pix.fill(Qt.GlobalColor.transparent)
            painter = QPainter(icon_pix)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            th = get_theme()
            painter.setBrush(th["accent"])
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(2, 2, 60, 60)
            painter.setBrush(QColor("white"))
            pts = [QPoint(32, 14), QPoint(18, 46), QPoint(46, 46)]
            painter.drawPolygon(QPolygon(pts))
            painter.end()
            tray_icon = QIcon(icon_pix)
        tray = QSystemTrayIcon(tray_icon, window)
        tray.setToolTip("SevenEndPointSecurity")
        global _g_tray
        _g_tray = tray
        menu = QMenu()
        act_about = QAction("关于 SevenEndPointSecurity", menu)
        act_about.triggered.connect(lambda: _show_about(window))
        menu.addAction(act_about)
        menu.addSeparator()
        act_exit = QAction("退出程序", menu)
        act_exit.triggered.connect(lambda: _on_app_exit(window, tray))
        menu.addAction(act_exit)
        tray.setContextMenu(menu)
        tray.activated.connect(lambda reason: _show_about(window) if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        tray.show()
        window._tray = tray
    except Exception as e:
        _log(f"[托盘] 初始化失败: {e}")


def _show_about(window=None):
    try:
        QMessageBox.information(
            None, "SevenEndPointSecurity",
            "SevenEndPointSecurity v3.0.0\n"
            "EDR / Anti-Virus\n\n"
            "Scan Engine: SevenEngine (LightGBM)\n"
            "Protection: Realtime + ETW Telemetry + Behavior EDR + MBR Guard\n\n"
            "Copyright 2024-2026 NewEra Studio")
    except Exception:
        pass


def _on_app_exit(window=None, tray=None):
    try:
        if window and hasattr(window, '_edr') and window._edr:
            window._edr.stop()
    except:
        pass
    try:
        if window and hasattr(window, '_realtime_monitor') and window._realtime_monitor:
            window._realtime_monitor.stop()
    except:
        pass
    try:
        if window and hasattr(window, '_file_monitor') and window._file_monitor:
            window._file_monitor.stop()
    except:
        pass
    try:
        if window and hasattr(window, '_mbr_guard') and window._mbr_guard:
            window._mbr_guard.stop()
    except:
        pass
    try:
        if window and hasattr(window, '_etw_monitor') and window._etw_monitor:
            window._etw_monitor.stop()
    except:
        pass
    try:
        if tray:
            tray.hide()
    except:
        pass
    _cleanup_on_exit()
    QApplication.quit()


def _cleanup_on_exit():
    try:
        with open(QUIT_SIGNAL, 'w') as f:
            f.write("quit")
    except:
        pass
    try:
        import subprocess as _sp
        _si = _sp.STARTUPINFO()
        _si.dwFlags |= _sp.STARTF_USESHOWWINDOW
        _sp.run(["taskkill", "/f", "/im", "Pedefenseserver.exe"], capture_output=True, timeout=3, startupinfo=_si, creationflags=_sp.CREATE_NO_WINDOW)
    except:
        pass


def main():
    # 高DPI:按实际缩放因子渲染,保证文字/图标清晰
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except Exception:
        pass
    app = QApplication(sys.argv)
    app.setApplicationName("SevenEndPointSecurity")
    app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(False)
    _load_settings_json()
    window = SevenEndPointWindow()
    window.hide()   # 纯托盘模式: 不显示任何窗口, 只保留 Qt6 托盘 + 通知
    global g_window
    g_window = window
    _setup_tray(app, window)
    _notify("SevenEndPointSecurity", "Realtime protection active")
    app.aboutToQuit.connect(lambda: _cleanup_on_exit())
    sys.exit(app.exec())


def _run_worker_mode():
    _real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        scanner = Scanner()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.stdout = _real_stdout
    try:
        _real_stdout.reconfigure(line_buffering=True, encoding='utf-8')
    except Exception:
        pass
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        fp = req.get("path")
        if fp is None:
            break
        quick = req.get("quick", False)
        try:
            if quick and hasattr(scanner, "scan_file_quick"):
                res, conf, vt = scanner.scan_file_quick(fp)
            else:
                res, conf, vt = scanner.scan_file(fp)
        except Exception:
            res, conf, vt = "ERROR", 0, ""
        out = {"path": fp, "result": res, "conf": conf, "vt": vt}
        try:
            _real_stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            _real_stdout.flush()
        except Exception:
            break


def _run_file_monitor_mode():
    import ctypes
    from ctypes import wintypes

    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    FILE_NOTIFY_CHANGE_SIZE = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

    FILE_ACTION_ADDED = 0x00000001
    FILE_ACTION_REMOVED = 0x00000002
    FILE_ACTION_MODIFIED = 0x00000003
    FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
    FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _FILE_NOTIFY_INFORMATION(ctypes.Structure):
        _fields_ = [("NextEntryOffset", wintypes.DWORD),
                    ("Action", wintypes.DWORD),
                    ("FileNameLength", wintypes.DWORD),
                    ("FileName", wintypes.WCHAR * 1)]

    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.ReadDirectoryChangesW.restype = wintypes.BOOL
    k32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                          wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                          ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    ntdll = ctypes.windll.ntdll
    ntdll.NtSuspendProcess.restype = wintypes.LONG
    ntdll.NtResumeProcess.restype = wintypes.LONG

    _rm_ok = False
    try:
        rstrtmgr = ctypes.WinDLL('rstrtmgr.dll')
        rstrtmgr.RmStartSession.restype = wintypes.DWORD
        rstrtmgr.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.c_wchar_p]
        rstrtmgr.RmRegisterResources.restype = wintypes.DWORD
        rstrtmgr.RmRegisterResources.argtypes = [wintypes.DWORD, wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p),
                                                  wintypes.UINT, ctypes.POINTER(wintypes.DWORD),
                                                  wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p)]
        rstrtmgr.RmGetList.restype = wintypes.DWORD
        rstrtmgr.RmGetList.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
                                        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        rstrtmgr.RmEndSession.restype = wintypes.DWORD
        rstrtmgr.RmEndSession.argtypes = [wintypes.DWORD]
        _rm_ok = True
    except Exception:
        pass

    class _RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]
    class _RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [("Process", _RM_UNIQUE_PROCESS), ("strAppName", wintypes.WCHAR * 256),
                    ("strServiceShortName", wintypes.WCHAR * 64), ("ApplicationType", wintypes.DWORD),
                    ("AppStatus", wintypes.DWORD), ("TSSessionId", wintypes.DWORD), ("bRestartable", wintypes.BOOL)]

    import tempfile
    backup_dir = os.path.join(tempfile.gettempdir(), "pedefense_rollback")
    try:
        os.makedirs(backup_dir, exist_ok=True)
    except Exception:
        pass
    home = os.path.expanduser("~")
    watch_dirs = []
    for _d in ["Documents", "Desktop", "Videos", "Pictures", "Music", "Downloads"]:
        _p = os.path.join(home, _d)
        if os.path.isdir(_p):
            watch_dirs.append(_p)

    _MONITOR_SKIP_SUBDIRS = {
        'pasw\\code', 'pasw\\engines', 'pasw\\logs', 'pasw\\main',
        'tencent files', 'nt_qq', 'wechat files', 'nt_wechat',
        'appdata\\local\\temp', 'appdata\\locallow',
        '.cache', 'cache', '__pycache__', 'node_modules', '.git',
        'winxttkernel', 'crashdumps', 'minidump', 'd3dscache',
        'nvidia corporation\\dxcache', 'amd\\cn', 'packages',
        'avast software', 'avast!', 'kaspersky lab', 'windows defender',
        'mcafee', 'norton', 'avg', 'bitdefender', 'eset', 'malwarebytes',
        'sophos', 'trend micro', 'f-secure', 'comodo', '360safe', '360\\safe',
        'huorong', 'windows\\security',
    }

    def _should_skip_path(full_path):
        pl = full_path.lower().replace('/', '\\')
        for skip in _MONITOR_SKIP_SUBDIRS:
            if skip in pl:
                return True
        with state_lock:
            if pl in state["whitelist_paths"]:
                return True
            for wd in state["whitelist_dirs"]:
                if pl.startswith(wd):
                    return True
        return False

    notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE
    buf_size = 65536

    state_lock = threading.Lock()
    state = {"count": 0, "creates": 0, "deletes": 0, "modifies": 0, "renames": 0,
             "files": [], "ops": [], "window_start": time.time(), "last_alert": 0.0,
             "suspended_pids": set(), "backup_map": {}, "backup_done": set(),
             "proc_name": "", "proc_pid": 0, "proc_path": "",
             "modify_times": [], "modify_burst": False, "backup_refresh_time": 0.0,
             "rollback_active": False, "choice_cache": {}, "choice_cache_time": {},
             "whitelist_paths": set(), "whitelist_dirs": set(),
             "rollback_end_time": 0.0, "rollback_paths": set(),
             "file_protect": True, "file_modify_monitor": True}
    stop_flag = threading.Event()
    trusted_dirs = set()
    dir_handles = {}

    _real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        _real_stdout.reconfigure(line_buffering=True, encoding='utf-8')
    except Exception:
        pass

    def _find_proc_using_file(filepath):
        if not _rm_ok:
            return []
        try:
            session_handle = wintypes.DWORD(0)
            session_key = (ctypes.c_wchar * 256)()
            if rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key) != 0:
                return []
            try:
                paths = (ctypes.c_wchar_p * 1)(filepath)
                if rstrtmgr.RmRegisterResources(session_handle, 1, paths, 0, None, 0, None) != 0:
                    return []
                proc_count = wintypes.UINT(0)
                reason = wintypes.DWORD(0)
                rstrtmgr.RmGetList(session_handle, ctypes.byref(proc_count), ctypes.byref(proc_count), None, ctypes.byref(reason))
                if proc_count.value == 0:
                    return []
                proc_infos = (_RM_PROCESS_INFO * proc_count.value)()
                if rstrtmgr.RmGetList(session_handle, ctypes.byref(proc_count), ctypes.byref(proc_count), proc_infos, ctypes.byref(reason)) != 0:
                    return []
                result = []
                for i in range(proc_count.value):
                    pid = proc_infos[i].Process.dwProcessId
                    name = proc_infos[i].strAppName
                    path = ""
                    h = k32.OpenProcess(0x1000 | 0x0400, False, pid)
                    if h:
                        buf = ctypes.create_unicode_buffer(260)
                        size = wintypes.DWORD(260)
                        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            path = buf.value
                        k32.CloseHandle(h)
                    result.append((pid, name, path))
                return result
            finally:
                rstrtmgr.RmEndSession(session_handle)
        except Exception:
            return []

    TH32CS_SNAPPROCESS = 0x00000002
    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    _watch_dirs_lower = [d.lower() for d in watch_dirs]

    _ide_exempt = {"code.exe", "code - insiders.exe", "devenv.exe", "idea64.exe",
                   "idea.exe", "pycharm64.exe", "pycharm.exe", "webstorm64.exe",
                   "goland64.exe", "clion64.exe", "rider64.exe", "phpstorm64.exe",
                   "rubymine64.exe", "datagrip64.exe", "studio64.exe",
                   "trae.exe", "trae cn.exe", "trae so lo cn.exe", "cursor.exe",
                   "windsurf.exe", "zed.exe", "atom.exe", "sublime_text.exe",
                   "notepad++.exe", "vim.exe", "emacs.exe", "gvim.exe"}

    def _find_proc_fallback(filepath):
        dir_match = []
        try:
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if not snap or snap == INVALID_HANDLE_VALUE:
                return []
            pe = _PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            self_pid = os.getpid()
            _exempt = {"explorer.exe", "sihost.exe", "taskhostw.exe",
                       "ctfmon.exe", "dwm.exe", "searchhost.exe",
                       "textinputhost.exe", "shellexperiencehost.exe",
                       "startmenuexperiencehost.exe", "runtimebroker.exe",
                       "applicationframehost.exe", "systemsettings.exe",
                       "conhost.exe", "fontdrvhost.exe", "dllhost.exe",
                       "svchost.exe", "spoolsv.exe", "lsass.exe",
                       "services.exe", "wininit.exe", "csrss.exe",
                       "smss.exe", "winlogon.exe", "userinit.exe"}
            _exempt.update(_ide_exempt)
            file_dir_lower = os.path.dirname(filepath).lower()
            if k32.Process32FirstW(snap, ctypes.byref(pe)):
                while True:
                    pid = pe.th32ProcessID
                    if pid != self_pid and pid != 0 and pid != 4:
                        name_lower = pe.szExeFile.lower()
                        if name_lower not in _exempt and not name_lower.startswith("pedefense") and not name_lower.startswith("sevenend") and name_lower != "pasw.exe":
                            h = k32.OpenProcess(0x1000 | 0x0400, False, pid)
                            if h:
                                buf = ctypes.create_unicode_buffer(260)
                                size = wintypes.DWORD(260)
                                if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                                    ppath = buf.value
                                    if ppath and not is_system_path(ppath):
                                        ppath_lower = ppath.lower()
                                        if ppath_lower.startswith(file_dir_lower):
                                            dir_match.append((pid, pe.szExeFile, ppath))
                                        else:
                                            for wd in _watch_dirs_lower:
                                                if ppath_lower.startswith(wd):
                                                    dir_match.append((pid, pe.szExeFile, ppath))
                                                    break
                                k32.CloseHandle(h)
                    if not k32.Process32NextW(snap, ctypes.byref(pe)):
                        break
            k32.CloseHandle(snap)
        except Exception:
            pass
        if dir_match:
            dir_match.sort(key=lambda x: x[0], reverse=True)
        return dir_match

    def _try_find_and_store_proc(filepath):
        with state_lock:
            if state["proc_pid"]:
                return
        def _do_find():
            procs = _find_proc_using_file(filepath)
            if not procs:
                procs = _find_proc_fallback(filepath)
            for pid, pname, ppath in procs:
                if pid == os.getpid():
                    continue
                if ppath and not is_system_path(ppath):
                    with state_lock:
                        state["proc_name"] = pname
                        state["proc_pid"] = pid
                        state["proc_path"] = ppath
                    return
        threading.Thread(target=_do_find, daemon=True).start()

    def _suspend_pid(pid):
        try:
            h = k32.OpenProcess(0x0800, False, pid)
            if h:
                ntdll.NtSuspendProcess(h)
                k32.CloseHandle(h)
                return True
        except Exception:
            pass
        return False

    def _resume_pid(pid):
        try:
            h = k32.OpenProcess(0x0800, False, pid)
            if h:
                ntdll.NtResumeProcess(h)
                k32.CloseHandle(h)
        except Exception:
            pass

    def _backup_file(filepath):
        try:
            if not os.path.isfile(filepath):
                return None
            fsize = os.path.getsize(filepath)
            if fsize > _BACKUP_MAX_SIZE:
                return None
            key = hashlib.md5(filepath.encode('utf-8')).hexdigest()
            backup_path = os.path.join(backup_dir, key + "_" + os.path.basename(filepath))
            shutil.copy2(filepath, backup_path)
            return backup_path
        except Exception:
            return None

    _BACKUP_MAX_SIZE = 10 * 1024 * 1024
    _BACKUP_MAX_TOTAL = 200 * 1024 * 1024
    _BACKUP_SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
                         '.cache', 'temp', 'tmp', '$recycle.bin', 'system volume information'}
    _BACKUP_EXTENSIONS = {'.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                          '.pdf', '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.csv',
                          '.rtf', '.odt', '.ods', '.odp', '.md', '.zip', '.rar', '.7z'}

    def _cleanup_old_backups():
        try:
            items = []
            total_size = 0
            for f in os.listdir(backup_dir):
                fp = os.path.join(backup_dir, f)
                if os.path.isfile(fp):
                    sz = os.path.getsize(fp)
                    mt = os.path.getmtime(fp)
                    items.append((mt, fp, sz))
                    total_size += sz
            if total_size <= _BACKUP_MAX_TOTAL:
                return
            items.sort()
            while total_size > _BACKUP_MAX_TOTAL and items:
                _, fp, sz = items.pop(0)
                try:
                    os.remove(fp)
                    total_size -= sz
                except Exception:
                    pass
        except Exception:
            pass

    def _backup_dir_files(d):
        try:
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if x.lower() not in _BACKUP_SKIP_DIRS]
                for item in files:
                    fp = os.path.join(root, item)
                    try:
                        if not os.path.isfile(fp):
                            continue
                        ext = os.path.splitext(fp)[1].lower()
                        if ext not in _BACKUP_EXTENSIONS:
                            continue
                        if os.path.getsize(fp) > _BACKUP_MAX_SIZE:
                            continue
                    except Exception:
                        continue
                    with state_lock:
                        if fp in state["backup_done"]:
                            continue
                        state["backup_done"].add(fp)
                    bp = _backup_file(fp)
                    if bp:
                        with state_lock:
                            state["backup_map"][fp] = bp
        except Exception:
            pass

    def _try_vss_restore(filepath):
        try:
            fp_norm = os.path.normpath(filepath).lower().replace('\\', '/')
            for _skip in ('/windows/', '/program files/', '/program files (x86)/', '/programdata/', '/$windows', '/windowsapps/'):
                if _skip in fp_norm:
                    return False
            import subprocess
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            creationflags = 0x08000000
            result = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command',
                 '(Get-WmiObject Win32_ShadowCopy).DeviceObject'],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                startupinfo=startupinfo, creationflags=creationflags
            )
            if result.returncode != 0 or not result.stdout.strip():
                return False
            drive = os.path.splitdrive(filepath)[0]
            rel = filepath[len(drive):].lstrip('\\')
            for line in result.stdout.strip().split('\n'):
                sc = line.strip()
                if sc:
                    vss_path = sc + '\\' + rel
                    if os.path.exists(vss_path):
                        shutil.copy2(vss_path, filepath)
                        return True
            return False
        except Exception:
            return False

    def _stdin_reader():
        while not stop_flag.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except Exception:
                continue
            if cmd.get("cmd") == "trust_dir":
                d = cmd.get("dir", "")
                if d:
                    trusted_dirs.add(d.lower())
                    h = dir_handles.pop(d, None)
                    if h:
                        try:
                            k32.CloseHandle(h)
                        except Exception:
                            pass
            elif cmd.get("cmd") == "set_whitelist":
                wl_paths = cmd.get("paths", [])
                with state_lock:
                    state["whitelist_paths"] = set(p.lower() for p in wl_paths)
                    state["whitelist_dirs"] = set(p.lower() for p in wl_paths if not os.path.splitext(p)[1])
            elif cmd.get("cmd") == "set_config":
                _cfg_key = cmd.get("key", "")
                _cfg_val = cmd.get("value", True)
                if _cfg_key in ("file_protect", "file_modify_monitor"):
                    with state_lock:
                        state[_cfg_key] = _cfg_val
                    sys.stderr.write("[file-monitor] config: {}={}\n".format(_cfg_key, _cfg_val))
                    sys.stderr.flush()
            elif cmd.get("cmd") == "cache_choice":
                sig = cmd.get("sig", "")
                choice = cmd.get("choice", "")
                if sig and choice:
                    with state_lock:
                        state["choice_cache"][sig] = choice
                        state["choice_cache_time"][sig] = time.time()
            elif cmd.get("cmd") == "rollback":
                ops = cmd.get("ops", [])
                _rb_paths = set(o.get("path", "") for o in ops)
                with state_lock:
                    state["rollback_active"] = True
                    state["rollback_paths"] = _rb_paths
                rolled_back = 0
                failed_list = []
                created_paths = set()
                for o in ops:
                    if o.get("action") in ("create", "create_delete"):
                        created_paths.add(o.get("path", ""))
                for op in reversed(ops):
                    try:
                        action = op.get("action", "")
                        path = op.get("path", "")
                        old_path = op.get("old_path", "")
                        if action in ("create", "create_delete"):
                            if os.path.exists(path):
                                os.remove(path)
                                rolled_back += 1
                                sys.stderr.write("[rollback] deleted created file: {}\n".format(path))
                            else:
                                sys.stderr.write("[rollback] create file already gone: {}\n".format(path))
                        elif action == "rename_new":
                            if os.path.exists(path) and old_path:
                                os.rename(path, old_path)
                                rolled_back += 1
                                sys.stderr.write("[rollback] renamed back: {} -> {}\n".format(path, old_path))
                        elif action in ("modify", "delete"):
                            if path in created_paths:
                                if os.path.exists(path):
                                    os.remove(path)
                                    rolled_back += 1
                                    sys.stderr.write("[rollback] deleted modified created file: {}\n".format(path))
                                else:
                                    sys.stderr.write("[rollback] modified created file already gone: {}\n".format(path))
                            else:
                                with state_lock:
                                    bp = state["backup_map"].get(path)
                                if bp and os.path.exists(bp):
                                    shutil.copy2(bp, path)
                                    rolled_back += 1
                                    sys.stderr.write("[rollback] restored from backup: {}\n".format(path))
                                else:
                                    sys.stderr.write("[rollback] no backup, trying VSS: {}\n".format(path))
                                    vss_ok = _try_vss_restore(path)
                                    if vss_ok:
                                        rolled_back += 1
                                        sys.stderr.write("[rollback] restored from VSS shadow copy: {}\n".format(path))
                                    else:
                                        failed_list.append(path)
                                        sys.stderr.write("[rollback] FAILED no backup and no VSS: {}\n".format(path))
                    except Exception as e:
                        failed_list.append(op.get("path", "?"))
                        sys.stderr.write("[rollback] error on {}: {}\n".format(op.get("path", "?"), e))
                        sys.stderr.flush()
                sys.stderr.write("[rollback] total rolled back: {}/{}, failed: {}\n".format(rolled_back, len(ops), len(failed_list)))
                sys.stderr.flush()
                with state_lock:
                    state["rollback_active"] = False
                    state["rollback_end_time"] = time.time()
                try:
                    _real_stdout.write(json.dumps({"type": "rollback_result", "count": rolled_back, "failed": len(failed_list), "failed_files": failed_list[:10]}, ensure_ascii=False) + "\n")
                    _real_stdout.flush()
                except Exception as e:
                    sys.stderr.write("[rollback] failed to send result: {}\n".format(e))
                    sys.stderr.flush()
            elif cmd.get("cmd") == "resume":
                with state_lock:
                    state["rollback_active"] = False
                    state["rollback_end_time"] = time.time()
                    state["rollback_paths"] = set()
                    for pid in list(state["suspended_pids"]):
                        _resume_pid(pid)
                    state["suspended_pids"].clear()
                    state["proc_pid"] = 0
                    state["proc_name"] = ""
                    state["proc_path"] = ""

    def _watch_dir(d):
        if d.lower() in trusted_dirs:
            return
        h = k32.CreateFileW(d, FILE_LIST_DIRECTORY,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            None, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, None)
        if not h or h == INVALID_HANDLE_VALUE:
            return
        dir_handles[d] = h
        try:
            while not stop_flag.is_set():
                if d.lower() in trusted_dirs:
                    break
                buf = (ctypes.c_char * buf_size)()
                bytes_returned = wintypes.DWORD(0)
                ok = k32.ReadDirectoryChangesW(h, buf, buf_size, True, notify_filter,
                                               ctypes.byref(bytes_returned), None, None)
                if not ok or bytes_returned.value == 0:
                    continue
                offset = 0
                local_ops = []
                local_files = []
                rename_old = None
                batch_created = set()
                while offset < bytes_returned.value:
                    info = ctypes.cast(ctypes.addressof(buf) + offset,
                                       ctypes.POINTER(_FILE_NOTIFY_INFORMATION)).contents
                    action = info.Action
                    name_len = info.FileNameLength
                    name_ptr = ctypes.addressof(info) + 12
                    try:
                        name = ctypes.wstring_at(name_ptr, name_len // 2)
                    except Exception:
                        name = ""
                    full = os.path.join(d, name)
                    if _should_skip_path(full):
                        if info.NextEntryOffset == 0:
                            break
                        offset += info.NextEntryOffset
                        continue
                    with state_lock:
                        _fp_on = state["file_protect"]
                        _fmm_on = state["file_modify_monitor"]
                    if action == FILE_ACTION_ADDED:
                        if not _fp_on:
                            if info.NextEntryOffset == 0:
                                break
                            offset += info.NextEntryOffset
                            continue
                        batch_created.add(full)
                        op = {"path": full, "action": "create"}
                    elif action == FILE_ACTION_REMOVED:
                        if not _fp_on:
                            if info.NextEntryOffset == 0:
                                break
                            offset += info.NextEntryOffset
                            continue
                        if full in batch_created:
                            batch_created.discard(full)
                            op = {"path": full, "action": "create_delete"}
                        else:
                            op = {"path": full, "action": "delete"}
                    elif action == FILE_ACTION_MODIFIED:
                        if not _fmm_on:
                            if info.NextEntryOffset == 0:
                                break
                            offset += info.NextEntryOffset
                            continue
                        if full in batch_created:
                            offset += info.NextEntryOffset if info.NextEntryOffset else 0
                            if info.NextEntryOffset == 0:
                                break
                            continue
                        op = {"path": full, "action": "modify"}
                    elif action == FILE_ACTION_RENAMED_OLD_NAME:
                        if not _fp_on:
                            if info.NextEntryOffset == 0:
                                break
                            offset += info.NextEntryOffset
                            continue
                        rename_old = full
                        op = {"path": full, "action": "rename_old"}
                    elif action == FILE_ACTION_RENAMED_NEW_NAME:
                        if not _fp_on:
                            if info.NextEntryOffset == 0:
                                break
                            offset += info.NextEntryOffset
                            continue
                        op = {"path": full, "action": "rename_new", "old_path": rename_old or ""}
                        rename_old = None
                    else:
                        op = {"path": full, "action": "unknown"}
                    local_ops.append(op)
                    if len(local_files) < 10:
                        local_files.append(full)
                    if op["action"] in ("modify", "delete", "create", "create_delete"):
                        with state_lock:
                            _skip_proc = state["rollback_active"] or (state["rollback_end_time"] and (time.time() - state["rollback_end_time"]) < 5.0)
                        if not _skip_proc:
                            _try_find_and_store_proc(full)
                    if info.NextEntryOffset == 0:
                        break
                    offset += info.NextEntryOffset
                with state_lock:
                    _rb_active = state["rollback_active"]
                    _rb_grace = (time.time() - state["rollback_end_time"]) < 5.0 if state["rollback_end_time"] else False
                    if _rb_active or _rb_grace:
                        local_ops = []
                        local_files = []
                        continue
                with state_lock:
                    _now_ts = time.time()
                    if state["count"] == 0 and local_ops:
                        for _wd in watch_dirs:
                            threading.Thread(target=_backup_dir_files, args=(_wd,), daemon=True).start()
                        state["window_start"] = _now_ts
                    _prev_sig = state.get("_last_op_sig", "")
                    for o in local_ops:
                        act = o["action"]
                        _sig = act + "|" + o.get("path", "")
                        # 去重: ReadDirectoryChangesW 对同一文件的同一操作常双发, 连续重复只记一次
                        if _sig == _prev_sig and act in ("modify", "rename_old", "rename_new", "create", "delete"):
                            continue
                        _prev_sig = _sig
                        # 修复x3计数: 一次重命名只记一次(只计 rename_new, rename_old 仅用于配对)
                        if act == "rename_old":
                            continue
                        state["count"] += 1
                        if act == "create":
                            state["creates"] += 1
                        elif act == "delete":
                            state["deletes"] += 1
                        elif act == "create_delete":
                            state["creates"] += 1
                            state["deletes"] += 1
                        elif act == "modify":
                            state["modifies"] += 1
                            state.setdefault("modify_paths", {})[o.get("path", "")] = _now_ts
                            if len(state["modify_paths"]) > 200:
                                state["modify_paths"] = {p: t for p, t in state["modify_paths"].items() if _now_ts - t <= 10.0}
                            # 勒索特征: 3秒内 >=5 个"不同文件"被改写(修复单文件双触发导致的误报)
                            _recent_paths = [p for p, t in state["modify_paths"].items() if _now_ts - t <= 3.0]
                            if len(_recent_paths) >= 5:
                                state["modify_burst"] = True
                        elif act == "rename_new":
                            state["renames"] += 1
                        state["ops"].append(o)
                        if len(state["ops"]) > 200:
                            state["ops"] = state["ops"][-200:]
                    state["_last_op_sig"] = _prev_sig
                    state["files"].extend(local_files)
                    if len(state["files"]) > 10:
                        state["files"] = state["files"][-10:]
        finally:
            try:
                k32.CloseHandle(h)
            except Exception:
                pass

    _cleanup_old_backups()

    for _d in watch_dirs:
        threading.Thread(target=_backup_dir_files, args=(_d,), daemon=True).start()

    def _periodic_backup_loop():
        while not stop_flag.is_set():
            time.sleep(600)
            _cleanup_old_backups()
            with state_lock:
                state["backup_done"] = set()
                state["backup_refresh_time"] = time.time()
            for _d in watch_dirs:
                threading.Thread(target=_backup_dir_files, args=(_d,), daemon=True).start()

    threading.Thread(target=_periodic_backup_loop, daemon=True).start()

    for _d in watch_dirs:
        _t = threading.Thread(target=_watch_dir, args=(_d,), daemon=True)
        _t.start()

    _stdin_t = threading.Thread(target=_stdin_reader, daemon=True)
    _stdin_t.start()

    while not stop_flag.is_set():
        now = time.time()
        with state_lock:
            _threshold = 20   # 勒索判定阈值: 累计20次文件操作
            if state["count"] >= _threshold:
                if (now - state["last_alert"]) >= 15:
                    ops_snapshot = list(state["ops"][:200])
                    files_snapshot = list(state["files"][:5])
                    proc_name = state["proc_name"]
                    proc_pid = state["proc_pid"]
                    proc_path = state["proc_path"]
                    _is_burst = state["modify_burst"]
                    state["last_alert"] = now
                    state["count"] = 0
                    state["creates"] = 0
                    state["deletes"] = 0
                    state["modifies"] = 0
                    state["renames"] = 0
                    state["files"] = []
                    state["ops"] = []
                    state["modify_burst"] = False
                    state["modify_times"] = []
                    state["window_start"] = now
                else:
                    ops_snapshot = None
            else:
                ops_snapshot = None
        if ops_snapshot is not None:
            with state_lock:
                already_suspended = proc_pid in state["suspended_pids"]
            _ops_sig = json.dumps(sorted((o.get("action", ""), os.path.dirname(o.get("path", ""))) for o in ops_snapshot[:10]), ensure_ascii=False)
            _cached_choice = None
            with state_lock:
                _cache_time = state["choice_cache_time"].get(_ops_sig, 0)
                if _cache_time and (now - _cache_time) < 300:
                    _cached_choice = state["choice_cache"].get(_ops_sig)
            if _cached_choice == "ignore":
                sys.stderr.write("[file-monitor] auto-ignore (cached choice): count={}\n".format(len(ops_snapshot)))
                sys.stderr.flush()
                continue
            if _cached_choice == "rollback":
                sys.stderr.write("[file-monitor] auto-rollback (cached choice): count={}\n".format(len(ops_snapshot)))
                sys.stderr.flush()
                _rollback_ops = list(ops_snapshot)
                _rb_paths = set(o.get("path", "") for o in _rollback_ops)
                with state_lock:
                    state["rollback_active"] = True
                    state["rollback_paths"] = _rb_paths
                rolled_back = 0
                for op in reversed(_rollback_ops):
                    try:
                        action = op.get("action", "")
                        path = op.get("path", "")
                        if action in ("create", "create_delete"):
                            if os.path.exists(path):
                                os.remove(path)
                                rolled_back += 1
                        elif action in ("modify", "delete"):
                            with state_lock:
                                bp = state["backup_map"].get(path)
                            if bp and os.path.exists(bp):
                                shutil.copy2(bp, path)
                                rolled_back += 1
                    except Exception:
                        pass
                with state_lock:
                    state["rollback_active"] = False
                    state["rollback_end_time"] = time.time()
                sys.stderr.write("[file-monitor] auto-rollback done: {}/{}\n".format(rolled_back, len(_rollback_ops)))
                sys.stderr.flush()
                continue
            if proc_pid and not already_suspended:
                _suspend_pid(proc_pid)
                with state_lock:
                    state["suspended_pids"].add(proc_pid)
            if not proc_pid:
                for fp in files_snapshot:
                    procs = _find_proc_using_file(fp)
                    if not procs:
                        procs = _find_proc_fallback(fp)
                    for pid, pname, ppath in procs:
                        if pid == os.getpid():
                            continue
                        if pname and pname.lower() in _ide_exempt:
                            continue
                        if ppath and not is_system_path(ppath):
                            _suspend_pid(pid)
                            proc_pid = pid
                            proc_name = pname
                            proc_path = ppath
                            with state_lock:
                                state["suspended_pids"].add(pid)
                                state["proc_name"] = pname
                                state["proc_pid"] = pid
                                state["proc_path"] = ppath
                            break
                    if proc_pid:
                        break
            alert = {
                "type": "file_op_alert",
                "count": len(ops_snapshot),
                "creates": sum(1 for o in ops_snapshot if o.get("action") in ("create", "create_delete")),
                "deletes": sum(1 for o in ops_snapshot if o.get("action") in ("delete", "create_delete")),
                "modifies": sum(1 for o in ops_snapshot if o.get("action") == "modify"),
                "renames": sum(1 for o in ops_snapshot if o.get("action") in ("rename_old", "rename_new")),
                "files": files_snapshot,
                "ops": ops_snapshot,
                "proc_name": proc_name,
                "proc_pid": proc_pid,
                "proc_path": proc_path,
                "ransomware": _is_burst,
            }
            try:
                msg = json.dumps(alert, ensure_ascii=False)
                _real_stdout.write(msg + "\n")
                _real_stdout.flush()
                if _is_burst:
                    sys.stderr.write("[file-monitor] RANSOMWARE ALERT: rapid modify burst, count={} proc={}\n".format(len(ops_snapshot), proc_name))
                else:
                    sys.stderr.write("[file-monitor] alert sent: count={} proc={}\n".format(len(ops_snapshot), proc_name))
                sys.stderr.flush()
            except Exception as e:
                sys.stderr.write("[file-monitor] alert write failed: {}\n".format(e))
                sys.stderr.flush()
        with state_lock:
            if (now - state["window_start"]) > 10 and state["count"] < 20:
                state["count"] = 0
                state["creates"] = 0
                state["deletes"] = 0
                state["modifies"] = 0
                state["renames"] = 0
                state["files"] = []
                state["ops"] = []
                state["window_start"] = now
        time.sleep(0.2)


# ============================ ETW遥测Worker(端点规则拦截) ============================
# 实时ETW会话采集 进程/文件/注册表/网络/DNS 遥测,按 Rules/*.json 端点规则匹配。
# block 命中 -> 输出 etw_alert 给主程序终止进程链并告;警 log 命中 -> 仅记录行为链。
# 白名单 White.json 命中 -> 直接放行。测试版:解析失败/无权限时优雅退出。
def _run_etw_worker_mode():
    import ctypes
    from ctypes import (wintypes, byref, c_void_p, c_ulong, c_ushort, c_ubyte,
                        c_ulonglong, c_longlong, c_long, Structure, POINTER, WINFUNCTYPE,
                        sizeof, create_string_buffer, cast)
    import re as _re_mod
    import uuid as _uuid_mod

    _real = sys.stdout
    sys.stdout = sys.stderr
    try:
        _real.reconfigure(line_buffering=True, encoding='utf-8')
    except Exception:
        pass

    def _out(obj):
        try:
            _real.write(json.dumps(obj, ensure_ascii=False) + "\n")
            _real.flush()
        except Exception:
            pass

    SESSION_NAME = "SevenEndPointTelemetry"
    rules_dir = os.path.join(BASE_DIR, 'Rules')

    # ---------------- 规则引擎 ----------------
    def _glob_to_re(g):
        r"""glob语义: **跨目录、*单层、?单字符、?:\ 任意盘符。"""
        gl = g.lower().replace('/', '\\')
        out = ['^']
        i = 0
        n = len(gl)
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
            out.append(_re_mod.escape(c))
            i += 1
        out.append('$')
        try:
            return re.compile(''.join(out))
        except Exception:
            return None

    class _Rule:
        __slots__ = ('id', 'kinds', 'globs', 'proc_globs', 'except_globs',
                     'contains', 'detail_contains', 'action', 'score', 'severity', 'note')

    SUPPORTED_KINDS = {'processcreate', 'filecreate', 'fileopen', 'filewrite', 'filemodify',
                       'filedelete', 'filedrop', 'registryset', 'registrydelete',
                       'netconnect', 'dnsquery'}

    white_rules, match_rules = [], []
    unsupported_kinds = set()
    try:
        rule_files = [f for f in os.listdir(rules_dir) if f.lower().endswith('.json')] if os.path.isdir(rules_dir) else []
    except Exception:
        rule_files = []
    for fn in sorted(rule_files):
        try:
            with open(os.path.join(rules_dir, fn), 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            _out({"type": "etw_error", "msg": f"规则加载失败 {fn}: {e}"})
            continue
        for r in data.get('rules', []):
            try:
                rule = _Rule()
                rule.id = r.get('id', fn)
                kinds = [k.lower() for k in r.get('kinds', [])]
                rule.kinds = set(kinds) if kinds else None
                rule.globs = [x for x in (_glob_to_re(g) for g in r.get('glob', [])) if x]
                rule.proc_globs = [x for x in (_glob_to_re(g) for g in r.get('proc_glob', [])) if x]
                rule.except_globs = [x for x in (_glob_to_re(g) for g in r.get('except_glob', [])) if x]
                rule.contains = [c.lower() for c in r.get('contains', [])]
                rule.detail_contains = [c.lower() for c in r.get('detail_contains', [])]
                rule.action = (r.get('action') or 'log').lower()
                rule.score = int(r.get('score', 5) or 5)
                rule.severity = int(r.get('severity', 40) or 40)
                rule.note = r.get('_note', '')
                if rule.kinds:
                    sup = rule.kinds & SUPPORTED_KINDS
                    if not sup:
                        unsupported_kinds |= rule.kinds
                        continue
                    rule.kinds = sup
                if rule.action == 'allow':
                    white_rules.append(rule)
                else:
                    match_rules.append(rule)
            except Exception:
                continue
    _out({"type": "etw_status",
          "msg": f"规则就绪: {len(white_rules)}白名单 {len(match_rules)}拦截/记录, 未支持类别: {sorted(unsupported_kinds) if unsupported_kinds else '无'}"})

    # 需要的ETW提供者
    need = set()
    for r in match_rules + white_rules:
        if not r.kinds:
            continue
        for k in r.kinds:
            if k.startswith('process'):
                need.add('process')
            elif k.startswith('file'):
                need.add('file')
            elif k.startswith('registry'):
                need.add('registry')
            elif k == 'netconnect':
                need.add('network')
            elif k == 'dnsquery':
                need.add('dns')
    # 进程创建几乎总是需要(用于 proc_glob/上下文)
    if match_rules or white_rules:
        need.add('process')

    PROVIDER_GUIDS = {
        'process': '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716',   # Microsoft-Windows-Kernel-Process
        'file': 'edd08927-9cc4-4e65-b970-c2560fb5c289',      # Microsoft-Windows-Kernel-File
        'registry': '70eb4f03-c1de-4f73-a051-33d13f5f227a',  # Microsoft-Windows-Kernel-Registry
        'network': '7dd42a49-5329-4832-8dfd-43d979153a88',   # Microsoft-Windows-Kernel-Network
        'dns': '1c95126e-7eea-49a9-a3fe-a378b03ddb4d',       # Microsoft-Windows-DNS-Client
    }

    def _any_match(regexes, s):
        if not s:
            return False
        sl = s.lower()
        return any(rx.match(sl) for rx in regexes)

    def _rule_hit(rule, kind, target, proc, detail):
        if rule.kinds and kind not in rule.kinds:
            return False
        dl = (detail or '').lower()
        if rule.contains and not any(c in dl for c in rule.contains):
            return False
        if rule.detail_contains and not any(c in dl for c in rule.detail_contains):
            return False
        if rule.except_globs and (_any_match(rule.except_globs, target) or _any_match(rule.except_globs, proc)):
            return False
        if rule.globs and not _any_match(rule.globs, target):
            return False
        if rule.proc_globs and not _any_match(rule.proc_globs, proc):
            return False
        return True

    def _match_event(kind, target, proc, detail):
        # 白名单先行:命中即放行
        for wr in white_rules:
            if _rule_hit(wr, kind, target, proc, detail):
                return None
        for r in match_rules:
            if _rule_hit(r, kind, target, proc, detail):
                return r
        return None

    # ---------------- 进程路径解析缓存 ----------------
    _proc_cache = {}
    _proc_cache_lock = threading.Lock()
    _k32w = ctypes.windll.kernel32
    _k32w.OpenProcess.restype = c_void_p
    _k32w.OpenProcess.argtypes = [c_ulong, wintypes.BOOL, c_ulong]
    _k32w.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _k32w.QueryFullProcessImageNameW.argtypes = [c_void_p, c_ulong, wintypes.LPWSTR, POINTER(c_ulong)]
    _k32w.CloseHandle.argtypes = [c_void_p]

    def _query_proc_path(pid):
        try:
            h = _k32w.OpenProcess(0x1000, False, int(pid) & 0xFFFFFFFF)
            if not h or h == c_void_p(-1).value:
                return ''
            try:
                buf = ctypes.create_unicode_buffer(520)
                size = c_ulong(520)
                if _k32w.QueryFullProcessImageNameW(h, 0, buf, byref(size)):
                    return buf.value or ''
            finally:
                _k32w.CloseHandle(h)
        except Exception:
            pass
        return ''

    def _resolve_path(pid):
        if not pid:
            return ''
        now = time.time()
        with _proc_cache_lock:
            e = _proc_cache.get(pid)
            if e and now - e[1] < 5:
                return e[0]
        path = _query_proc_path(pid)
        with _proc_cache_lock:
            if len(_proc_cache) > 4096:
                _proc_cache.clear()
            _proc_cache[pid] = (path, now)
        return path

    # ---------------- ETW 会话 ----------------
    advapi32 = ctypes.windll.advapi32
    tdh = ctypes.windll.tdh

    class _GUID(Structure):
        _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort),
                    ("Data4", c_ubyte * 8)]

    def _guid(s):
        return _GUID.from_buffer_copy(_uuid_mod.UUID(s).bytes_le)

    def _guid_str(g):
        try:
            b = bytes(g.Data4)
            return f"{g.Data1:08x}-{g.Data2:04x}-{g.Data3:04x}-{b[0]:02x}{b[1]:02x}-{b[2]:02x}{b[3]:02x}{b[4]:02x}{b[5]:02x}{b[6]:02x}{b[7]:02x}"
        except Exception:
            return ''

    class _WNODE_HEADER(Structure):
        _fields_ = [("BufferSize", c_ulong), ("ProviderId", c_ulong),
                    ("HistoricalContext", c_ulonglong), ("TimeStamp", wintypes.LARGE_INTEGER),
                    ("Guid", _GUID), ("ClientContext", c_ulong), ("Flags", c_ulong)]

    class _EVENT_TRACE_PROPERTIES(Structure):
        _fields_ = [("Wnode", _WNODE_HEADER), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong),
                    ("MaximumBuffers", c_ulong), ("MaximumFileSize", c_ulong), ("LogfileMode", c_ulong),
                    ("FlushTimer", c_ulong), ("EnableFlags", c_ulong), ("AgeLimit", c_long),
                    ("NumberOfBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                    ("BuffersWritten", c_ulong), ("LogBuffersLost", c_ulong),
                    ("RealTimeBuffersLost", c_ulong), ("LoggerThreadId", c_void_p),
                    ("LogFileNameOffset", c_ulong), ("LoggerNameOffset", c_ulong)]

    class _EVENT_DESCRIPTOR(Structure):
        _fields_ = [("Id", c_ushort), ("Version", c_ubyte), ("Channel", c_ubyte),
                    ("Level", c_ubyte), ("Opcode", c_ubyte), ("Task", c_ushort),
                    ("Keyword", c_ulonglong)]

    class _EVENT_HEADER(Structure):
        _fields_ = [("Size", c_ushort), ("HeaderType", c_ushort), ("Flags", c_ulong),
                    ("EventProperty", c_ulong), ("ThreadId", c_ulong), ("ProcessId", c_ulong),
                    ("TimeStamp", wintypes.LARGE_INTEGER), ("ProviderId", _GUID),
                    ("EventDescriptor", _EVENT_DESCRIPTOR), ("KernelTime", c_ulong),
                    ("UserTime", c_ulong), ("ActivityId", _GUID)]

    class _ETW_BUFFER_CONTEXT(Structure):
        _fields_ = [("ProcessorIndex", c_ushort), ("LoggerId", c_ushort)]

    class _EVENT_RECORD(Structure):
        _fields_ = [("EventHeader", _EVENT_HEADER),
                    ("BufferContext", _ETW_BUFFER_CONTEXT),
                    ("Reserved1", c_ushort), ("Reserved2", c_ushort),
                    ("UserDataLength", c_ulong), ("Reserved3", c_ulong),
                    ("UserData", c_void_p), ("UserContext", c_void_p),
                    ("ExtendedData", c_void_p), ("ExtendedDataCount", c_ulong),
                    ("Reserved4", c_ulong), ("UserContext2", c_void_p),
                    ("Reserved5", c_void_p)]

    class _TRACE_LOGFILE_HEADER(Structure):
        _fields_ = [("BufferSize", c_ulong), ("Version", c_ulong),
                    ("ProviderVersion", c_ulong), ("NumberOfProcessors", c_ulong),
                    ("EndTime", c_longlong), ("TimerResolution", c_ulong),
                    ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong),
                    ("LogBuffersLost", c_ulong), ("Flags", c_ulong),
                    ("StartBuffers", c_longlong), ("PointerSize", c_longlong),
                    ("EventsLost", c_longlong), ("CpuSpeedInMHz", c_longlong),
                    ("LoggerNameOffset", c_longlong), ("LogFileNameOffset", c_longlong),
                    ("TimeZone", c_ubyte * 252), ("BootTime", c_longlong),
                    ("PerfFreq", c_longlong), ("StartTime", c_longlong),
                    ("ReservedFlags", c_ulong), ("BuffersLost", c_longlong)]

    class _EVENT_TRACE_LOGFILEW(Structure):
        """按MSDN官方声明(x64): LogFileName@0 LoggerName@8 CurrentTime@16 BuffersRead@24
        ProcessTraceMode@28(union LogFileMode) CurrentEvent@32(EVENT_TRACE=88)
        LogfileHeader@120(TRACE_LOGFILE_HEADER=392) BufferCallback@512
        BufferSize@520 Filled@524 EventsLost@528 EventRecordCallback@536(union EventCallback)
        IsKernelTrace@544 Context@552 (size=560)"""
        _fields_ = [("LogFileName", wintypes.LPWSTR),
                    ("LoggerName", wintypes.LPWSTR),
                    ("CurrentTime", c_longlong),
                    ("BuffersRead", c_ulong),
                    ("ProcessTraceMode", c_ulong),
                    ("CurrentEvent", c_ubyte * 88),
                    ("LogfileHeader", _TRACE_LOGFILE_HEADER),
                    ("BufferCallback", c_void_p),
                    ("BufferSize", c_ulong), ("Filled", c_ulong), ("EventsLost", c_ulong),
                    ("EventRecordCallback", c_void_p),
                    ("IsKernelTrace", c_ulong),
                    ("Context", c_void_p)]

    WNODE_FLAG_TRACED_GUID = 0x00020000
    EVENT_TRACE_REAL_TIME_MODE = 0x00000100
    EVENT_TRACE_CONTROL_STOP = 1
    PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
    PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

    # TDH 结构(自校准布局)
    class _PROPERTY_DATA_DESCRIPTOR(Structure):
        _fields_ = [("PropertyName", c_ulong), ("ArrayIndex", c_ulong)]

    _ev_rec_cb = WINFUNCTYPE(None, POINTER(_EVENT_RECORD))

    _info_layout_lock = threading.Lock()
    _info_layout = None  # (property_count_off, array_off)

    def _read_utf16(buf, off, max_len=256):
        try:
            raw = bytes(buf[off:off + max_len * 2])
            s = raw.decode('utf-16-le', errors='ignore')
            s = s.split('\x00')[0]
            if s and all(32 <= ord(ch) < 0xFFFE for ch in s):
                return s
        except Exception:
            pass
        return None

    def _calibrate_info_layout(buf):
        """自校准 TRACE_EVENT_INFO 布局:寻找 (PropertyCount, TopLevelPropertyCount, ArrayOffset)。
        通过"属性名必须是可打印UTF-16字符串"来验证,避免依赖固定偏移。"""
        n = len(buf)
        for q in range(120, min(n - 16, 320), 4):
            try:
                cnt = int.from_bytes(buf[q:q + 4], 'little')
                top = int.from_bytes(buf[q + 4:q + 8], 'little')
                flags = int.from_bytes(buf[q + 8:q + 12], 'little')
            except Exception:
                continue
            if not (0 < top <= cnt <= 256) or flags > 64:
                continue
            arr = q + 12
            if arr + 8 * min(top, 4) > n:
                continue
            ok = 0
            for j in range(min(top, 4)):
                name_off = int.from_bytes(buf[arr + 8 * j:arr + 8 * j + 4], 'little')
                if name_off >= n or name_off < arr:
                    ok = -1
                    break
                s = _read_utf16(buf, name_off, 96)
                if s and _re_mod.match(r'^[A-Za-z_][A-Za-z0-9_\.]*$', s):
                    ok += 1
                else:
                    ok = -1
                    break
            if ok > 0:
                return (q, arr)
        return None

    _tdh_buf = create_string_buffer(65536)

    def _event_props(rec_ptr):
        """返回 (props dict, event_name) — TDH解析顶层属性。"""
        size = c_ulong(0)
        rc = tdh.TdhGetEventInformation(rec_ptr, 0, None, None, byref(size))
        if rc != 0 or size.value == 0 or size.value > 1048576:
            return {}, ''
        info = create_string_buffer(size.value)
        rc = tdh.TdhGetEventInformation(rec_ptr, 0, None, info, byref(size))
        if rc != 0:
            return {}, ''
        ev_name = _read_utf16(info, int.from_bytes(info[48:52], 'little'), 96) or ''
        if ev_name and not _re_mod.match(r'^[A-Za-z_][A-Za-z0-9_]*$', ev_name):
            ev_name = ''
        with _info_layout_lock:
            layout = _info_layout
            if layout is None:
                layout = _calibrate_info_layout(bytes(info[:min(size.value, 4096)]))
                if layout:
                    _info_layout = layout
                    _out({"type": "etw_status", "msg": f"TDH属性布局校准成功(PropertyCount偏移={layout[0]})"})
                else:
                    _info_layout = (-1, -1)  # 校准失败,不再重试
                    _out({"type": "etw_status", "msg": "TDH属性布局校准失败,属性解析不可用(仅事件名可用)"})
                    layout = None
        if not layout or layout == (-1, -1):
            return {}, ev_name
        cnt_off, arr_off = layout
        try:
            cnt = int.from_bytes(info[cnt_off:cnt_off + 4], 'little')
            top = int.from_bytes(info[cnt_off + 4:cnt_off + 8], 'little')
        except Exception:
            return {}, ev_name
        if not (0 < top <= cnt <= 256):
            return {}, ev_name
        props = {}
        for i in range(top):
            try:
                name_off = int.from_bytes(info[arr_off + 8 * i:arr_off + 8 * i + 4], 'little')
                pname = _read_utf16(info, name_off, 96)
                if not pname:
                    continue
                dd = _PROPERTY_DATA_DESCRIPTOR(name_off, 0xFFFFFFFF)
                psz = c_ulong(0)
                if tdh.TdhGetPropertySize(rec_ptr, 0, None, 1, byref(dd), byref(psz)) != 0 or psz.value == 0:
                    continue
                if psz.value > 8192:
                    props[pname] = f'<{psz.value}B>'
                    continue
                vbuf = create_string_buffer(psz.value + 2)
                if tdh.TdhGetProperty(rec_ptr, 0, None, 1, byref(dd), psz.value, vbuf) != 0:
                    continue
                raw = bytes(vbuf.raw[:psz.value])
                if psz.value == 1:
                    props[pname] = raw[0]
                elif psz.value in (2, 4, 8):
                    props[pname] = int.from_bytes(raw, 'little')
                else:
                    s = raw.decode('utf-16-le', errors='ignore').split('\x00')[0]
                    if s and all(32 <= ord(ch) < 0xFFFE for ch in s):
                        props[pname] = s
                    else:
                        s2 = raw.decode('latin-1', errors='ignore').split('\x00')[0]
                        props[pname] = s2 if s2 and all(32 <= ord(ch) < 127 for ch in s2) else raw[:64].hex()
            except Exception:
                continue
        return props, ev_name

    # 文件对象 -> 文件名 映射(Write/Delete事件只有FileObject)
    _fileobj_map = {}
    _fileobj_lock = threading.Lock()

    def _remember_fileobj(props):
        fo = props.get('FileObject')
        fn = props.get('FileName')
        if fo and fn:
            with _fileobj_lock:
                if len(_fileobj_map) > 4096:
                    _fileobj_map.clear()
                _fileobj_map[fo] = fn

    def _lookup_fileobj(props):
        fo = props.get('FileObject')
        if not fo:
            return props.get('FileName', '')
        with _fileobj_lock:
            return _fileobj_map.get(fo, '')

    _EXEC_EXTS = ('.exe', '.dll', '.sys', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.scr', '.com', '.ocx', '.msi', '.py', '.pyw')

    # 限速:每秒最多处理的事件数
    _rate_lock = threading.Lock()
    _rate_win = [0, 0]  # [window_start, count]
    _dropped_reported = [False]

    def _rate_ok():
        now = time.time()
        with _rate_lock:
            if now - _rate_win[0] >= 1.0:
                _rate_win[0] = now
                _rate_win[1] = 0
                _dropped_reported[0] = False
            _rate_win[1] += 1
            if _rate_win[1] > 3000:
                if not _dropped_reported[0]:
                    _dropped_reported[0] = True
                    _out({"type": "etw_status", "msg": "事件量过大,部分遥测被限速丢弃"})
                return False
            return True

    def _emit(rule, kind, pid, ppid, target, proc, detail):
        name = os.path.basename(target) if target else (proc and os.path.basename(proc)) or ''
        _out({"type": "etw_alert", "rule": rule.id, "kind": kind, "action": rule.action,
              "score": rule.score, "severity": rule.severity, "note": rule.note,
              "pid": pid or 0, "ppid": ppid or 0, "name": name or '',
              "path": target or '', "proc_name": (proc and os.path.basename(proc)) or '',
              "proc_path": proc or '', "detail": (detail or '')[:400]})

    _alert_dedup = {}
    _alert_dedup_lock = threading.Lock()

    def _emit_dedup(rule, kind, pid, ppid, target, proc, detail):
        key = (rule.id, (target or detail or '').lower())
        now = time.time()
        with _alert_dedup_lock:
            if now - _alert_dedup.get(key, 0) < 60:
                return
            _alert_dedup[key] = now
            if len(_alert_dedup) > 1000:
                for k in [k for k, t in _alert_dedup.items() if now - t > 300]:
                    _alert_dedup.pop(k, None)
        _emit(rule, kind, pid, ppid, target, proc, detail)

    _SELF_PID = os.getpid()

    def _handle_record(rec):
        try:
            hdr = rec.contents.EventHeader
            pid = hdr.ProcessId
            if pid in (0, _SELF_PID):
                return
            prov = _guid_str(hdr.ProviderId)
            if not _rate_ok():
                return
            props, ev_name = _event_props(rec)
            if not props and not ev_name:
                return
            ev_name_l = (ev_name or '').lower()
            detail_parts = []

            def _detail(extra):
                if extra:
                    detail_parts.append(extra)

            # ---------- 分发到遥测类别 ----------
            events = []  # (kind, target, proc_pid, detail)
            if prov == PROVIDER_GUIDS['process']:
                if 'processstart' in ev_name_l or hdr.EventDescriptor.Id == 1:
                    newpid = int(props.get('NewProcessId') or 0)
                    ppid = int(props.get('ParentProcessId') or 0) or pid
                    img = props.get('ImageFileName') or ''
                    if isinstance(img, int):
                        img = ''
                    cmdline = props.get('CommandLine') or ''
                    if isinstance(cmdline, int):
                        cmdline = ''
                    target = _resolve_path(newpid) or (img if img else '')
                    proc = _resolve_path(ppid)
                    _detail(f'cmd: {cmdline}' if cmdline else '')
                    events.append(('processcreate', target, ppid, '; '.join(detail_parts)))
                # 其他(ProcessStop/Thread/ImageLoad)忽略
            elif prov == PROVIDER_GUIDS['file']:
                fname = props.get('FileName') or ''
                if isinstance(fname, int):
                    fname = ''
                if fname:
                    _remember_fileobj(props)
                fo_name = fname or _lookup_fileobj(props)
                if 'create' in ev_name_l:
                    if fo_name:
                        events.append(('fileopen', fo_name, pid, ''))
                        events.append(('filecreate', fo_name, pid, ''))
                elif 'write' in ev_name_l or 'setinformation' in ev_name_l:
                    if fo_name:
                        events.append(('filewrite', fo_name, pid, ''))
                        events.append(('filemodify', fo_name, pid, ''))
                elif 'delete' in ev_name_l or 'rename' in ev_name_l:
                    if fo_name:
                        events.append(('filedelete', fo_name, pid, ''))
                elif 'cleanup' in ev_name_l or 'close' in ev_name_l:
                    if fo_name:
                        with _fileobj_lock:
                            _fileobj_map.pop(props.get('FileObject'), None)
            elif prov == PROVIDER_GUIDS['registry']:
                keyname = props.get('KeyName') or props.get('KeyPath') or ''
                if isinstance(keyname, int):
                    keyname = ''
                if not keyname:
                    return
                if 'set' in ev_name_l or 'create' in ev_name_l:
                    events.append(('registryset', keyname, pid, f'注册表写入: {keyname}'))
                elif 'delete' in ev_name_l or 'rename' in ev_name_l:
                    events.append(('registrydelete', keyname, pid, f'注册表删除: {keyname}'))
            elif prov == PROVIDER_GUIDS['network']:
                if 'connect' in ev_name_l:
                    daddr = props.get('daddr') or props.get('Daddr') or ''
                    dport = props.get('dport') or props.get('Dport') or 0
                    events.append(('netconnect', '', pid, f'connect {daddr}:{dport}'))
            elif prov == PROVIDER_GUIDS['dns']:
                qname = props.get('QueryName') or props.get('QueryResults') or ''
                if isinstance(qname, int):
                    qname = ''
                if qname:
                    events.append(('dnsquery', '', pid, f'dns: {qname}'))

            for kind, target, proc_pid, detail in events:
                # 可执行体落地 => 额外 FileDrop 语义
                test_kinds = [kind]
                tl = (target or '').lower()
                if kind in ('filecreate', 'filewrite') and tl.endswith(_EXEC_EXTS):
                    test_kinds.append('filedrop')
                rule = None
                for tk in test_kinds:
                    rule = _match_event(tk, target, _resolve_path(proc_pid), detail)
                    if rule:
                        kind = tk
                        break
                if rule:
                    _emit_dedup(rule, kind, proc_pid if kind == 'processcreate' else pid,
                                0, target, _resolve_path(proc_pid), detail)
        except Exception:
            return

    _callback_ref = _ev_rec_cb(_handle_record)  # 防GC

    # 启动会话
    if not need:
        _out({"type": "etw_status", "msg": "无可匹配的ETW遥测类别,Worker退出"})
        return

    _props_size = sizeof(_EVENT_TRACE_PROPERTIES) + 2 * 1024

    def _make_props():
        buf = create_string_buffer(_props_size)
        props = cast(buf, POINTER(_EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = _props_size
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.Wnode.ClientContext = 1
        props.LogfileMode = EVENT_TRACE_REAL_TIME_MODE
        props.BufferSize = 64
        props.MinimumBuffers = 16
        props.MaximumBuffers = 64
        props.FlushTimer = 1
        props.LoggerNameOffset = sizeof(_EVENT_TRACE_PROPERTIES)
        name_bytes = SESSION_NAME.encode('utf-16-le') + b'\x00\x00'
        ctypes.memmove(byref(buf, props.LoggerNameOffset), name_bytes, len(name_bytes))
        return buf

    def _start_session():
        buf = _make_props()
        props = cast(buf, POINTER(_EVENT_TRACE_PROPERTIES)).contents
        h = c_ulonglong(0)
        rc = advapi32.StartTraceW(byref(h), SESSION_NAME, byref(props))
        if rc == 183:  # 已存在:先停再启
            advapi32.ControlTraceW(c_ulonglong(0), SESSION_NAME, byref(props), EVENT_TRACE_CONTROL_STOP)
            time.sleep(0.2)
            buf = _make_props()
            props = cast(buf, POINTER(_EVENT_TRACE_PROPERTIES)).contents
            rc = advapi32.StartTraceW(byref(h), SESSION_NAME, byref(props))
        return (h.value, rc) if rc == 0 else (0, rc)

    sess_handle, rc = _start_session()
    if not sess_handle:
        msg = {5: "需要管理员权限", 183: "会话冲突", 1310: "需要管理员权限"}.get(rc, f"错误码{rc}")
        _out({"type": "etw_error", "msg": f"ETW会话启动失败({msg})。遥测拦截需要以管理员身份运行。"})
        return

    # 启用提供者
    enabled = []
    for pkey in sorted(need):
        g = _guid(PROVIDER_GUIDS[pkey])
        okk = False
        for kw in (0xFFFFFFFFFFFFFFFF, 0xFF, 0x1FFFFFFF, 0):
            rrc = advapi32.EnableTraceEx2(c_ulonglong(sess_handle), byref(g), 1, 5,
                                          c_ulonglong(kw), c_ulonglong(0), 0, None)
            if rrc == 0:
                okk = True
                break
        if okk:
            enabled.append(pkey)
        else:
            _out({"type": "etw_status", "msg": f"提供者 {pkey} 启用失败(部分规则将不生效)"})
    _out({"type": "etw_status", "msg": f"ETW会话已启动,提供者: {enabled}"})

    # OpenTrace + ProcessTrace
    advapi32.OpenTraceW.restype = c_ulonglong
    advapi32.ProcessTrace.restype = c_ulong
    advapi32.CloseTrace.restype = c_ulong
    lf = _EVENT_TRACE_LOGFILEW()
    lf.LoggerName = ctypes.c_wchar_p(SESSION_NAME)
    lf.LogFileName = None
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
    lf.EventRecordCallback = cast(_callback_ref, c_void_p)
    hlog = advapi32.OpenTraceW(byref(lf))
    if hlog == 0xFFFFFFFFFFFFFFFF or hlog == 0xFFFFFFFF or hlog == 0:
        _out({"type": "etw_error", "msg": f"OpenTrace失败(lf_size={sizeof(_EVENT_TRACE_LOGFILEW)}),ETW遥测不可用"})
        advapi32.ControlTraceW(c_ulonglong(sess_handle), SESSION_NAME, None, EVENT_TRACE_CONTROL_STOP)
        return
    harr = (c_ulonglong * 1)(hlog)
    advapi32.ProcessTrace(harr, 1, None, None)
    # ProcessTrace返回即退出
    try:
        advapi32.CloseTrace(c_ulonglong(hlog))
    except Exception:
        pass
    advapi32.ControlTraceW(c_ulonglong(sess_handle), SESSION_NAME, None, EVENT_TRACE_CONTROL_STOP)


if __name__ == '__main__':
    if '--worker' in sys.argv:
        _run_worker_mode()
    elif '--file-monitor' in sys.argv:
        _run_file_monitor_mode()
    elif '--etw-worker' in sys.argv:
        _run_etw_worker_mode()
    else:
        main()
