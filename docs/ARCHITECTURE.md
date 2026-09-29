# SevenEndPoint 架构疏导图

> 单文件 `SevenEndPoint.py`（约 10800 行）的结构地图。**行号会漂移，定位一律用类名/函数名搜索**；
> 行号只给大致方位。改任何一层前先读本文对应小节，确认上下游。

## 一、进程模型（谁在跑什么）

| 进程/线程 | 入口 | 职责 |
|---|---|---|
| 主进程 | `main()` | PyQt6 UI + 托盘 + 全部决策逻辑 |
| 主进程 · 主循环线程 | `RealtimeMonitor._process_loop` | 20ms 轮询进程表：快速拦截 / 行为入链 / 投递任务（**轮询频率是防快速跑路样本的核心，勿改慢**） |
| 主进程 · ProcSpawnWorker | `RealtimeMonitor._spawn_worker` | **专门负责开线程**的 Worker：主循环只投递 `_spawn_queue`，由它统一创建 `_on_new_process` 处理线程 |
| 子进程 · 扫描 Worker | `--worker` 模式 / `SevenEngine.exe --WORKER` | 常驻扫描引擎。全局唯一实例 `_SCAN_WORKER`（类 `_ResidentScanWorker`），所有扫描共用，详见 WORKERS.md |
| 子进程 · 文件监控 | `--file-monitor` 模式 → `_run_file_monitor_mode` | ReadDirectoryChangesW 监控 7 目录 + 备份（压缩存内存）+ 勒索爆发判定 + 回滚执行 |
| 子进程 · ETW Worker | `--etw-worker` 模式 → `_run_etw_worker_mode` | ETW 订阅内核事件流 + Rules/*.json 规则判决 |

## 二、单文件分区（按行号从上到下）

| 区段（约） | 内容 | 关键符号 |
|---|---|---|
| 1–70 | 全局记录表 | `_record_dropped_file`（pid→{path:时间戳}）、`_record_interception` |
| 72–305 | **EDR 评分账本** | `EDR_EVENT_POINTS`、`_edr_add_event`（双闸在此）、`_edr_chain_dynamic_score`、`_edr_root_pid` |
| 307–560 | 溯源报告 + 链拦截 | `_edr_report_chain`（思维导图 HTML → `Line/`）、`_edr_enforce_chain` |
| 565–690 | 隔离与回滚 | `_quarantine_file`、`_quarantine_new_drop`（**旧 DLL 硬闸门在此**）、`_rollback_chain_files` |
| 690–860 | 隔离区 CLI | `--quarantinelist/del/move` |
| 860–960 | 日志/通知 | `_log`、`_scan_log`、`_edr_log`、`_etw_log`、`_endpoint_log`、`_notify`（详见 LOGGING.md） |
| 960–1170 | 设置/引擎/Worker 命令 | `_load_settings_json`、`_worker_cmd`、`_SCAN_WORKER` |
| 1170–1950 | 引擎门面 | `Whitelist`、`Scanner`、`_exe_scan_file`（CLI 兜底）、`classify_threat`、`is_system_path`、`verify_name_path`、`_parse_pe_all`、`_extract_signer` |
| 1957–2065 | 轻量行为 EDR 配置 | `EDR_SCORE_THRESHOLD(70)`、`EDR_SUSPICIOUS_DIR_TOKENS`、`EDR_API_CHAINS` |
| 2120–4160 | PyQt6 UI 组件与页面 | `Sidebar`、`HomePage`、`ScanPage`、`SettingsPage`、`ToolPage`、各 `_ManageDialog` |
| 4165–4470 | **FileMonitor**（主进程侧） | 与文件监控子进程的 IPC、`_show_dialog`（勒索自动处置，**外壳豁免在此**） |
| 4471–5125 | EtwTelemetryMonitor / MemoryGuard | 遥测入账本（`_handle_telemetry`）、句柄表注入检测 |
| 5125–5324 | MBRGuard | MBR 保护 |
| 5324–6944 | **RealtimeMonitor** | `_process_loop`、`_spawn_worker`、`_on_new_process`、`_handle_new_process`、`_terminate_chain`、`_scan_file_subprocess`、MSI 处置、`_start_realtime_monitor`（并行分级启动在此） |
| 6944–7440 | BehaviorEDR | 行为评分轮询、`_calc_score`、`_handle_threat` |
| 7440–8133 | 行为链 UI | `BehaviorChainWidget/Page` |
| 8133–9035 | 主窗口 `SevenEndPointWindow` | `_init_worker`（引擎初始化）、`_start_realtime_monitor`、`_show_scan_dialog` |
| 9035–9190 | 托盘/退出/提权 | `_setup_tray`、`_ensure_admin_relaunch`、`main()` |
| 9190–10845 | 三个子进程模式 | `_run_worker_mode`、`_run_file_monitor_mode`、`_run_etw_worker_mode` |

## 三、一次勒索样本的标准处置流（数据流示例）

```
样本落地 Temp
→ 文件监控子进程: ReadDirectoryChangesW 捕获 → 先备份(压缩入内存) → 计数/爆发判定
→ 落盘扫描线程: _scan_dropped_file → _SCAN_WORKER.scan 引擎判恶
→ 判恶: 杀释放进程整链(_terminate_chain full) + 新DLL隔离(_quarantine_new_drop)
        + mal_drop +20 记分(_edr_add_event) + 溯源报告(_edr_report_chain)
→ 就算漏判: 批量改写/改后缀/挪移/删除任一爆发 → Ransom Block → 整链终止+回滚(内存备份解压还原, VSS兜底)
→ 全程留痕: _record_interception / _edr_log / _endpoint_log
```

## 四、改代码前必读的三条铁律

1. **评分分值存在多个消费点**（`EDR_EVENT_POINTS`、`_DANGEROUS_CMD_PATTERNS`、ETW `_handle_alert`、文件遥测 `_handle_telemetry`）——改一处分值要全文搜 etype 名同步，见 SCORING.md。
2. **拦截必建链**：任何 block/kill 路径都应配 `_edr_report_chain(...)`，否则溯源图缺失。
3. **防误报闸门不要绕过**：计分双闸（去重+封顶）、`EDR_EXEMPT_NAMES`、`_FILE_OP_EXEMPT_NAMES`、旧 DLL 硬闸门、Program Files 硬保护——删任何一个都会回归误报。

## 五、启动顺序（已并行分级）

`main()` → UI 先起 → `_init_worker`（后台：服务器探活 → Scanner 就绪）→ `_start_realtime_monitor`：
**RealtimeMonitor 同步先起（自身防护）** → EDR/FileMonitor/MBR/MemoryGuard/ETW 五个 Worker 各自线程并行启动 → join（≤30s）→ 线程自然结束移除 → 日志 `[防护] 全部防护Worker并行启动完成`。
