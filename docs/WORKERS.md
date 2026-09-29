# Worker 与子进程接口手册

主进程与三类子进程/Worker 的通信协议。改协议两端必须同步。

## 1. 扫描 Worker（全局唯一，`_SCAN_WORKER`）

- **拉起**：`_worker_cmd()` → 打包环境 `SevenEngine.exe --WORKER`；源码环境 `python --worker`（`_run_worker_mode`）。
- **实例**：类 `_ResidentScanWorker`（模块级单例 `_SCAN_WORKER`）。**全部扫描共用这一个进程**——
  实时监控（`RealtimeMonitor._scan_file_subprocess`）、手动扫描（`Scanner.scan_file/quick` exe 模式）、MSI 研判都走 `_SCAN_WORKER.scan()`。
- **协议**（stdin/stdout，每行一个 JSON）：
  - 请求：`{"path": "<文件路径>", "quick": true?}`；热身握手 `{"path": "__warmup__"}`
  - 响应：`{"result": "MALICIOUS|CLEAN|WHITELIST|ERROR", "conf": int, "vt": "类型"}`
- **语义**：请求经 `_req_lock` 串行下发（单 Worker 平摊，无流交叉）；超时/异常 → 杀 Worker → 下次自动拉起；
  热身 90s 超时。`Scanner` 在 Worker 不可用时回退 `_exe_scan_file`（CLI 单次拉起，慢，仅兜底）。
- **外部 kill**：设置页切换引擎模式时 kill `rm._scan_proc`（镜像句柄）→ `_ensure` 自动重拉。

## 2. 文件监控子进程（`--file-monitor`）

- **拉起**：`_file_monitor_cmd()`，由 `FileMonitor.start()`（主进程侧类，line≈4165）管理。
- **主→子命令**（stdin JSON）：`{"cmd": "rollback", "ops": [...]}`、`{"cmd": "resume"}`、
  `{"cmd": "trust_dir", "dir": "<目录>"}`（停看该目录并关句柄；发送端=`_mark_user_allowed` 用户放行时信任其所在目录，
  `_send_config` 在子进程重启后重发全量信任目录）、启动时 config 行。
- **子→主事件**（stdout JSON 行）：
  - `file_op_alert`：`{count, creates, deletes, modifies, renames, files, ops, proc_name, proc_pid, proc_path, ransomware}`
  - `rollback_result`：`{count, failed, failed_files}`
- **勒索爆发判定**（子进程内，阈值勿改需同步 SCORING.md）：3s 窗口内 ≥5 文件改写 / ≥5 改后缀或跨目录重命名 / ≥8 删除；
  另有 10s/20 次总量窗口。
- **备份机制（已改内存压缩）**：`_backup_file` 读文件 → `zlib.compress(...,3)` → `state["backup_mem"][path]=(ts,blob)`；
  单文件上限 `_BACKUP_MAX_SIZE`(10MB)，总量 `_BACKUP_MAX_TOTAL`(200MB 压缩字节) 超限按时间淘汰（`_cleanup_old_backups`）。
  回滚 = 解压写回；无内存备份 → VSS 影子副本兜底。**备份随子进程生命周期，重启后依赖 VSS**。
- **外壳豁免**（主进程 `_show_dialog`）：`_FILE_OP_EXEMPT_NAMES` 命中且路径不在落毒高发目录（Temp/Downloads/Roaming/Public/ProgramData）→ 放行。

## 3. ETW Worker（`--etw-worker`）

- **拉起**：`_etw_worker_cmd()`，`EtwTelemetryMonitor` 管理；受 `settings.json: etw_telemetry` 开关控制。
- **规则**：加载 `Rules/*.json`（White 短路 → kinds 过滤 → except → glob/contains）；用户态支持 kinds 见
  `_run_etw_worker_mode` 内 `SUPPORTED_KINDS`（**不含** ServiceOp/ProcessInject/MemThreat/ProcessOpen/ProcessTerminate——
  这几类是驱动遗留，分别由注册表遥测转换 / MemoryGuard 用户态执行）。
- **子→主事件**：`etw_status` / `etw_error` / `etw_alert`（rule/kind/action/severity/pid/proc_path/detail...）。
- **事件结构自检**：`_EVENT_TRACE_LOGFILEW` sizeof != 560 → 直接报错退出（Windows 结构变更保护）。

## 4. 线程 Worker（主进程内）

- **ProcSpawnWorker**（`RealtimeMonitor._spawn_worker`）：唯一负责为每个新进程创建 `_on_new_process` 处理线程；
  主循环只 `self._spawn_queue.put((pid, name, path, ppid, ppinfo))`。哨兵 `None` 退出。
  **背压**：`_proc_sem = BoundedSemaphore(64)`——处理线程并发上限 64，fork 炸弹时任务在队列排队等槽位。
- **DropScanWorker**（`_sensitive_op_loop` 内 `_drop_scan_worker`）：落盘文件扫描请求入队，
  `_drop_scan_sem = BoundedSemaphore(16)` 限 16 并发（单次扫描可达 30s，防解压风暴打爆线程）。
- **并行分级启动**（`_start_realtime_monitor`）：RealtimeMonitor 同步先起（自身防护）→ 其余 5 Worker
  （EDR/FileMonitor/MBR/MemoryGuard/ETW）各自独立线程并行 start → join(30s) → 线程自然结束移除。

## 5. 新增 Worker 的检查单

1. 命令行分支加进 `main()` 的 argv 分发 + 对应 `_*_cmd()`；
2. stdout 一律 JSON 行（走 `_real_stdout`），stderr 走日志；崩溃不能拖死主进程（主进程读行要有超时）；
3. 在 WORKERS.md 补协议；在 ARCHITECTURE.md 进程模型表补一行。
