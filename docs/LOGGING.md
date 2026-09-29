# 日志体系速查

5 个日志函数 + 各自落点。都是追加写、失败静默（不影响主流程）。

## 函数 → 落点

| 函数 | 行≈ | 落点 | 内容 |
|---|---|---|---|
| `_log` | 896 | **Main/UIdebug.txt** + GUI 日志页 + 终端回显 | 全局主日志：拦截/启动/Worker/异常，什么都记 |
| `_scan_log` | 913 | 仅 GUI 扫描页内存缓冲（`_g_scan_log_lines`） | 扫描页显示专用，不落盘 |
| `_edr_log` | 931 | **Main/EDRlog.txt** | 评分账本：SCORE 记账/判决/溯源报告生成 |
| `_etw_log` | 935 | **Main/ETWlog.txt** | 遥测：会话启停/规则就绪/BLOCK 命中 |
| `_endpoint_log` | 939 | **Main/Endpointlog.txt** | 端点主防：TERMINATE/REPEAT-BLOCK/DropScan |

## 约定

- **主日志 `_log` 无条件记**；专项日志按域分流，排障时先看域日志再回 UIdebug 对时间线。
- 子进程（文件监控/ETW worker）的 stderr 行是给人看的诊断流，不进以上文件；结构化数据必须走 stdout JSON。
- 写日志统一经 `_file_log`（时间戳前缀 `[YYYY-MM-DD HH:MM:SS]`），不要在调用处自带时间戳。
- 新增日志域：仿照 `_edr_log` 三件套——路径常量 + `_file_log` 包装 + 本文档补一行。

## 已知取舍

- 追加写无轮转：日志文件会一直增长（UIdebug.txt 最大）。需要轮转时在 `_file_log` 加大小检查截断，别在各调用点处理。
- `_log` 同时写 GUI 缓冲/终端/文件三处，高频路径（如 20ms 轮询内的每次发现）不要直接 `_log`，先聚合。
