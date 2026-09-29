# EDR 评分与拦截阈值速查

> **分值存在多个消费点**：改一处必须全文搜 etype 名同步其余消费点，改完跑 `_full_test.py` + `_trust_test.py`。

## 1. 分值表（`EDR_EVENT_POINTS`，行≈80）

| etype | 分值 | 触发点（消费位置） |
|---|---|---|
| violation | +10 | ETW 拦截规则命中（`_handle_alert`） |
| file_op | +5 | 遥测文件分支 `_handle_telemetry`；释放落盘 `_scan_dropped_file`；可疑目录 MSI |
| mal_drop | +20 | 释放文件判恶（3 处：恶意释放源/释放文件判恶/恶意 MSI，均 `_quarantine_new_drop` 路径） |
| driver_drop | +15 | 驱动释放（`_ask_driver_install`） |
| dll_drop | +5 | 遥测 DLL 落可疑目录；**代理 DLL +15**（白加黑，`_SIDELOAD_PROXY_DLLS` 名单，两处计分点） |
| script_run | +5 | 危险命令遥测 + 主循环脚本运行 |
| registry_sensitive | **+10** | 遥测注册表分支 + `_handle_alert`（同步过） |
| persistence | **+15** | Run键/服务键/IFEO/Winlogon（遥测分支 + `_DANGEROUS_CMD_PATTERNS`） |
| privilege | **+15** | sc create/bcdedit/vssadmin delete/icacls grant 等（命令行遥测） |
| task_sched | **+15** | schtasks /create 等（命令行遥测 + `_handle_alert`） |
| c2 | +10 | 预留 |
| injection | +10 | 注入检测；MemoryGuard 句柄表**观察信号 +5**（`INJECTION-TELEMETRY`，单凭句柄不拦截，需链上累积） |
| lsass_access | +15 | LSASS 句柄读取 |
| uac_bypass | +10 | fodhelper/-enc 等 |
| ransom_op | +10 | 文件防护批量操作（`_show_dialog`） |
| av_tamper | +20 | **最高优先级**：杀 360/火绒/管家/金山、Defender 排除项/关实时防护、sc stop 产品服务 |
| cred_dump | +20 | comsvcs MiniDump / procdump LSASS / mimikatz |

**阈值 `EDR_SCORE_THRESHOLD = 70`**（行≈2100）。判决 = 单进程分 或 整链动态分（`_edr_chain_dynamic_score`）。

## 2. 计分双闸（`_edr_add_event` 内，防误报核心，勿删）

1. 同 (pid, etype, detail前150字) 120s 内去重 → 不重复计分（事件仍留痕）；
2. 同 (pid, etype) 计分封顶 4 次 → 批量解压/反复写键不堆分；
   恶意链靠多类型组合（银狐A链 = dll_drop15+av_tamper20+av_tamper20+privilege15 = 70）过阈值。

## 3. 命令行模式表（`_DANGEROUS_CMD_PATTERNS`，行≈100）

顺序即优先级：av_tamper(20) → cred_dump(20) → privilege(15) → uac_bypass(10) → task_sched(15) → persistence(15)。
正则命中第一个就停。**新增 AV 进程名要同时加 taskkill/net stop/sc/wmic 四个分支。**

## 4. 文件防护阈值（文件监控子进程内，硬编码）

| 机制 | 阈值 | 位置 |
|---|---|---|
| 总量窗口 | 10s 内 20 次操作 → 回滚+终止整链 | `_show_dialog`（主进程） |
| 改写爆发 | 3s 内 ≥5 个不同文件 modify | 子进程 `_watch_dir` |
| 改后缀/挪移爆发 | 3s 内 ≥5 个不同文件 rename（扩展名变化或跨目录） | 同上（rename_paths） |
| 删除爆发 | 3s 内 ≥8 个不同文件 delete | 同上（delete_paths） |
| 外壳豁免 | `_FILE_OP_EXEMPT_NAMES` + 路径不在落毒高发目录 | `_show_dialog` |
| 恶意 DLL 隔离 | 仅隔离监控启动后新落盘的（ctime 闸门 60s 容差）；旧的绝不自动动 | `_quarantine_new_drop` |

## 5. 防误报闸门清单（动哪个都可能回归误报）

- `EDR_EXEMPT_NAMES`（评分豁免）/ `_FILE_OP_EXEMPT_NAMES`（文件防护豁免，两者用途不同别混）
- `_SIDELOAD_PROXY_DLLS` 白加黑名单（只在可疑目录计分）
- `_REG_PERSIST_KEYS` 敏感注册表分类
- 计分双闸（见上）
- Program Files/Programs 目录硬保护（`_scan_dropped_file` 开头）
- ETW `White.json` 树状白名单已限 kinds（进程类不短路——曾导致宏链规则全灭）

## 6. 改完必跑

```
python _full_test.py    # 50项: 拦截组+误报组+隔离策略+勒索全链
python _trust_test.py   # 29项: 银狐规则命中+可信操作
```
