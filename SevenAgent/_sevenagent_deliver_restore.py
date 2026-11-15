# -*- coding: utf-8 -*-
"""Restore full alert delivery: named-pipe primary + TCP 47821 fallback + local file.

The ETW-ABI isolation round (2026-11-14) had reduced deliver() to local-file only
("pipe/TCP disabled"), which made the agent detect and log but never SEND pid to
the main guard -> no termination, no notification. This patch restores the v3
dual-channel contract without touching any detection path:
  - deliver(): local file ALWAYS + pipe write (fail-fast connect) + tcp_send fallback
  - pipe_keeper thread: reconnect every ~2s while running
  - boot diag/stderr line updated accordingly
"""
import io, shutil, sys, time

SRC = r"D:\Administrator\Desktop\TestUI\CodeBak\SevenAgent\SevenAgent.c"
s = io.open(SRC, "r", encoding="utf-8", newline="").read()

def rep(tag, old, new):
    global s
    n = s.count(old)
    if n != 1:
        print("FAIL %s: anchor count=%d" % (tag, n)); sys.exit(1)
    s = s.replace(old, new)
    print("ok   %s" % tag)

bak = SRC + ".bak_deliver_" + time.strftime("%H%M%S")
shutil.copy2(SRC, bak)
print("backup ->", bak)

# P1: counter
rep("P1 add g_diag_pipe counter",
    "static DWORD g_diag_events=0,g_diag_proc=0,g_diag_cmdfail=0,g_diag_pebok=0,g_diag_drop=0,g_diag_alert=0,g_diag_tcp=0;",
    "static DWORD g_diag_events=0,g_diag_proc=0,g_diag_cmdfail=0,g_diag_pebok=0,g_diag_drop=0,g_diag_alert=0,g_diag_tcp=0,g_diag_pipe=0;")

# P2: comment block above deliver reflects restored contract
rep("P2 delivery comment",
    "/* Every alert is appended to a LOCAL file, one JSON object per line.\n   No named pipe, no TCP, no main-guard involvement. */",
    "/* Every alert is appended to a LOCAL file, one JSON object per line, and\n   delivered to the main guard: named pipe primary, 127.0.0.1:47821 TCP fallback. */")

# P3: pipe_try + pipe_keeper + deliver rewrite
rep("P3 deliver full restore",
    'static void pipe_fast(void){}\n'
    'static int deliver(const char*msg){\n'
    ' g_diag_alert++;\n'
    ' diag("ALERT %s",msg);\n'
    ' alert_log(msg);\n'
    ' return 1;}',
    'static void pipe_fast(void){}\n'
    '/* v4 restored dual-channel delivery (detection paths unchanged):\n'
    '   local file ALWAYS + named-pipe primary + 127.0.0.1:47821 TCP fallback. */\n'
    'static void pipe_try(void){\n'
    ' if(g_pipe_handle!=INVALID_HANDLE_VALUE)return;\n'
    ' g_pipe_handle=CreateFileW(g_pipe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);\n'
    ' if(g_pipe_handle!=INVALID_HANDLE_VALUE)diag("IPC pipe connected");}\n'
    'static DWORD WINAPI pipe_keeper(LPVOID x){\n'
    ' (void)x;\n'
    ' while(g_running){pipe_try();{int s;for(s=0;s<20&&g_running;s++)Sleep(100);}}\n'
    ' return 0;}\n'
    'static int deliver(const char*msg){\n'
    ' DWORD w=0;int sent=0;size_t L;\n'
    ' g_diag_alert++;\n'
    ' EnterCriticalSection(&g_diag_lock);\n'
    ' diag("ALERT %s",msg);\n'
    ' alert_log(msg);\n'
    ' L=strlen(msg);\n'
    ' if(g_pipe_handle==INVALID_HANDLE_VALUE)pipe_try();\n'
    ' if(g_pipe_handle!=INVALID_HANDLE_VALUE){\n'
    '  if(WriteFile(g_pipe_handle,msg,(DWORD)L,&w,NULL)&&w==(DWORD)L){g_diag_pipe++;sent=1;}\n'
    '  else{CloseHandle(g_pipe_handle);g_pipe_handle=INVALID_HANDLE_VALUE;\n'
    '   diag("IPC pipe write failed -> TCP fallback");}}\n'
    ' LeaveCriticalSection(&g_diag_lock);\n'
    ' if(!sent&&tcp_send(msg)){g_diag_tcp++;sent=1;}\n'
    ' diag("DELIVER %s pipe=%lu tcp=%lu",sent?"sent":"FAILED",(unsigned long)g_diag_pipe,(unsigned long)g_diag_tcp);\n'
    ' return sent;}')

# P4: wmain delivery boot block + start pipe_keeper
rep("P4 wmain delivery init",
    'pipe_fast();fwprintf(stderr,L"[SevenAgent][DELIVERY] local-file agent_alerts.log (pipe/TCP disabled)\\n");diag("DELIVERY local-file agent_alerts.log (pipe/TCP disabled)");CreateThread(NULL,0,parent_watch,NULL,0,NULL);',
    'pipe_fast();fwprintf(stderr,L"[SevenAgent][DELIVERY] pipe primary + TCP 47821 fallback + local agent_alerts.log\\n");diag("DELIVERY pipe primary + TCP %d fallback + local file",AGENT_TCP_PORT);CreateThread(NULL,0,pipe_keeper,NULL,0,NULL);CreateThread(NULL,0,parent_watch,NULL,0,NULL);')

io.open(SRC, "w", encoding="utf-8", newline="").write(s)
print("PATCHED OK")
