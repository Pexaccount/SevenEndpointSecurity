@echo off
cd /d D:\Administrator\Desktop\TestUI\CodeBak
start /b python _SevenEndPoint_debug.py --etw-worker > dbg_out6.txt 2>&1
ping -n 8 127.0.0.1 > nul
logman -ets query SevenEndPointTelemetry > lm_e1.txt 2>&1
for /l %%i in (1,1,10) do cmd /c echo x%%i > %TEMP%\etw_lm2_%%i.txt
ping -n 8 127.0.0.1 > nul
logman -ets query SevenEndPointTelemetry > lm_e2.txt 2>&1
exit
