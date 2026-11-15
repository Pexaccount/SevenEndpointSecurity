taskkill /F /IM SevenAgent.exe >nul 2>&1
logman stop "SevenAgent-Process" -ets >nul 2>&1
exit
