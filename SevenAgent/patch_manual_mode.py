from pathlib import Path
p=Path(__file__).with_name('SevenAgent.c')
s=p.read_text(encoding='utf-8')
s=s.replace('typedef BOOL (WINAPI *PFN_QUERY_IMAGE)(HANDLE,DWORD,LPWSTR,PDWORD);', 'typedef BOOL (WINAPI *PFN_QUERY_IMAGE)(HANDLE,DWORD,LPWSTR,PDWORD);\ntypedef BOOL (WINAPI *PFN_ENUM_PROCESSES)(DWORD*,DWORD,DWORD*);')
s=s.replace('static PFN_TDH_INFO pTdhInfo;', 'static PFN_ENUM_PROCESSES pEnumProcesses;static PFN_TDH_INFO pTdhInfo;')
s=s.replace('static int process_path(DWORD pid,WCHAR*out,DWORD cap)', 'static DWORD find_controller(void){HMODULE m=LoadLibraryW(L"psapi.dll");PFN_ENUM_PROCESSES fn;DWORD ids[4096],need=0,i;WCHAR p[MAX_PATH];if(!m)return 0;fn=(PFN_ENUM_PROCESSES)GetProcAddress(m,"EnumProcesses");if(!fn||!fn(ids,sizeof(ids),&need))return 0;for(i=0;i<need/sizeof(DWORD);i++){if(ids[i]&&process_path(ids[i],p,MAX_PATH)&&has(p,L"\\\\sevenendpoint.exe"))return ids[i];}return 0;}\nstatic int process_path(DWORD pid,WCHAR*out,DWORD cap)')
s=s.replace('if(!g_parent){fwprintf(stderr,L"[SevenAgent] Missing controller PID.\\n");return 10;}', 'if(!g_parent)g_parent=find_controller();if(!g_parent){fwprintf(stderr,L"[SevenAgent] Waiting for SevenEndPoint.exe; retrying controller discovery.\\n");for(;;){Sleep(2000);g_parent=find_controller();if(g_parent)break;}}')
p.write_text(s,encoding='utf-8',newline='')
