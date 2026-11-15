#define _WIN32_WINNT 0x0601
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <stdint.h>

typedef ULONGLONG TRACEHANDLE;
typedef struct { USHORT Id; UCHAR Version,Channel,Level,Opcode; USHORT Task; ULONGLONG Keyword; } EVENT_DESCRIPTOR_L;
typedef struct { USHORT Size,HeaderType,Flags,EventProperty; ULONG ThreadId,ProcessId; LARGE_INTEGER TimeStamp; GUID ProviderId; EVENT_DESCRIPTOR_L EventDescriptor; ULONG KernelTime,UserTime; GUID ActivityId; } EVENT_HEADER_L;
typedef struct { UCHAR ProcessorNumber,Alignment; USHORT LoggerId; } ETW_BUFFER_CONTEXT_L;
typedef struct { EVENT_HEADER_L EventHeader; ETW_BUFFER_CONTEXT_L BufferContext; USHORT ExtendedDataCount,UserDataLength; PVOID ExtendedData,UserData,UserContext; } EVENT_RECORD_L;
typedef struct { ULONG BufferSize,ProviderId; ULONGLONG HistoricalContext; LARGE_INTEGER TimeStamp; GUID Guid; ULONG ClientContext,Flags; } WNODE_HEADER_L;
typedef struct { WNODE_HEADER_L Wnode; ULONG BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags; LONG AgeLimit; ULONG NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost; HANDLE LoggerThreadId; ULONG LogFileNameOffset,LoggerNameOffset; } EVENT_TRACE_PROPERTIES_L;
typedef struct { LONG Bias; WCHAR StandardName[32]; SYSTEMTIME StandardDate; LONG StandardBias; WCHAR DaylightName[32]; SYSTEMTIME DaylightDate; LONG DaylightBias; } TIME_ZONE_INFORMATION_L;
typedef struct { ULONG BufferSize,Version,ProviderVersion,NumberOfProcessors; LARGE_INTEGER EndTime; ULONG TimerResolution,MaximumFileSize,LogFileMode,BuffersWritten; GUID LogInstanceGuid; LPWSTR LoggerName,LogFileName; TIME_ZONE_INFORMATION_L TimeZone; LARGE_INTEGER BootTime,PerfFreq,StartTime; ULONG ReservedFlags,BuffersLost; } TRACE_LOGFILE_HEADER_L;
typedef VOID (WINAPI *PEVENT_RECORD_CB)(EVENT_RECORD_L*);
typedef ULONG (WINAPI *PBUFFER_CB)(PVOID);
/* EVENT_TRACE (x64) is 120 bytes and field-compatible with EVENT_TRACE_PROPERTIES */
typedef EVENT_TRACE_PROPERTIES_L EVENT_TRACE_L;
/* Official x64 SDK layout: size=480, EventRecordCallback offset=456, Context offset=472 */
typedef struct { LPWSTR LogFileName,LoggerName; LONGLONG CurrentTime; ULONG BuffersRead,ProcessTraceMode;
 EVENT_TRACE_L CurrentEvent; TRACE_LOGFILE_HEADER_L LogfileHeader;
 PBUFFER_CB BufferCallback; ULONG BufferSize,Filled,EventsLost;
 union { PVOID EventCallback; PEVENT_RECORD_CB EventRecordCallback; };
 ULONG IsKernelTrace; PVOID Context; } EVENT_TRACE_LOGFILE_L;
typedef struct { ULONG Flags,NameOffset; union { struct { USHORT InType,OutType; ULONG MapNameOffset; } T; struct { USHORT StructStartIndex,NumOfStructMembers; ULONG Padding; } S; }; USHORT Count,Length; ULONG Reserved; } EVENT_PROPERTY_INFO_L;
typedef struct { GUID ProviderGuid,EventGuid; EVENT_DESCRIPTOR_L EventDescriptor; ULONG DecodingSource,ProviderNameOffset,LevelNameOffset,ChannelNameOffset,KeywordsNameOffset,TaskNameOffset,OpcodeNameOffset,EventMessageOffset,ProviderMessageOffset,BinaryXMLOffset,BinaryXMLSize,ActivityIDNameOffset,RelatedActivityIDNameOffset,PropertyCount,TopLevelPropertyCount,Flags; EVENT_PROPERTY_INFO_L EventPropertyInfoArray[1]; } TRACE_EVENT_INFO_L;
typedef struct { ULONGLONG PropertyName; ULONG ArrayIndex,Reserved; } PROPERTY_DATA_DESCRIPTOR_L;
#define WNODE_FLAG_TRACED_GUID 0x00020000
#define EVENT_TRACE_REAL_TIME_MODE 0x00000100
#define EVENT_TRACE_CONTROL_STOP   1
#define EVENT_TRACE_CONTROL_QUERY  0
#define EVENT_TRACE_CONTROL_UPDATE 2
#define KERNEL_LOGGER_NAMEW       L"NT Kernel Logger"
#define EVENT_TRACE_SYSTEM_LOGGER_MODE 0x02000000
#define EVENT_TRACE_FLAG_PROCESS 0x00000001
#define EVENT_TRACE_FLAG_IMAGE_LOAD 0x00000004
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
/* ===== official private-session route: Microsoft-Windows-Kernel-Process provider ===== */
#define WINEVENT_KEYWORD_PROCESS 0x0000000000000010ULL
#define EVENT_CONTROL_CODE_DISABLE_PROVIDER 0
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER  1
static const GUID KERNEL_PROCESS_GUID={0x22fb2cd6,0x0045,0x4c1e,{0x8b,0x13,0x8e,0x40,0x34,0x94,0x86,0xe4}};
typedef ULONG (WINAPI *PFN_ENABLE)(TRACEHANDLE,const GUID*,ULONG,UCHAR,ULONGLONG,ULONGLONG,ULONG,PVOID);
typedef ULONG (WINAPI *PFN_DISABLE)(TRACEHANDLE);
static PFN_ENABLE pEnable;static PFN_DISABLE pDisable;
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS 183
#endif
#define MAX_HITS 512
#define IMAGE_LOAD_EVENT 10
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

typedef ULONG (WINAPI *PFN_START)(TRACEHANDLE*,LPCWSTR,EVENT_TRACE_PROPERTIES_L*);
typedef ULONG (WINAPI *PFN_CONTROL)(TRACEHANDLE,LPCWSTR,EVENT_TRACE_PROPERTIES_L*,ULONG);
typedef TRACEHANDLE (WINAPI *PFN_OPEN)(EVENT_TRACE_LOGFILE_L*);
typedef ULONG (WINAPI *PFN_PROCESS)(TRACEHANDLE*,ULONG,LPFILETIME,LPFILETIME);
typedef ULONG (WINAPI *PFN_CLOSE)(TRACEHANDLE);
typedef ULONG (WINAPI *PFN_TDH_INFO)(EVENT_RECORD_L*,ULONG,PVOID,TRACE_EVENT_INFO_L*,ULONG*);
typedef ULONG (WINAPI *PFN_TDH_SIZE)(EVENT_RECORD_L*,ULONG,PVOID,ULONG,PROPERTY_DATA_DESCRIPTOR_L*,ULONG*);
typedef ULONG (WINAPI *PFN_TDH_GET)(EVENT_RECORD_L*,ULONG,PVOID,ULONG,PROPERTY_DATA_DESCRIPTOR_L*,ULONG,PBYTE);
typedef BOOL (WINAPI *PFN_QUERY_IMAGE)(HANDLE,DWORD,LPWSTR,PDWORD);
typedef BOOL (WINAPI *PFN_ENUM_PROCESSES)(DWORD*,DWORD,DWORD*);
static PFN_START pStart;static PFN_CONTROL pControl;static PFN_OPEN pOpen;static PFN_PROCESS pProcess;static PFN_CLOSE pClose;static PFN_ENUM_PROCESSES pEnumProcesses;static PFN_TDH_INFO pTdhInfo;static PFN_TDH_SIZE pTdhSize;static PFN_TDH_GET pTdhGet;static PFN_QUERY_IMAGE pQueryImage;
static WCHAR g_session[128]=L"SevenAgent-Process",g_pipe[]=L"\\\\.\\pipe\\SevenAgentIPC";static DWORD g_parent;static HANDLE g_pipe_handle=INVALID_HANDLE_VALUE;static volatile LONG g_running=1;static LONG g_bad=0;static TRACEHANDLE g_session_handle;static EVENT_TRACE_PROPERTIES_L*g_props;static TRACEHANDLE g_session_handle;static EVENT_TRACE_PROPERTIES_L*g_props;
typedef struct {DWORD pid;ULONGLONG tick;WCHAR module[MAX_PATH];} HIT;static HIT g_hits[MAX_HITS];static LONG g_hit_count;static CRITICAL_SECTION g_lock;
static int has(const WCHAR*s,const WCHAR*q){WCHAR a[MAX_PATH*2],b[128];DWORD i;if(!s||!q)return 0;for(i=0;s[i]&&i<MAX_PATH*2-1;i++)a[i]=(WCHAR)towlower(s[i]);a[i]=0;for(i=0;q[i]&&i<127;i++)b[i]=(WCHAR)towlower(q[i]);b[i]=0;return wcsstr(a,b)!=0;}
static int sensitive_dll(const WCHAR*p){return has(p,L"\\version.dll")||has(p,L"\\winmm.dll")||has(p,L"\\dbghelp.dll")||has(p,L"\\dxgi.dll")||has(p,L"\\d3d9.dll")||has(p,L"\\d3d11.dll")||has(p,L"\\winhttp.dll")||has(p,L"\\wintrust.dll")||has(p,L"\\usp10.dll");}
static int user_path(const WCHAR*p){return has(p,L"\\appdata\\")||has(p,L"\\temp\\")||has(p,L"\\downloads\\")||has(p,L"\\users\\public\\")||has(p,L"\\programdata\\");}
static int risky_host(const WCHAR*p){return has(p,L"\\rundll32.exe")||has(p,L"\\regsvr32.exe")||has(p,L"\\mshta.exe")||has(p,L"\\installutil.exe")||has(p,L"\\control.exe");}
static int exempt(const WCHAR*p){return has(p,L"\\sevenagent\\")||has(p,L"\\sevenendpointsecurity\\")||has(p,L"\\sevenendpoint.exe");}
/* ===== v3 additive layer: localhost dual-channel delivery + pending-chain correlation =====
   Design contract (all existing detection/termination paths are preserved verbatim):
   - named pipe stays the PRIMARY channel; 127.0.0.1 TCP is a fallback when the pipe is
     busy/broken (UIdebug showed 28 consecutive [Errno 231] ERROR_PIPE_BUSY at 14:30).
   - when a PID/image cannot be resolved, the signal is NOT dropped: it is silently
     recorded under a chain_key. A later behaviour on the same chain_key links the
     observations together and emits one terminate (user: "串起来终止").
   - PID-less first sighting is ALWAYS "observe" (report only, never terminate).
   ==================================================================================== */
#include <string.h>
#include <stdarg.h>
/* ===== v3 diagnostic layer: standalone agent_diag.log + ETW watchdog ===== */
static CRITICAL_SECTION g_diag_lock;
static FILE*g_diagf=NULL;
static FILE*g_alertf=NULL;
static TRACEHANDLE g_trace;
static int g_owns_session=0;  /* only 1 when we called StartTrace successfully */
static BYTE g_logbuf[1024]; /* static; sizeof(EVENT_TRACE_LOGFILE_L)=480, buffer oversized on purpose */
static void diag_open(void){
 char p[MAX_PATH],q[MAX_PATH];DWORD n=GetModuleFileNameA(NULL,p,MAX_PATH);char*s;
 if(!n||n>=MAX_PATH)return;
 s=strrchr(p,'\\');if(s)*(s+1)=0;else p[0]=0;
 strcpy(q,p);
 strncat(p,"agent_diag.log",MAX_PATH-strlen(p)-1);
 strncat(q,"agent_alerts.log",MAX_PATH-strlen(q)-1);
 g_diagf=fopen(p,"a");g_alertf=fopen(q,"a");
}
/* Deliberately FILE-ONLY: writing stderr here could block if the main guard's
   stderr pump died and the pipe filled up (that is one of the failure modes
   under investigation). */
static void diag(const char*fmt,...){
 char b[1200];va_list ap;va_start(ap,fmt);
 _vsnprintf(b,sizeof(b)-1,fmt,ap);b[sizeof(b)-1]=0;va_end(ap);
 EnterCriticalSection(&g_diag_lock);
 if(g_diagf){fprintf(g_diagf,"[%lu] %s\n",(unsigned long)GetTickCount(),b);fflush(g_diagf);}
 LeaveCriticalSection(&g_diag_lock);
}
/* Every alert is appended to a LOCAL file, one JSON object per line, and
   delivered to the main guard: named pipe primary, 127.0.0.1:47821 TCP fallback. */
static int g_alert_file_ok=0;
static void alert_log(const char*msg){
 size_t L=strlen(msg);
 EnterCriticalSection(&g_diag_lock);
 if(g_alertf){fwrite(msg,1,L,g_alertf);if(!L||msg[L-1]!='\n')fputc('\n',g_alertf);fflush(g_alertf);g_alert_file_ok=1;}
 LeaveCriticalSection(&g_diag_lock);
}
static DWORD WINAPI etw_worker(LPVOID x){(void)x;pProcess(&g_trace,1,NULL,NULL);diag("ETW worker exited");return 0;}
#define AGENT_TCP_PORT 47821
#define PENDING_MAX 64
#define PEND_WINDOW_MS 120000
#define PEND_SCORE_TH 50
typedef int (WINAPI *PFN_WSASTARTUP)(unsigned short,void*);
typedef unsigned long long (WINAPI *PFN_SOCKET)(int,int,int);
typedef int (WINAPI *PFN_CONNECT)(unsigned long long,const void*,int);
typedef int (WINAPI *PFN_SEND)(unsigned long long,const char*,int,int);
typedef int (WINAPI *PFN_CLOSESOCKET)(unsigned long long);
typedef unsigned short (WINAPI *PFN_HTONS)(unsigned short);
typedef struct {short f;unsigned short p;unsigned long a;char z[8];} SAIN_L;
typedef LONG (WINAPI *PFN_NTQIP)(HANDLE,int,PVOID,ULONG,PULONG);
typedef struct {LONG ExitStatus;PVOID PebBaseAddress;unsigned long long AffinityMask;LONG BasePriority;unsigned long long UniqueProcessId;unsigned long long InheritedFromUniqueProcessId;} PBI_L;
typedef struct {unsigned short Length,MaximumLength;PVOID Buffer;} US_L;
typedef struct {char key[40];WCHAR image[MAX_PATH];char rid[64],beh[96],detail[256],cmd[256];
 int sum,hits,ntypes;char types[8][32];DWORD last_pid;ULONGLONG tick;int fired;} PEND;
static PEND g_pend[PENDING_MAX];static int g_pend_n=0;
static DWORD g_pipe_retry=0;
static DWORD g_diag_events=0,g_diag_proc=0,g_diag_cmdfail=0,g_diag_pebok=0,g_diag_drop=0,g_diag_alert=0,g_diag_tcp=0,g_diag_pipe=0;
static PFN_WSASTARTUP pWsaStart;static PFN_SOCKET pSocket;static PFN_CONNECT pConnect;static PFN_SEND pSend;
static PFN_CLOSESOCKET pCloseSocket;static PFN_HTONS pHtons;static int g_ws=-1;
static int deliver(const char*msg);
static void pipe_fast(void);
static void esc_put(char*out,int cap,const char*s){int i=0,j=0;unsigned char c;if(cap<1)return;
 while(s&&s[i]&&j+7<cap){c=(unsigned char)s[i++];
  if(c==34||c==92){out[j++]=92;out[j++]=(char)c;}
  else if(c<0x20||c>0x7e){_snprintf(out+j,7,"\\u%04x",(unsigned)c);j+=6;}
  else out[j++]=(char)c;}
 out[j]=0;}
static void esc_put_w(char*out,int cap,const WCHAR*s){int i=0,j=0;WCHAR c;if(cap<1)return;
 while(s&&s[i]&&j+7<cap){c=s[i++];
  if(c==L'\\'||c==L'"'){out[j++]=92;out[j++]=(char)c;}
  else if(c<0x20||c>0x7e){_snprintf(out+j,7,"\\u%04x",(unsigned)c);j+=6;}
  else out[j++]=(char)c;}
 out[j]=0;}
static int tcp_send(const char*msg){char wsa[512];SAIN_L sa;unsigned long long s;DWORD n=0;
 int len=(int)strlen(msg),off=0,k,ok=0;
 if(g_ws<0){HMODULE m=LoadLibraryW(L"ws2_32.dll");g_ws=0;
  if(m){pWsaStart=(PFN_WSASTARTUP)GetProcAddress(m,"WSAStartup");
   pSocket=(PFN_SOCKET)GetProcAddress(m,"socket");pConnect=(PFN_CONNECT)GetProcAddress(m,"connect");
   pSend=(PFN_SEND)GetProcAddress(m,"send");pCloseSocket=(PFN_CLOSESOCKET)GetProcAddress(m,"closesocket");
   pHtons=(PFN_HTONS)GetProcAddress(m,"htons");
   if(pWsaStart&&pSocket&&pConnect&&pSend&&pCloseSocket&&pHtons){ZeroMemory(wsa,sizeof(wsa));
    if(pWsaStart(0x0202,wsa)==0)g_ws=1;}}}
 if(!g_ws)return 0;
 s=pSocket(2,1,6);if(s==(unsigned long long)-1||s==0)return 0;
 ZeroMemory(&sa,sizeof(sa));sa.f=2;sa.p=pHtons((unsigned short)AGENT_TCP_PORT);sa.a=0x0100007fUL;
 if(pConnect(s,&sa,sizeof(sa))==0){while(off<len){k=pSend(s,msg+off,len-off,0);if(k<=0)break;off+=k;}ok=(off==len);}
 pCloseSocket(s);return ok;}
static void pipe_fast(void){}
/* v4 restored dual-channel delivery (detection paths unchanged):
   local file ALWAYS + named-pipe primary + 127.0.0.1:47821 TCP fallback. */
static void pipe_try(void){
 if(g_pipe_handle!=INVALID_HANDLE_VALUE)return;
 g_pipe_handle=CreateFileW(g_pipe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(g_pipe_handle!=INVALID_HANDLE_VALUE)diag("IPC pipe connected");}
static DWORD WINAPI pipe_keeper(LPVOID x){
 (void)x;
 while(g_running){pipe_try();{int s;for(s=0;s<20&&g_running;s++)Sleep(100);}}
 return 0;}
static int deliver(const char*msg){
 DWORD w=0;int sent=0;size_t L;
 g_diag_alert++;
 EnterCriticalSection(&g_diag_lock);
 diag("ALERT %s",msg);
 alert_log(msg);
 L=strlen(msg);
 if(g_pipe_handle==INVALID_HANDLE_VALUE)pipe_try();
 if(g_pipe_handle!=INVALID_HANDLE_VALUE){
  if(WriteFile(g_pipe_handle,msg,(DWORD)L,&w,NULL)&&w==(DWORD)L){g_diag_pipe++;sent=1;}
  else{CloseHandle(g_pipe_handle);g_pipe_handle=INVALID_HANDLE_VALUE;
   diag("IPC pipe write failed -> TCP fallback");}}
 LeaveCriticalSection(&g_diag_lock);
 if(!sent&&tcp_send(msg)){g_diag_tcp++;sent=1;}
 diag("DELIVER %s pipe=%lu tcp=%lu",sent?"sent":"FAILED",(unsigned long)g_diag_pipe,(unsigned long)g_diag_tcp);
 return sent;}
static void diag_report(void){
 if(g_diag_events&&(g_diag_events%200)==0)
  fwprintf(stderr,L"[SevenAgent][DIAG] events=%lu proc=%lu cmdfail=%lu pebok=%lu drop=%lu alerts=%lu pipe=%lu tcp=%lu pend=%d\n",
   (unsigned long)g_diag_events,(unsigned long)g_diag_proc,(unsigned long)g_diag_cmdfail,
   (unsigned long)g_diag_pebok,(unsigned long)g_diag_drop,(unsigned long)g_diag_alert,
   (unsigned long)g_diag_pipe,(unsigned long)g_diag_tcp,g_pend_n);}
static void make_key(const WCHAR*image,char*out,int cap){unsigned long long h=1469598103934665603ULL;
 int i;WCHAR b[MAX_PATH];const WCHAR*p=image,*s=wcsrchr(image,L'\\');
 if(s)s++;p=s?s:image;
 for(i=0;p[i]&&i<MAX_PATH-1;i++)b[i]=(WCHAR)towlower(p[i]);b[i]=0;
 for(i=0;b[i];i++){h^=(unsigned)(b[i]&0xff);h*=1099511628211ULL;h^=(unsigned)((b[i]>>8)&0xff);h*=1099511628211ULL;}
 _snprintf(out,cap-1,"%08x%08x",(unsigned)(h>>32),(unsigned)(h&0xffffffff));out[cap-1]=0;}
static int peb_cmdline(DWORD pid,char*out,int cap){HANDLE h;HMODULE m;PFN_NTQIP fn;
 PBI_L pbi;unsigned long long pp=0;US_L us;ULONG nt=0;unsigned long long nr=0;WCHAR w[2048];int i,j=0;
 if(!pid)return 0;m=GetModuleHandleW(L"ntdll.dll");if(!m)return 0;
 fn=(PFN_NTQIP)GetProcAddress(m,"NtQueryInformationProcess");if(!fn)return 0;
 h=OpenProcess(0x0410,FALSE,pid);if(!h)return 0;
 ZeroMemory(&pbi,sizeof(pbi));
 if(fn(h,0,&pbi,sizeof(pbi),&nt)!=0||!pbi.PebBaseAddress){CloseHandle(h);return 0;}
 if(!ReadProcessMemory(h,(BYTE*)pbi.PebBaseAddress+0x20,&pp,8,&nr)||!pp){CloseHandle(h);return 0;}
 ZeroMemory(&us,sizeof(us));
 if(!ReadProcessMemory(h,(BYTE*)pp+0x70,&us,sizeof(us),&nr)||!us.Buffer||us.Length<2||us.Length>sizeof(w)-2){CloseHandle(h);return 0;}
 ZeroMemory(w,sizeof(w));if(!ReadProcessMemory(h,us.Buffer,w,us.Length,&nr)){CloseHandle(h);return 0;}
 CloseHandle(h);
 for(i=0;i<(int)(us.Length/2)&&j+1<cap;i++){unsigned wc=(unsigned)w[i];if(!wc)break;
  out[j++]=(wc>=128)?'?':(char)(wc>='a'&&wc<='z'?wc-32:wc);}
 out[j]=0;if(j)g_diag_pebok++;return j>0;}
static PEND*pend_get(const char*key,const WCHAR*image,int create){int i;ULONGLONG now=(ULONGLONG)GetTickCount();
 for(i=0;i<g_pend_n;i++)if(now-g_pend[i].tick>PEND_WINDOW_MS){g_pend[i]=g_pend[g_pend_n-1];g_pend_n--;i--;}
 for(i=0;i<g_pend_n;i++)if(!strcmp(g_pend[i].key,key)){g_pend[i].tick=now;return &g_pend[i];}
 if(!create||g_pend_n>=PENDING_MAX)return NULL;
 {PEND*e=&g_pend[g_pend_n++];ZeroMemory(e,sizeof(PEND));strncpy(e->key,key,39);
  lstrcpynW(e->image,image,MAX_PATH);e->tick=now;return e;}}
static void pend_emit(PEND*e,DWORD use,const char*action,int linked){
 char msg[4096],im[1024],dt[512],cm[512],beh[256],rid[128];
 esc_put_w(im,sizeof(im),e->image);esc_put(dt,sizeof(dt),e->detail);
 esc_put(cm,sizeof(cm),e->cmd);esc_put(beh,sizeof(beh),e->beh);esc_put(rid,sizeof(rid),e->rid);
 _snprintf(msg,sizeof(msg)-1,
  "{\"pid\":%lu,\"rule\":\"%s\",\"behavior\":\"%s\",\"family\":\"PendingChain\",\"module\":\"%s\",\"detail\":\"%s\",\"score\":%d,\"action\":\"%s\",\"pid_unknown\":%d,\"chain_key\":\"%s\",\"linked\":%d,\"cmd\":\"%s\"}\n",
  (unsigned long)use,rid,beh,im,dt,e->sum,action,use?0:1,e->key,linked,cm);
 msg[sizeof(msg)-1]=0;deliver(msg);}
static void pend_score(PEND*e,const char*type,int score,DWORD pid){int i,dup=0;
 for(i=0;i<e->ntypes;i++)if(!strcmp(e->types[i],type)){dup=1;break;}
 if(!dup&&e->ntypes<8){strncpy(e->types[e->ntypes],type,31);e->types[e->ntypes][31]=0;
  e->ntypes++;e->sum+=score;}
 e->hits++;if(pid)e->last_pid=pid;}
static void pend_signal(const char*key,const WCHAR*image,DWORD pid,const char*rid,const char*beh,
 const char*type,const char*detail,int score,const char*cmd,int emit){
 PEND*e=pend_get(key,image,1);if(!e)return;
 if(!e->rid[0]){strncpy(e->rid,rid,63);strncpy(e->beh,beh,95);
  strncpy(e->detail,detail,255);strncpy(e->cmd,cmd?cmd:"",255);}
 pend_score(e,type,score,pid);
 if(!emit)return;
 {int linked=e->hits>=2,score_hit=e->sum>=PEND_SCORE_TH,trigger=linked||score_hit;
  int can=(pid>0||e->last_pid>0);DWORD use=pid?pid:e->last_pid;
  if(trigger&&can&&!e->fired){e->fired=1;pend_emit(e,use,"terminate",e->hits);}
  else if(!e->fired)pend_emit(e,use,"observe",e->hits);}}
static void pend_touch(const char*key,DWORD pid,const char*type,int score){
 PEND*e=pend_get(key,L"",0);if(!e)return;
 pend_score(e,type,score,pid);
 if((e->hits>=2||e->sum>=PEND_SCORE_TH)&&e->last_pid&&!e->fired){e->fired=1;pend_emit(e,e->last_pid,"terminate",e->hits);}}
/* ===== end v3 additive layer ===== */
static int process_path(DWORD pid,WCHAR*out,DWORD cap);
static DWORD find_controller(void){HMODULE m=LoadLibraryW(L"psapi.dll");PFN_ENUM_PROCESSES fn;DWORD ids[4096],need=0,i;WCHAR p[MAX_PATH];if(!m)return 0;fn=(PFN_ENUM_PROCESSES)GetProcAddress(m,"EnumProcesses");if(!fn||!fn(ids,sizeof(ids),&need))return 0;for(i=0;i<need/sizeof(DWORD);i++){if(ids[i]&&ids[i]!=GetCurrentProcessId()&&process_path(ids[i],p,MAX_PATH)){WCHAR*base=wcsrchr(p,L'\\');base=base?base+1:p;if(!_wcsicmp(base,L"SevenEndPoint.exe"))return ids[i];}}return 0;}
static int process_path(DWORD pid,WCHAR*out,DWORD cap){HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);DWORD n=cap;int ok=0;out[0]=0;if(h){ok=pQueryImage&&pQueryImage(h,0,out,&n);CloseHandle(h);}return ok;}
static int pipe_connect(void){int i;for(i=0;i<120&&g_running;i++){g_pipe_handle=CreateFileW(g_pipe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(g_pipe_handle!=INVALID_HANDLE_VALUE)return 1;Sleep(250);}return 0;}
static void send_alert(DWORD pid,const WCHAR*module){char msg[4096],esc[2048];DWORD n,i=0,j=0;WCHAR c;if(g_pipe_handle==INVALID_HANDLE_VALUE)pipe_fast();while(module[i]&&j+6<sizeof(esc)){c=module[i++];if(c==L'\\'||c==L'"'){esc[j++]='\\';esc[j++]=(char)c;}else if(c<0x20||c>0x7e){_snprintf(esc+j,7,"\\u%04x",(unsigned)c);j+=6;}else esc[j++]=(char)c;}esc[j]=0;_snprintf(msg,sizeof(msg),"{\"pid\":%lu,\"rule\":\"Agent.HighConfidence.SideloadChain\",\"behavior\":\"ImageLoad.SuspiciousSideload\",\"family\":\"SilverFox\",\"module\":\"%s\"}\n",(unsigned long)pid,esc);deliver(msg);}
static int get_module(EVENT_RECORD_L*r,TRACE_EVENT_INFO_L*info,ULONG info_bytes,WCHAR*out,DWORD cap){ULONG i,sz,off;PROPERTY_DATA_DESCRIPTOR_L d;BYTE val[1024];WCHAR*name;for(i=0;i<info->TopLevelPropertyCount&&i<info->PropertyCount;i++){off=info->EventPropertyInfoArray[i].NameOffset;if(off>=info_bytes)continue;name=(WCHAR*)((BYTE*)info+off);if(!has(name,L"image")&&!has(name,L"file")&&!has(name,L"path"))continue;ZeroMemory(&d,sizeof(d));d.PropertyName=(ULONGLONG)(ULONG_PTR)name;d.ArrayIndex=0xffffffff;sz=0;if(pTdhSize(r,0,NULL,1,&d,&sz)!=0||sz<2||sz>sizeof(val)||(sz&1))continue;if(pTdhGet(r,0,NULL,1,&d,sz,val)!=0)continue;{DWORD c=sz/2;if(c>=cap)c=cap-1;memcpy(out,val,c*2);out[c]=0;if(out[0])return 1;}}return 0;}
#include <stdlib.h>
/* ===== v2 rules engine: external JSON rules, v1 SideloadChain logic untouched ===== */
#define V2_PAT_MAX 400
#define V2_RULES_MAX 4
#define V2_CB_MAX 256
typedef struct {char match[128];char context[128];char type[32];char mitre[16];char note[160];}V2PAT;
typedef struct {char id[64];char behavior[96];char level[16];int score;int npat;V2PAT pats[V2_PAT_MAX];}RULE2;
static RULE2 g_v2[V2_RULES_MAX];static int g_v2_count=0;
static int g_combo_th=60,g_combo_types=3,g_susp_th=30,g_susp_types=2,g_mod_score=20,g_window_ms=120000;
static char g_combo_rule[64]="Agent.Combo.HighConfidence",g_combo_behavior[96]="ProcessCombo.SuspiciousChain";
static char g_susp_rule[64]="Agent.Combo.SuspectChain",g_susp_behavior[96]="ProcessCombo.SuspectChain";
static char g_rules_path[MAX_PATH];static int g_selftest=0;
typedef struct JV{int t;char*s;double n;struct JV**kids;char**keys;int nkid;}JV;
static HANDLE g_arena=NULL;
static void*ja(size_t n){return HeapAlloc(g_arena,HEAP_ZERO_MEMORY,n);}
static JV*jobj_new(void){JV*v=(JV*)ja(sizeof(JV));v->t=0;v->keys=(char**)ja(64*sizeof(char*));v->kids=(JV**)ja(64*sizeof(JV*));return v;}
static JV*jarr_new(void){JV*v=(JV*)ja(sizeof(JV));v->t=1;v->kids=(JV**)ja(512*sizeof(JV*));return v;}
static void jpush(JV*v,JV*k,const char*key){int cap=(v->t==1)?512:64;if(v->nkid>=cap)return;if(key)v->keys[v->nkid]=(char*)key;v->kids[v->nkid++]=k;}
static JV*jget(JV*v,const char*key){int i;if(!v||v->t!=0)return NULL;for(i=0;i<v->nkid;i++)if(v->keys[i]&&!strcmp(v->keys[i],key))return v->kids[i];return NULL;}
static const char*jstr(JV*v){return (v&&v->t==2)?v->s:"";}
static const char*jp_skip(const char*p){while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n')p++;return p;}
static const char*jp_str(const char*p,char*out,int cap){int i=0;out[0]=0;if(*p!='"')return p;p++;while(*p&&*p!='"'&&i<cap-1){char c=*p;if(c=='\\'&&p[1]){p++;char e=*p;c=e;if(e=='n')c='\n';else if(e=='t')c='\t';else if(e=='r')c='\r';else if(e=='u'&&p[1]&&p[2]&&p[3]&&p[4]){unsigned v=0;int k;for(k=1;k<=4;k++){char h=p[k];v=(v<<4);if(h>='0'&&h<='9')v+=(unsigned)(h-'0');else if(h>='A'&&h<='F')v+=(unsigned)(h-'A'+10);else if(h>='a'&&h<='f')v+=(unsigned)(h-'a'+10);}p+=4;if(v<128)c=(char)v;else c='?';}}out[i++]=c;p++;}out[i]=0;if(*p=='"')p++;return p;}
static const char*jp_val(const char*p,JV**out);
static const char*jp_val(const char*p,JV**out){p=jp_skip(p);*out=NULL;
 if(*p=='{'){JV*o=jobj_new();p=jp_skip(p+1);while(*p&&*p!='}'){char*k;p=jp_skip(p);if(*p!='"')return p;k=(char*)ja(160);p=jp_str(p,k,160);p=jp_skip(p);if(*p==':')p++;{JV*cv;p=jp_val(p,&cv);if(!cv)return p;jpush(o,cv,k);}p=jp_skip(p);if(*p==',')p++;}if(*p=='}')p++;*out=o;return p;}
 if(*p=='['){JV*a=jarr_new();p=jp_skip(p+1);while(*p&&*p!=']'){JV*k;p=jp_val(p,&k);if(!k)return p;jpush(a,k,NULL);p=jp_skip(p);if(*p==',')p++;}if(*p==']')p++;*out=a;return p;}
 if(*p=='"'){char*s=(char*)ja(4096);p=jp_str(p,s,4096);{JV*v=(JV*)ja(sizeof(JV));v->t=2;v->s=s;*out=v;}return p;}
 if(!strncmp(p,"true",4)){JV*v=(JV*)ja(sizeof(JV));v->t=4;v->n=1;*out=v;p+=4;return p;}
 if(!strncmp(p,"false",5)){JV*v=(JV*)ja(sizeof(JV));v->t=4;v->n=0;*out=v;p+=5;return p;}
 if(!strncmp(p,"null",4)){JV*v=(JV*)ja(sizeof(JV));v->t=5;*out=v;p+=4;return p;}
 {char*end=NULL;double d=strtod(p,&end);if(end&&end>p){JV*v=(JV*)ja(sizeof(JV));v->t=3;v->n=d;*out=v;return end;}}
 return p;}
static void v2_load(void){JV*root=NULL,*rules,*combo;int i,k;
 g_arena=HeapCreate(0,0,0);if(!g_arena)return;
 {char*buf=(char*)ja(2097152);HANDLE f;DWORD n=0;
  f=CreateFileA(g_rules_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
  if(f==INVALID_HANDLE_VALUE){fwprintf(stderr,L"[v2] open failed err=%lu
",(unsigned long)GetLastError());HeapDestroy(g_arena);g_arena=NULL;return;}
  ReadFile(f,buf,2097152,&n,NULL);CloseHandle(f);buf[n]=0;
  if(g_selftest)fwprintf(stderr,L"[v2] bytes=%lu
",(unsigned long)n);
  {const char*p=jp_val(buf,&root);if(!root||root->t!=0){int off=(int)(p-buf);fwprintf(stderr,L"[v2] parse failed root=%p t=%d off=%d ctx=[%.40S]
",root,root?root->t:-1,off,(root?(const wchar_t*)L"?" : (const wchar_t*)(buf+ (off>20?off-20:0))));HeapDestroy(g_arena);g_arena=NULL;return;}}
  if(g_selftest){JV*rl=jget(root,"rules");if(rl)fwprintf(stderr,L"[v2] rules nkid=%d
",rl->nkid);{int q;for(q=0;q<((rl&&rl->t==1)?rl->nkid:0);q++){JV*r2=rl->kids[q];JV*kd=jget(r2,"kind");fwprintf(stderr,L"  [%d] kind=%S id=%S
",q,kd?jstr(kd):"(null)",jget(r2,"id")?jstr(jget(r2,"id")):"(null)");}}}}
 rules=jget(root,"rules");
 if(rules&&rules->t==1)for(i=0;i<rules->nkid&&g_v2_count<V2_RULES_MAX;i++){JV*r=rules->kids[i];JV*kind=jget(r,"kind");
  if(!kind||strcmp(jstr(kind),"ProcessCmdline"))continue;
  {RULE2*d=&g_v2[g_v2_count];JV*ps=jget(r,"patterns");JV*t;
   t=jget(r,"id");if(t){strncpy(d->id,jstr(t),63);d->id[63]=0;}
   t=jget(r,"behavior");if(t){strncpy(d->behavior,jstr(t),95);d->behavior[95]=0;}
   t=jget(r,"level");if(t){strncpy(d->level,jstr(t),15);d->level[15]=0;}
   t=jget(r,"score");d->score=(t&&(t->t==3||t->t==4))?(int)t->n:0;
   if(ps&&ps->t==1){int j;for(j=0;j<ps->nkid&&d->npat<V2_PAT_MAX;j++){JV*po=ps->kids[j];V2PAT*dp=&d->pats[d->npat];JV*tv;
    tv=jget(po,"match");if(tv){strncpy(dp->match,jstr(tv),127);dp->match[127]=0;}
    tv=jget(po,"context");if(tv){strncpy(dp->context,jstr(tv),127);dp->context[127]=0;}
    tv=jget(po,"type");if(tv){strncpy(dp->type,jstr(tv),31);dp->type[31]=0;}
    tv=jget(po,"mitre");if(tv){strncpy(dp->mitre,jstr(tv),15);dp->mitre[15]=0;}
    tv=jget(po,"note");if(tv){strncpy(dp->note,jstr(tv),159);dp->note[159]=0;}
    d->npat++;}}
   g_v2_count++;}}
 combo=jget(root,"combo");
 if(combo&&combo->t==0){JV*t;
  t=jget(combo,"combo_threshold");if(t)g_combo_th=(int)t->n;
  t=jget(combo,"combo_min_types");if(t)g_combo_types=(int)t->n;
  t=jget(combo,"suspect_threshold");if(t)g_susp_th=(int)t->n;
  t=jget(combo,"suspect_min_types");if(t)g_susp_types=(int)t->n;
  t=jget(combo,"module_load_score");if(t)g_mod_score=(int)t->n;
  t=jget(combo,"window_seconds");if(t)g_window_ms=((int)t->n)*1000;
  t=jget(combo,"combo_rule");if(t){strncpy(g_combo_rule,jstr(t),63);g_combo_rule[63]=0;}
  t=jget(combo,"combo_behavior");if(t){strncpy(g_combo_behavior,jstr(t),95);g_combo_behavior[95]=0;}
  t=jget(combo,"suspect_rule");if(t){strncpy(g_susp_rule,jstr(t),63);g_susp_rule[63]=0;}
  t=jget(combo,"suspect_behavior");if(t){strncpy(g_susp_behavior,jstr(t),95);g_susp_behavior[95]=0;}}
}
static RULE2*v2_match(const char*up,RULE2**rr,V2PAT**pp){int i,j;
 for(i=0;i<g_v2_count;i++){RULE2*r=&g_v2[i];for(j=0;j<r->npat;j++){V2PAT*p=&r->pats[j];
  if(strstr(up,p->match)&&(!p->context[0]||strstr(up,p->context))){*rr=r;*pp=p;return r;}}}
 return NULL;}
typedef struct{DWORD pid;ULONGLONG tick;int ntypes;char types[8][32];int sum;int combo_done;int susp_done;}CBST;
static CBST g_cb[V2_CB_MAX];static int g_cb_n=0;
static void cb_purge(ULONGLONG now){int i;for(i=0;i<g_cb_n;i++)if(now-g_cb[i].tick>(ULONGLONG)g_window_ms){g_cb[i]=g_cb[g_cb_n-1];g_cb_n--;i--;}}
static CBST*cb_accum(DWORD pid,const char*type,int score,ULONGLONG now){int i;CBST*e=NULL;
 cb_purge(now);
 for(i=0;i<g_cb_n;i++)if(g_cb[i].pid==pid){e=&g_cb[i];break;}
 if(!e&&g_cb_n<V2_CB_MAX){e=&g_cb[g_cb_n++];e->pid=pid;e->tick=now;}
 if(!e)return NULL;
 e->tick=now;
 for(i=0;i<e->ntypes;i++)if(!strcmp(e->types[i],type))return e;
 if(e->ntypes<8){strncpy(e->types[e->ntypes],type,31);e->types[e->ntypes][31]=0;e->ntypes++;e->sum+=score;}
 return e;}
static void alert2(DWORD pid,const char*rid,const char*beh,const char*family,const WCHAR*module,const char*detail,int score,const char*action)
{char msg[4096],esc[2048];DWORD n,i=0,j=0;WCHAR c;
 if(g_selftest){fwprintf(stderr,L"[SelfTest-ALERT] rule=%S pid=%lu score=%d action=%S detail=%S\n",rid,(unsigned long)pid,score,action,detail);return;}
 if(g_pipe_handle==INVALID_HANDLE_VALUE)pipe_fast();
 while(module[i]&&j+6<sizeof(esc)){c=module[i++];if(c==L'\\'||c==L'"'){esc[j++]='\\';esc[j++]=(char)c;}else if(c<0x20||c>0x7e){_snprintf(esc+j,7,"\\u%04x",(unsigned)c);j+=6;}else esc[j++]=(char)c;}
 esc[j]=0;
 _snprintf(msg,sizeof(msg),"{\"pid\":%lu,\"rule\":\"%s\",\"behavior\":\"%s\",\"family\":\"%s\",\"module\":\"%s\",\"detail\":\"%s\",\"score\":%d,\"action\":\"%s\"}\n",
  (unsigned long)pid,rid,beh,family,esc,detail,score,action);
 deliver(msg);}
static void combo_eval(DWORD pid,const WCHAR*module,ULONGLONG now){int i;CBST*e=NULL;
 for(i=0;i<g_cb_n;i++)if(g_cb[i].pid==pid){e=&g_cb[i];break;}
 if(!e)return;
 if(!e->combo_done&&e->ntypes>=g_combo_types&&e->sum>=g_combo_th){e->combo_done=1;
  alert2(pid,g_combo_rule,g_combo_behavior,"Combo",module,"behavior-chain combo threshold",e->sum,"terminate");return;}
 if(!e->susp_done&&e->ntypes>=g_susp_types&&e->sum>=g_susp_th){e->susp_done=1;
  alert2(pid,g_susp_rule,g_susp_behavior,"Combo",module,"behavior-chain suspect threshold",e->sum,"report");}}
/* ===== shared v2 decision core: called by ETW v2_proc_start AND WMI source =====
   Verbatim body moved from v2_proc_start (lines unchanged), plus:
   - one g_decide_lock (two event-source threads now feed the same state)
   - 3s per-pid dedup ring so ETW + WMI never double-decide one process */
static CRITICAL_SECTION g_decide_lock;
static struct {DWORD pid;ULONGLONG tick;}g_dedup[128];static int g_dedup_i=0;static DWORD g_diag_dup=0;
static int v2_recent(DWORD pid){int i;ULONGLONG now=(ULONGLONG)GetTickCount();int seen=0;
 for(i=0;i<128;i++)if(g_dedup[i].pid==pid&&now-g_dedup[i].tick<3000){seen=1;break;}
 if(!seen){g_dedup[g_dedup_i].pid=pid;g_dedup[g_dedup_i].tick=now;g_dedup_i=(g_dedup_i+1)&127;}
 return seen;}
static void v2_decide(DWORD pid,char*up,int upcap,const char*img){
 WCHAR host[MAX_PATH];char key[40];int i,have_host,hit_rule=-1;V2PAT*pp=NULL;
 EnterCriticalSection(&g_decide_lock);
 if(pid==g_parent||pid==GetCurrentProcessId()){LeaveCriticalSection(&g_decide_lock);return;}
 if(v2_recent(pid)){g_diag_dup++;LeaveCriticalSection(&g_decide_lock);return;}
 if(!up[0]&&!peb_cmdline(pid,up,upcap)&&img[0]){strncpy(up,img,upcap-1);up[upcap-1]=0;}
 if(!up[0]){g_diag_cmdfail++;diag("CMDFAIL pid=%lu",(unsigned long)pid);LeaveCriticalSection(&g_decide_lock);return;}
 have_host=process_path(pid,host,MAX_PATH);
 if(!have_host){lstrcpynW(host,L"<unknown>",MAX_PATH);g_diag_drop++;}
 if(have_host&&exempt(host)){LeaveCriticalSection(&g_decide_lock);return;}
 make_key(host,key,sizeof(key));if(g_diag_proc<=30)diag("PROC pid=%lu cmd=[%.140s]",(unsigned long)pid,up);
 for(i=0;i<g_v2_count;i++)if(g_v2[i].level[0]=='m'&&strstr(up,"")){}
 for(i=0;i<g_v2_count&&hit_rule<0;i++){RULE2*r2=&g_v2[i];int j;
  for(j=0;j<r2->npat;j++){V2PAT*p=&r2->pats[j];
   if(strstr(up,p->match)&&(!p->context[0]||strstr(up,p->context))){hit_rule=i;pp=p;break;}}}
 if(hit_rule>=0){RULE2*r2=&g_v2[hit_rule];diag("HIT pid=%lu rule=%s match=%s score=%d pid_ok=%d host_ok=%d",(unsigned long)pid,r2->id,pp->match,r2->score,pid>0,have_host);
  if(r2->level[0]=='m'){
   if(pid&&have_host){alert2(pid,r2->id,r2->behavior,r2->level,host,pp->note,r2->score,"terminate");
    pend_signal(key,host,pid,r2->id,r2->behavior,pp->type,pp->note,r2->score,up,0);LeaveCriticalSection(&g_decide_lock);return;}
   pend_signal(key,host,pid,r2->id,r2->behavior,pp->type,pp->note,r2->score,up,1);LeaveCriticalSection(&g_decide_lock);return;}
  {ULONGLONG now=GetTickCount();cb_accum(pid,pp->type,r2->score,now);combo_eval(pid,host,now);
   pend_signal(key,host,pid,r2->id,r2->behavior,pp->type,pp->note,r2->score,up,1);LeaveCriticalSection(&g_decide_lock);return;}}
 pend_touch(key,pid,"ProcessOther",0);
 LeaveCriticalSection(&g_decide_lock);
 return;}
static void v2_proc_start(EVENT_RECORD_L*r){ULONG bytes=0,rc;TRACE_EVENT_INFO_L*info;DWORD pid=r->EventHeader.ProcessId;WCHAR host[MAX_PATH];
 char up[2048],img[MAX_PATH*2],key[40];int i,j,hit_rule=-1,have_host;V2PAT*pp=NULL;RULE2*rr=NULL;DWORD ppid=0;
 if(pid==g_parent||pid==GetCurrentProcessId())return;
 rc=pTdhInfo(r,0,NULL,NULL,&bytes);
 if(rc!=122||bytes<sizeof(TRACE_EVENT_INFO_L)||bytes>65536)return;
 info=(TRACE_EVENT_INFO_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);if(!info)return;
 rc=pTdhInfo(r,0,NULL,info,&bytes);
 if(rc){HeapFree(GetProcessHeap(),0,info);return;}
 up[0]=0;
  for(i=0;i<info->TopLevelPropertyCount&&i<info->PropertyCount;i++){ULONG off=info->EventPropertyInfoArray[i].NameOffset;WCHAR*name;PROPERTY_DATA_DESCRIPTOR_L d;BYTE val[4096];ULONG sz;int is_cmd,is_img,is_par;
   if(off>=bytes)continue;name=(WCHAR*)((BYTE*)info+off);
   is_cmd=has(name,L"command");is_img=has(name,L"image")||has(name,L"file");is_par=has(name,L"parent");
   if(!is_cmd&&!is_img&&!is_par)continue;
   ZeroMemory(&d,sizeof(d));d.PropertyName=(ULONGLONG)(ULONG_PTR)name;d.ArrayIndex=0xffffffff;sz=0;
   if(pTdhSize(r,0,NULL,1,&d,&sz)!=0||sz<2||sz>sizeof(val)||(sz&1))continue;
   if(pTdhGet(r,0,NULL,1,&d,sz,val)!=0)continue;
   if(is_par){if(sz>=4){DWORD v=0;memcpy(&v,val,4);if(v)ppid=v;}continue;}
   {DWORD cch=sz/2;int t=0;WCHAR*w=(WCHAR*)val;char tmp[2048];
    while(t<(int)cch&&w[t]&&t+1<(int)sizeof(tmp)){unsigned wc=(unsigned)w[t++];
     tmp[t-1]=(wc>=128)?'?':(char)(wc>='a'&&wc<='z'?wc-32:wc);}
    tmp[t]=0;
    if(is_cmd){strncpy(up,tmp,sizeof(up)-1);up[sizeof(up)-1]=0;break;}
    if(is_img&&!img[0]){strncpy(img,tmp,sizeof(img)-1);img[sizeof(img)-1]=0;}}
  }
 HeapFree(GetProcessHeap(),0,info);
 v2_decide(pid,up,(int)sizeof(up),img);
 return;}
/* ===== WMI kernel real-time event source (additive; ETW pump untouched) =====
   Empirical IWbemServices vtable map on this machine (raw COM, TCC, 2026-11-15):
   - slot 20: 6-arg + real-BSTR query call works (data queries deliver objects;
     official ExecNotificationQuery ABI position). Crash-free.
   - slot 18: real-BSTR call -> 0x800706f4 stub-data reject. Crash-free.
   - slots 14/15/21/23/24: mismatched call forms CRASH -> never called here.
   Route per approved plan: try PUSH (Win32_ProcessStartTrace, spawn-child
   self-test); if no event arrives within the test window, fall back to the
   agreed 300ms PULL snapshot diff. ETW keeps running in parallel either way;
   on healthy machines PUSH delivers at slot 20 directly. */
typedef struct { USHORT vt,w1,w2,w3; union { long lVal; void* pVal; } u; } WVAR;
typedef struct WMLVt WMLVt;struct WMLVt{ULONG(WINAPI*qi)(void*,const GUID*,void**);ULONG(WINAPI*ar)(void*);ULONG(WINAPI*rl)(void*);ULONG(WINAPI*conn)(void*,const WCHAR*,const WCHAR*,const WCHAR*,const WCHAR*,unsigned long,const WCHAR*,void*,void**);};
typedef struct{WMLVt*v;}WMLOBJ;
typedef struct WMLEVt WMLEVt;struct WMLEVt{ULONG(WINAPI*qi)(void*,const GUID*,void**);ULONG(WINAPI*ar)(void*);ULONG(WINAPI*rl)(void*);void*rst;ULONG(WINAPI*next)(void*,unsigned long,unsigned long,void**,unsigned long*);};
typedef struct{WMLEVt*v;}WMLENUM;
typedef struct WMOVt WMOVt;struct WMOVt{ULONG(WINAPI*qi)(void*,const GUID*,void**);ULONG(WINAPI*ar)(void*);ULONG(WINAPI*rl)(void*);void*gqs;ULONG(WINAPI*get)(void*,const WCHAR*,long,WVAR*,long*,long*);};
typedef struct{WMOVt*v;}WMOBJ;
static const GUID WMI_CLSID_LOC={0x4590f811,0x1d3a,0x11d0,{0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
static const GUID WMI_IID_LOC={0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
typedef long (WINAPI*PFN_WCOINIT)(void*,unsigned long);
typedef long (WINAPI*PFN_WCOSEC)(void*,long,void*,void*,unsigned long,unsigned long,void*,unsigned long,void*,void*);
typedef long (WINAPI*PFN_WCOCREATE)(const GUID*,void*,unsigned long,const GUID*,void**);
typedef void* (WINAPI*PFN_WALLOC)(const WCHAR*);
typedef void (WINAPI*PFN_WFREE)(void*);
typedef long (WINAPI*PFN_WQL6)(void*,const WCHAR*,const WCHAR*,long,void*,void**);
#define WMI_EXECQ_SLOT 20
#define WMI_EXECQ_SLOT_ALT 18
#define WMI_PULL_MS 300
#define WMI_SNAP_MAX 1024
static void wmi_name2img(const WCHAR*n,char*out,int cap){int i=0,j=0;
 while(n&&n[i]&&j+1<cap){unsigned wc=(unsigned)n[i++];out[j++]=(wc>=128)?'?':(char)(wc>='a'&&wc<='z'?wc-32:wc);}
 out[j]=0;}
static void wmi_spawn_child(void){STARTUPINFOW si;PROCESS_INFORMATION pi;WCHAR cmd[64];
 ZeroMemory(&si,sizeof(si));si.cb=sizeof(si);ZeroMemory(&pi,sizeof(pi));
 lstrcpynW(cmd,L"cmd.exe /c ver",64);
 if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}}
static void wmi_decide_evt(void*obj){WVAR v;long ty=0,fl=0;long pidv=-1;WCHAR name[260];char up[2048],imgc[MAX_PATH*2];
 name[0]=0;ZeroMemory(&v,sizeof(v));
 if(((WMOBJ*)obj)->v->get(obj,L"ProcessID",0,&v,&ty,&fl)>=0&&v.vt==3)pidv=v.u.lVal;
 ZeroMemory(&v,sizeof(v));
 if(((WMOBJ*)obj)->v->get(obj,L"ProcessName",0,&v,&ty,&fl)>=0&&v.vt==8&&v.u.pVal){lstrcpynW(name,(WCHAR*)v.u.pVal,260);}
 ((WMOBJ*)obj)->v->rl(obj);
 if(pidv<=4||pidv==g_parent||(DWORD)pidv==GetCurrentProcessId())return;
 wmi_name2img(name,imgc,(int)sizeof(imgc));ZeroMemory(up,sizeof(up));
 InterlockedIncrement(&g_diag_proc);g_diag_events++;
 v2_decide((DWORD)pidv,up,(int)sizeof(up),imgc);}
static DWORD WINAPI wmi_worker(LPVOID x){
 void *loc=NULL,*svc=NULL,*enm=NULL,*q=NULL;long hr;int push_ok=0;
 HMODULE o,a;PFN_WCOINIT ci;PFN_WCOSEC cs;PFN_WCOCREATE cc;PFN_WALLOC sa;PFN_WFREE sf;
 void** vt;PFN_WQL6 f6;
 (void)x;
 o=LoadLibraryW(L"ole32.dll");a=LoadLibraryW(L"oleaut32.dll");
 if(!o||!a){diag("WMI ole32/oleaut load fail");return 0;}
 ci=(PFN_WCOINIT)GetProcAddress(o,"CoInitializeEx");cs=(PFN_WCOSEC)GetProcAddress(o,"CoInitializeSecurity");
 cc=(PFN_WCOCREATE)GetProcAddress(o,"CoCreateInstance");
 sa=(PFN_WALLOC)GetProcAddress(a,"SysAllocString");sf=(PFN_WFREE)GetProcAddress(a,"SysFreeString");
 if(!ci||!cs||!cc||!sa||!sf){diag("WMI COM entry missing");return 0;}
 hr=ci(NULL,2);if(hr<0){diag("WMI CoInit hr=0x%08lx",(unsigned long)hr);return 0;}
 hr=cs(NULL,-1,NULL,NULL,0,3,NULL,0,NULL,NULL);
 diag("WMI CoInitializeSecurity hr=0x%08lx",(unsigned long)hr);
 hr=cc(&WMI_CLSID_LOC,NULL,1,&WMI_IID_LOC,&loc);
 if(hr<0||!loc){diag("WMI CoCreate hr=0x%08lx",(unsigned long)hr);return 0;}
 {int tries=0;hr=-1;
  for(tries=0;tries<10&&g_running;tries++){
   hr=((WMLOBJ*)loc)->v->conn(loc,L"ROOT\\CIMV2",NULL,NULL,NULL,0,NULL,NULL,&svc);
   if(hr>=0&&svc)break;
   Sleep(1000);}
  if(hr<0||!svc){diag("WMI ConnectServer hr=0x%08lx (10 tries)",(unsigned long)hr);return 0;}}
 diag("WMI ConnectServer OK");
 vt=*(void***)svc;
 /* PUSH attempts: crash-free slots only, real BSTRs. */
 {int slotlist[2];int ns=0,si_,got=0,k;
  slotlist[ns++]=WMI_EXECQ_SLOT;slotlist[ns++]=WMI_EXECQ_SLOT_ALT;
  for(si_=0;si_<ns&&!push_ok&&g_running;si_++){
   f6=(PFN_WQL6)vt[slotlist[si_]];
   {void* bl=sa(L"WQL"),*bq=sa(L"SELECT * FROM Win32_ProcessStartTrace");
    hr=f6(svc,bl,bq,0,NULL,&enm);sf(bl);sf(bq);}
   diag("WMI ExecNotificationQuery slot=%d hr=0x%08lx enm=%d",slotlist[si_],(unsigned long)hr,enm?1:0);
   if(hr>=0&&enm){
    got=0;
    wmi_spawn_child();
    for(k=0;k<3&&!got;k++){void* obj=NULL;unsigned long ret=0;
     hr=((WMLENUM*)enm)->v->next(enm,1000,1,&obj,&ret);
     if(hr>=0&&ret&&obj){got=1;((WMOBJ*)obj)->v->rl(obj);}}
    if(got){push_ok=1;diag("WMI push self-test slot=%d OK -> PUSH mode",slotlist[si_]);}
    else{diag("WMI push self-test slot=%d: no event in 3s",slotlist[si_]);
     ((WMLENUM*)enm)->v->rl(enm);enm=NULL;}}}
 }
 if(push_ok){
  diag("WMI mode=PUSH");
  while(g_running&&enm){
   void* obj=NULL;unsigned long ret=0;
   hr=((WMLENUM*)enm)->v->next(enm,1000,1,&obj,&ret);
   if(hr<0){diag("WMI push Next hr=0x%08lx -> drop to PULL",(unsigned long)hr);
    ((WMLENUM*)enm)->v->rl(enm);enm=NULL;push_ok=0;break;}
   if(ret&&obj)wmi_decide_evt(obj);}}
 if(!push_ok){
  static DWORD prev[WMI_SNAP_MAX];static int prev_n=0;
  static DWORD cur[WMI_SNAP_MAX];static void* warr[100];
  int first=1;
  diag("WMI mode=PULL interval=%dms",WMI_PULL_MS);
  while(g_running){
   int cur_n=0;
   f6=(PFN_WQL6)vt[WMI_EXECQ_SLOT];
   {void* bl=sa(L"WQL"),*bq=sa(L"SELECT ProcessId FROM Win32_Process");
    hr=f6(svc,bl,bq,0,NULL,&q);sf(bl);sf(bq);}
   if(hr>=0&&q){
    for(;;){unsigned long ret=0;int z;
     hr=((WMLENUM*)q)->v->next(q,1000,100,warr,&ret);
     if(hr<0||!ret)break;
     for(z=0;z<(int)ret&&cur_n<WMI_SNAP_MAX;z++){WVAR v;long ty=0,fl=0;long pidv=-1;
      ZeroMemory(&v,sizeof(v));
      if(((WMOBJ*)warr[z])->v->get(warr[z],L"ProcessId",0,&v,&ty,&fl)>=0&&v.vt==3)pidv=v.u.lVal;
      ((WMOBJ*)warr[z])->v->rl(warr[z]);
      if(pidv>4)cur[cur_n++]=(DWORD)pidv;}
     if(ret<100)break;}
    ((WMLENUM*)q)->v->rl(q);q=NULL;
    {int i2,j2;
     if(!first){
      for(i2=0;i2<cur_n;i2++){int found=0;
       for(j2=0;j2<prev_n;j2++)if(prev[j2]==cur[i2]){found=1;break;}
       if(!found&&cur[i2]!=g_parent&&cur[i2]!=GetCurrentProcessId()){
        char up[2048],imgc[MAX_PATH*2];imgc[0]=0;up[0]=0;
        InterlockedIncrement(&g_diag_proc);g_diag_events++;
        v2_decide(cur[i2],up,(int)sizeof(up),imgc);}}}
     memcpy(prev,cur,(size_t)cur_n*sizeof(DWORD));prev_n=cur_n;first=0;}
   }else{diag("WMI pull ExecQuery hr=0x%08lx",(unsigned long)hr);}
   {int sl;for(sl=0;sl<3&&g_running;sl++)Sleep(WMI_PULL_MS/3);}}}
 diag("WMI worker exiting push=%d",push_ok);
 return 0;}
/* ===== end WMI source ===== */
static int v2_selftest(void){
 static const char*ben[]={"IPCONFIG /ALL","NET STOP SPOOLER","NET STOP WUAUSERV","TASKKILL /PID 3601 /F","TASKKILL /IM NOTEPAD.EXE","REG ADD HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN /V TEST /D C:\\X.EXE /F","POWERSHELL -COMMAND GET-PROCESS","POWERSHELL GET-PROCESS","CERTUTIL -HASHFILE C:\\A.EXE SHA256","CERTUTIL -ENUMSTORE","MSHTA C:\\LOCAL\\TEST.HTA","CMD /C DIR","SCHTASKS /QUERY /FO LIST","WMIC CPU GET NAME","DISM /ONLINE /GET-FEATURES","ROBOCOPY C:\\A C:\\B /E","VSSADMIN LIST SHADOWS","BCDEDIT /ENUM","NET USER ADMINISTRATOR","SC QUERY WINDEFEND","NET START","NETSH INTERFACE SHOW INTERFACE","RUNDLL32 SHELL32.DLL,CONTROL_RUNDLL","CIPHER /S:C:\\USERS","SC CONFIG SPOOLER START= AUTO"};
 static const char*mal[]={"NET STOP WINDEFEND","SC STOP WINDEFEND","SC CONFIG WINDEFEND START= DISABLED","TASKKILL /IM MSMPENG /F","TASKKILL /IM HIPSTRAY /F","FLTMC UNLOAD","VSSADMIN DELETE SHADOWS /ALL /QUIET","BCDEDIT /SET RECOVERYENABLED NO","WBADMIN DELETE CATALOG -QUIET","DISKSHADOW","ADD-MPPREFERENCE -EXCLUSIONPATH C:\\X","WEVTUTIL CL SECURITY","MSHTA VBSCRIPT:MSGBOX"};
 static const char*sus[]={"NET USER BACKDOOR P@SS /ADD","AUDITPOL /SET /SUCCESS:DISABLE","RUNDLL32 C:\\TEMP\\A.DLL,Entry","REG ADD HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON /V USERINIT","WMIC PROCESS CALL CREATE CMD","POWERSHELL -ENC  SQBFAFgA","POWERSHELL -ENCODEDCOMMAND SQBF","POWERSHELL -W HIDDEN -NOP","CERTUTIL -URLCACHE -F HTTP://X/A.EXE","CERTUTIL -DECODE A.TXT B.EXE","BITSADMIN /TRANSFER J HTTP://X/A.EXE C:\\A.EXE","MSHTA HTTP://X/A.HTA","REGSVR32 /I:HTTP://X SCROBJ.DLL","RUNDLL32 JAVASCRIPT:PAYLOAD","SCHTASKS /CREATE /RU SYSTEM /TN T /TR X","POWERSHELL -NOPROFILE -EXECUTIONPOLICY BYPASS"};
 int i,ok=1,nb,nm,ns,nbhit=0,nmhit=0,nshit=0;
 nb=(int)(sizeof(ben)/sizeof(ben[0]));nm=(int)(sizeof(mal)/sizeof(mal[0]));ns=(int)(sizeof(sus)/sizeof(sus[0]));
 fwprintf(stderr,L"[SelfTest] rules loaded=%d path=%S\n",g_v2_count,g_rules_path);
 for(i=0;i<nb;i++){V2PAT*pp=NULL;RULE2*rr=NULL;
  if(v2_match(ben[i],&rr,&pp)&&rr->level[0]=='m'){nbhit++;ok=0;fwprintf(stderr,L"[SelfTest] FP: %S -> %S / %S\n",ben[i],rr->id,pp->note);}}
 for(i=0;i<nm;i++){V2PAT*pp=NULL;RULE2*rr=NULL;
  if(!v2_match(mal[i],&rr,&pp)||rr->level[0]!='m'){nmhit++;ok=0;fwprintf(stderr,L"[SelfTest] MISS: %S\n",mal[i]);}}
 for(i=0;i<ns;i++){V2PAT*pp=NULL;RULE2*rr=NULL;
  if(!v2_match(sus[i],&rr,&pp)||rr->level[0]!='s'){nshit++;ok=0;fwprintf(stderr,L"[SelfTest] SUS-MISS: %S\n",sus[i]);}}
 {DWORD fake=0xBEEF;ULONGLONG now=GetTickCount();g_selftest=1;g_cb_n=0;
  cb_accum(fake,"USERMODULELOAD",g_mod_score,now);
  cb_accum(fake,"CmdExec",30,now);
  cb_accum(fake,"SecSetting",10,now+1000);
  combo_eval(fake,L"C:\\TEST\\VERSION.DLL",now+1000);
  {int fired=0;int q;for(q=0;q<g_cb_n;q++)if(g_cb[q].pid==fake&&g_cb[q].combo_done)fired=1;
   if(!fired){ok=0;fwprintf(stderr,L"[SelfTest] COMBO MISS (60/3 chain)\n");}}
  g_cb_n=0;g_selftest=0;}
 fwprintf(stderr,L"[SelfTest] benign=%d fp=%d malicious=%d miss=%d suspect=%d miss=%d => %S\n",nb,nbhit,nm,nmhit,ns,nshit,ok?"PASS":"FAIL");
 return ok?0:1;}

/* ===== end v2 ===== */

static void WINAPI on_record(EVENT_RECORD_L*r){ULONG bytes=0,rc;TRACE_EVENT_INFO_L*info;WCHAR module[MAX_PATH],host[MAX_PATH];DWORD pid;LONG i;ULONGLONG now;int hit=0;if(!r)return;g_diag_events++;diag_report();if(g_diag_events<=30)diag("EVT #%lu id=%lu pid=%lu",(unsigned long)g_diag_events,(unsigned long)r->EventHeader.EventDescriptor.Id,(unsigned long)r->EventHeader.ProcessId);if(r->EventHeader.EventDescriptor.Id==1||r->EventHeader.EventDescriptor.Id==3){g_diag_proc++;v2_proc_start(r);return;}if(r->EventHeader.EventDescriptor.Id!=IMAGE_LOAD_EVENT)return;pid=r->EventHeader.ProcessId;if(!pid||pid==g_parent||pid==GetCurrentProcessId())return;rc=pTdhInfo(r,0,NULL,NULL,&bytes);if(rc!=122||bytes<sizeof(TRACE_EVENT_INFO_L)||bytes>65536){InterlockedIncrement(&g_bad);return;}info=(TRACE_EVENT_INFO_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);if(!info)return;rc=pTdhInfo(r,0,NULL,info,&bytes);if(rc||!get_module(r,info,bytes,module,MAX_PATH)){HeapFree(GetProcessHeap(),0,info);InterlockedIncrement(&g_bad);return;}HeapFree(GetProcessHeap(),0,info);if(!sensitive_dll(module)||!user_path(module)||exempt(module))return;{ULONGLONG cnow=GetTickCount();cb_accum(pid,"USERMODULELOAD",g_mod_score,cnow);combo_eval(pid,module,cnow);}{char k[40];int hh=process_path(pid,host,MAX_PATH);if(hh){make_key(host,k,sizeof(k));pend_touch(k,pid,"USERMODULELOAD",g_mod_score);}if(!hh||!risky_host(host)||exempt(host))return;}now=(ULONGLONG)GetTickCount();EnterCriticalSection(&g_lock);for(i=0;i<g_hit_count;i++)if(g_hits[i].pid==pid&&now-g_hits[i].tick<30000&&_wcsicmp(g_hits[i].module,module)!=0){hit=1;break;}if(!hit&&g_hit_count<MAX_HITS){g_hits[g_hit_count].pid=pid;g_hits[g_hit_count].tick=now;lstrcpynW(g_hits[g_hit_count].module,module,MAX_PATH);g_hit_count++;}for(i=0;i<g_hit_count;i++)if(now-g_hits[i].tick>30000){g_hits[i]=g_hits[--g_hit_count];i--;}LeaveCriticalSection(&g_lock);if(hit)send_alert(pid,module);}
static DWORD WINAPI parent_watch(LPVOID x){HANDLE h;(void)x;h=OpenProcess(SYNCHRONIZE,FALSE,g_parent);if(h){WaitForSingleObject(h,INFINITE);CloseHandle(h);}InterlockedExchange(&g_running,0);if(g_pipe_handle!=INVALID_HANDLE_VALUE)CloseHandle(g_pipe_handle);diag("PARENT GONE -> agent exits; foreign session left intact");if(g_owns_session&&pControl)pControl(0,g_session,g_props,EVENT_TRACE_CONTROL_STOP);ExitProcess(0);return 0;}
static int load_api(void){HMODULE a=LoadLibraryW(L"advapi32.dll"),s=LoadLibraryW(L"sechost.dll"),t=LoadLibraryW(L"tdh.dll"),k=GetModuleHandleW(L"kernel32.dll");if(!a||!t||!k)return 0;pStart=(PFN_START)GetProcAddress(a,"StartTraceW");pControl=(PFN_CONTROL)GetProcAddress(a,"ControlTraceW");pOpen=(PFN_OPEN)GetProcAddress(a,"OpenTraceW");pProcess=(PFN_PROCESS)GetProcAddress(a,"ProcessTrace");if(!pProcess&&s)pProcess=(PFN_PROCESS)GetProcAddress(s,"ProcessTrace");pClose=(PFN_CLOSE)GetProcAddress(a,"CloseTrace");pEnable=(PFN_ENABLE)GetProcAddress(a,"EnableTraceEx2");pDisable=(PFN_DISABLE)GetProcAddress(a,"EnableTraceEx");pTdhInfo=(PFN_TDH_INFO)GetProcAddress(t,"TdhGetEventInformation");pTdhSize=(PFN_TDH_SIZE)GetProcAddress(t,"TdhGetPropertySize");pTdhGet=(PFN_TDH_GET)GetProcAddress(t,"TdhGetProperty");pQueryImage=(PFN_QUERY_IMAGE)GetProcAddress(k,"QueryFullProcessImageNameW");return pStart&&pControl&&pOpen&&pProcess&&pClose&&pTdhInfo&&pTdhSize&&pTdhGet&&pQueryImage;}
int wmain(int argc,WCHAR**argv){ULONG sz=(ULONG)(sizeof(EVENT_TRACE_PROPERTIES_L)+512),rc;EVENT_TRACE_PROPERTIES_L*p;EVENT_TRACE_LOGFILE_L*pl=(EVENT_TRACE_LOGFILE_L*)g_logbuf;TRACEHANDLE session=0,trace;WCHAR env[MAX_PATH];WCHAR wrules[MAX_PATH];DWORD wrn;InitializeCriticalSection(&g_lock);InitializeCriticalSection(&g_diag_lock);InitializeCriticalSection(&g_decide_lock);diag_open();diag("BOOT pid=%lu session=[%S] log=%s",(unsigned long)GetCurrentProcessId(),g_session,g_diagf?"open":"FAILED");wrn=GetModuleFileNameW(NULL,wrules,MAX_PATH);if(wrn&&wrn<MAX_PATH){WCHAR*sl=wcsrchr(wrules,L'\\');if(sl)*(sl+1)=0;wcscat(wrules,L"agent_rules.json");wcstombs(g_rules_path,wrules,MAX_PATH-1);}if(GetEnvironmentVariableW(L"SEVEN_AGENT_RULES",env,MAX_PATH)){char vpath[MAX_PATH];wcstombs(vpath,env,MAX_PATH-1);strncpy(g_rules_path,vpath,MAX_PATH-1);g_rules_path[MAX_PATH-1]=0;}if(argc>=2&&!_wcsicmp(argv[1],L"--SelfTest")){v2_load();return v2_selftest();}if(argc>=2&&(!_wcsicmp(argv[1],L"--Agent")||!_wcsicmp(argv[1],L"--test"))){v2_load();fwprintf(stderr,L"[SevenAgent][DIAG] v2 rules=%d path=%S\n",g_v2_count,g_rules_path);}
if(argc>=2&&!_wcsicmp(argv[1],L"--LoopbackTest")){char k[40],tm[768];int ok;make_key(L"C:\\TEST\\SILVERFOX_SIM.EXE",k,sizeof(k));_snprintf(tm,sizeof(tm)-1,"{\"pid\":0,\"rule\":\"Agent.Cmdline.Malicious\",\"behavior\":\"Loopback.Test\",\"family\":\"PendingChain\",\"module\":\"loopback\",\"detail\":\"selftest\",\"score\":0,\"action\":\"observe\",\"pid_unknown\":1,\"chain_key\":\"%s\",\"linked\":1,\"cmd\":\"\"}\n",k);tm[sizeof(tm)-1]=0;deliver(tm);ok=g_alert_file_ok;fwprintf(stderr,L"[SevenAgent][LocalLogTest] %S\n",ok?"OK":"FAIL");return ok?0:21;}if(argc<2||(_wcsicmp(argv[1],L"--Agent")&&_wcsicmp(argv[1],L"--test"))){fwprintf(stderr,L"Usage: SevenAgent.exe --Agent | --test\n");return 64;}if(GetEnvironmentVariableW(L"SEVEN_PARENT_PID",env,MAX_PATH))g_parent=wcstoul(env,NULL,10);if(!g_parent)g_parent=find_controller();if(!g_parent&&argc>=2&&!_wcsicmp(argv[1],L"--Agent")){fwprintf(stderr,L"[SevenAgent] Waiting for SevenEndPoint.exe; retrying controller discovery.\n");for(;;){Sleep(2000);g_parent=find_controller();if(g_parent)break;}}if(!g_parent){g_parent=GetCurrentProcessId();diag("--test mode: standalone, no controller wait (parent=self)");fwprintf(stderr,L"[SevenAgent] --test standalone mode (no controller wait)\n");}if(!load_api()){fwprintf(stderr,L"[SevenAgent] ETW/TDH APIs unavailable.\n");return 11;}p=(EVENT_TRACE_PROPERTIES_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);if(!p)return 12;/* ===== official private-session route: never touches NT Kernel Logger ===== */
p->Wnode.BufferSize=sz;p->Wnode.Flags=WNODE_FLAG_TRACED_GUID;p->Wnode.ClientContext=1;
p->LogFileMode=EVENT_TRACE_REAL_TIME_MODE;
p->LogFileNameOffset=0;p->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES_L);
p->BufferSize=64;p->MinimumBuffers=2;p->MaximumBuffers=64;p->FlushTimer=1;
lstrcpynW((WCHAR*)((char*)p+p->LoggerNameOffset),g_session,(sz-p->LoggerNameOffset)/sizeof(WCHAR));
diag("ETW private-session properties ready mode=0x%lx gsession=[%S] wnodeGuid1=%08x",(unsigned long)p->LogFileMode,g_session,(unsigned)p->Wnode.Guid.Data1);
rc=pStart(&session,g_session,p);
diag("ETW StartTrace rc=%lu session=[%S] gsession-hex=%04x%04x%04x%04x",(unsigned long)rc,g_session,(unsigned)g_session[0],(unsigned)g_session[1],(unsigned)g_session[2],(unsigned)g_session[3]);
if(rc==ERROR_ALREADY_EXISTS){ULONG stp=pControl(0,g_session,p,EVENT_TRACE_CONTROL_STOP);
 diag("ETW own stale session -> STOP rc=%lu, restart",(unsigned long)stp);Sleep(200);
 rc=pStart(&session,g_session,p);diag("ETW StartTrace retry rc=%lu",(unsigned long)rc);}
if(rc){fwprintf(stderr,L"[SevenAgent] StartTrace failed: %lu\n",rc);return (int)rc;}
g_owns_session=1;g_session_handle=session;
diag("ETW owns=1 session=%llu",(unsigned long long)session);
if(pEnable){rc=pEnable(session,&KERNEL_PROCESS_GUID,EVENT_CONTROL_CODE_ENABLE_PROVIDER,4,WINEVENT_KEYWORD_PROCESS,0,0,NULL);
 diag("ETW EnableTraceEx2 rc=%lu provider=Kernel-Process keyword=PROCESS",(unsigned long)rc);
 if(rc){fwprintf(stderr,L"[SevenAgent] EnableTraceEx2 failed: %lu\n",rc);return (int)rc;}}
else{diag("ETW EnableTraceEx2 unavailable");fwprintf(stderr,L"[SevenAgent] EnableTraceEx2 unavailable\n");return 14;}
/* layout guard: must match official x64 ABI (size=480, EventCallback offset=456) */
if(sizeof(EVENT_TRACE_LOGFILE_L)!=480){
 diag("FATAL EVENT_TRACE_LOGFILE_L size=%u offCB=%u",(unsigned)sizeof(EVENT_TRACE_LOGFILE_L),
  (unsigned)((char*)&pl->EventCallback-(char*)pl));
 fwprintf(stderr,L"[SevenAgent] FATAL EVENT_TRACE_LOGFILE_L layout size=%u\n",(unsigned)sizeof(EVENT_TRACE_LOGFILE_L));
 return 15;}
diag("ETW layout ok size=%u offCB=%u",(unsigned)sizeof(EVENT_TRACE_LOGFILE_L),
 (unsigned)((char*)&pl->EventCallback-(char*)pl));
ZeroMemory(g_logbuf,sizeof(g_logbuf));pl->LoggerName=g_session;pl->ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD;pl->EventCallback=(PVOID)on_record;diag("ETW pre-open cb=%d pProcess=%d pOpen=%d",pl->EventCallback?1:0,pProcess?1:0,pOpen?1:0);trace=pOpen(pl);diag("ETW OpenTrace trace=%llu owns=%d",(unsigned long long)trace,g_owns_session);if(trace==(TRACEHANDLE)-1){diag("ETW OpenTrace FAILED");if(g_owns_session)pControl(0,g_session,p,EVENT_TRACE_CONTROL_STOP);return 13;}g_session_handle=session;g_props=p;pipe_fast();fwprintf(stderr,L"[SevenAgent][DELIVERY] pipe primary + TCP 47821 fallback + local agent_alerts.log\n");diag("DELIVERY pipe primary + TCP %d fallback + local file",AGENT_TCP_PORT);CreateThread(NULL,0,pipe_keeper,NULL,0,NULL);CreateThread(NULL,0,parent_watch,NULL,0,NULL);CreateThread(NULL,0,wmi_worker,NULL,0,NULL);diag("WMI event source thread started");fwprintf(stderr,L"[SevenAgent] ETW ready; controller PID=%lu owns_session=%d\n",g_parent,g_owns_session);fflush(stderr);g_trace=trace;
diag("ETW entering ProcessTrace: official callback-driven pump, no polling");rc=pProcess(&trace,1,NULL,NULL);diag("ETW ProcessTrace returned rc=%lu events=%lu proc=%lu alerts=%lu",(unsigned long)rc,(unsigned long)g_diag_events,(unsigned long)g_diag_proc,(unsigned long)g_diag_alert);pClose(trace);if(g_owns_session)pControl(0,g_session,p,EVENT_TRACE_CONTROL_STOP);HeapFree(GetProcessHeap(),0,p);DeleteCriticalSection(&g_lock);return 0;}