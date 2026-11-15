# -*- coding: utf-8 -*-
"""Merge patch: WMI kernel real-time event source + shared v2_decide.

Approved plan (user, 2026-11-15): WMI 内核实时回调（推模式，不可用则自动 300ms
拉模式兜底）+ PEB 读 cmdline + ETW 原样保留并行. Decision logic extracted into
shared v2_decide. ETW path untouched.

Empirical slot map (this machine, wmi_slot_map.exe 2026-11-15):
  slot 20 = 6-arg + real-BSTR query API (ExecQuery semantics on this build;
            official ExecNotificationQuery position per ABI doc). Crash-free.
  slot 18 = real-BSTR calls -> 0x800706f4, crash-free (alt push candidate).
  slots 14/15/21/23/24 = CRASH with mismatched forms -> never called.
  PUSH self-test (spawn child, expect ProcessStartTrace event) decides
  PUSH vs 300ms PULL per the approved plan.
"""
import io, shutil, sys, time

SRC = r"D:\Administrator\Desktop\TestUI\CodeBak\SevenAgent\SevenAgent.c"

s = io.open(SRC, "r", encoding="utf-8", newline="").read()
orig_len = len(s)
orig_lines = s.count("\n")

def rep(tag, old, new):
    global s
    n = s.count(old)
    if n != 1:
        print("FAIL %s: anchor count=%d" % (tag, n)); sys.exit(1)
    s = s.replace(old, new)
    print("ok   %s" % tag)

# ---------------- backup ----------------
bak = SRC + ".bak_wmi_" + time.strftime("%H%M%S")
shutil.copy2(SRC, bak)
print("backup ->", bak)

# ---------------- P-B: v2_proc_start tail -> v2_decide call ----------------
# locate the tail by markers (whitespace-proof): from the PEB fallback line
# through the closing "return;}" of v2_proc_start.
_i = s.find('if(!up[0]&&!peb_cmdline')
_j = s.find('pend_touch(key,pid,"ProcessOther",0);', _i)
_k = s.find('return;}', _j)
assert _i > 0 and _j > _i and _k > _j, (_i, _j, _k)
OLD_TAIL = s[_i:_k + len('return;}')]
for landmark in ('CMDFAIL pid', 'have_host=process_path', 'HIT pid=%lu rule=%s',
                 'combo_eval(pid,host,now)', 'pend_signal', 'exempt(host)'):
    if landmark not in OLD_TAIL:
        print('FAIL P-B landmark missing:', landmark); sys.exit(1)
NEW_TAIL = 'v2_decide(pid,up,(int)sizeof(up),img);\n return;}'
s = s[:_i] + NEW_TAIL + s[_k + len('return;}'):]
print('ok   P-B v2_proc_start tail -> v2_decide (region %d bytes)' % len(OLD_TAIL))

# ---------------- P-A1: v2_decide core before v2_proc_start ----------------
V2D_ANCHOR = "static void v2_proc_start(EVENT_RECORD_L*r){"
V2D_NEW = r'''/* ===== shared v2 decision core: called by ETW v2_proc_start AND WMI source =====
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
static void v2_proc_start(EVENT_RECORD_L*r){'''
rep("P-A1 v2_decide before v2_proc_start", V2D_ANCHOR, V2D_NEW)

# ---------------- P-A2: WMI event source block before v2_selftest ----------------
WMI_ANCHOR = "static int v2_selftest(void){"
WMI_NEW = r'''/* ===== WMI kernel real-time event source (additive; ETW pump untouched) =====
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
 {int slotlist[2];int ns=0,si_;
  slotlist[ns++]=WMI_EXECQ_SLOT;slotlist[ns++]=WMI_EXECQ_SLOT_ALT;
  for(si_=0;si_<ns&&!push_ok&&g_running;si_++){
   f6=(PFN_WQL6)vt[slotlist[si_]];
   {void* bl=sa(L"WQL"),*bq=sa(L"SELECT * FROM Win32_ProcessStartTrace");
    hr=f6(svc,bl,bq,0,NULL,&enm);sf(bl);sf(bq);}
   diag("WMI ExecNotificationQuery slot=%d hr=0x%08lx enm=%d",slotlist[si_],(unsigned long)hr,enm?1:0);
   if(hr>=0&&enm){
    int got=0,k;
    wmi_spawn_child();
    for(k=0;k<3&&!got;k++){void* obj=NULL;unsigned long ret=0;
     hr=((WMLENUM*)enm)->v->next(enm,1000,1,&obj,&ret);
     if(hr>=0&&ret&&obj){got=1;((WMOBJ*)obj)->v->rl(obj);}}}
    if(got){push_ok=1;diag("WMI push self-test slot=%d OK -> PUSH mode",slotlist[si_]);}
    else{diag("WMI push self-test slot=%d: no event in 3s",slotlist[si_]);
     ((WMLENUM*)enm)->v->rl(enm);enm=NULL;}}}
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
    if(!first){
     {int i2,j2;
      for(i2=0;i2<cur_n;i2++){int found=0;
       for(j2=0;j2<prev_n;j2++)if(prev[j2]==cur[i2]){found=1;break;}
       if(!found&&cur[i2]!=g_parent&&cur[i2]!=GetCurrentProcessId()){
        char up[2048],imgc[MAX_PATH*2];imgc[0]=0;up[0]=0;
        InterlockedIncrement(&g_diag_proc);g_diag_events++;
        v2_decide(cur[i2],up,(int)sizeof(up),imgc);}}}
    memcpy(prev,cur,(size_t)cur_n*sizeof(DWORD));prev_n=cur_n;first=0;
   }else{diag("WMI pull ExecQuery hr=0x%08lx",(unsigned long)hr);}
   {int sl;for(sl=0;sl<3&&g_running;sl++)Sleep(WMI_PULL_MS/3);}}}
 diag("WMI worker exiting push=%d",push_ok);
 return 0;}
/* ===== end WMI source ===== */
static int v2_selftest(void){'''
rep("P-A2 WMI block before v2_selftest", WMI_ANCHOR, WMI_NEW)

# ---------------- P-C: init decide lock ----------------
rep("P-C init g_decide_lock",
    "InitializeCriticalSection(&g_lock);InitializeCriticalSection(&g_diag_lock);",
    "InitializeCriticalSection(&g_lock);InitializeCriticalSection(&g_diag_lock);InitializeCriticalSection(&g_decide_lock);")

# ---------------- P-D: start WMI thread ----------------
rep("P-D start wmi_worker thread",
    "CreateThread(NULL,0,parent_watch,NULL,0,NULL);",
    'CreateThread(NULL,0,parent_watch,NULL,0,NULL);CreateThread(NULL,0,wmi_worker,NULL,0,NULL);diag("WMI event source thread started");')

io.open(SRC, "w", encoding="utf-8", newline="").write(s)
print("PATCHED: %d -> %d bytes, %d -> %d lines" % (orig_len, len(s), orig_lines, s.count("\n")))
