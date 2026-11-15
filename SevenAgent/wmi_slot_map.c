/* Decisive IWbemServices vtable slot mapper.
   Usage: wmi_slot_map.exe <slot> <Q|N|A7>
   Q  : 6-arg form, data query  "SELECT * FROM Win32_Process"
   N  : 6-arg form, notify query "SELECT * FROM Win32_ProcessStartTrace"
        then spawn 2 children and Next() up to 3 events (6s timeout each)
   A7 : 7-arg form, NULL sink/callresult (async slots return invalid-param,
        sync slots ignore the extra stack arg)
   One process per config so a bad-slot crash only kills its own run.
   All output ASCII. */
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>

typedef struct { USHORT vt,w1,w2,w3; union { long lVal; void* pVal; } u; } VARP;
typedef struct LVt LVt; struct LVt { ULONG (WINAPI*qi)(void*,const GUID*,void**); ULONG (WINAPI*ar)(void*); ULONG (WINAPI*rl)(void*); ULONG (WINAPI*conn)(void*,const WCHAR*,const WCHAR*,const WCHAR*,const WCHAR*,unsigned long,const WCHAR*,void*,void**); };
typedef struct { LVt* v; } LOBJ;
typedef struct EVt EVt; struct EVt { ULONG (WINAPI*qi)(void*,const GUID*,void**); ULONG (WINAPI*ar)(void*); ULONG (WINAPI*rl)(void*); void* rst; ULONG (WINAPI*next)(void*,unsigned long,unsigned long,void**,unsigned long*); };
typedef struct { EVt* v; } EOBJ;
typedef struct OVt OVt; struct OVt { ULONG (WINAPI*qi)(void*,const GUID*,void**); ULONG (WINAPI*ar)(void*); ULONG (WINAPI*rl)(void*); void* gqs; ULONG (WINAPI*get)(void*,const WCHAR*,long,VARP*,long*,long*); };
typedef struct { OVt* v; } OOBJ;

static const GUID CLSID_LOC={0x4590f811,0x1d3a,0x11d0,{0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
static const GUID IID_LOC={0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

typedef long (WINAPI*PFN_COINIT)(void*,unsigned long);
typedef long (WINAPI*PFN_COSEC)(void*,long,void*,void*,unsigned long,unsigned long,void*,unsigned long,void*,void*);
typedef long (WINAPI*PFN_COCREATE)(const GUID*,void*,unsigned long,const GUID*,void**);
typedef void* (WINAPI*PFN_ALLOC)(const WCHAR*);
typedef void (WINAPI*PFN_FREE)(void*);
typedef long (WINAPI*PFN6)(void*,const WCHAR*,const WCHAR*,long,void*,void**);
typedef long (WINAPI*PFN7)(void*,const WCHAR*,const WCHAR*,long,void*,void*,void**);

static void spawn_children(void){
 STARTUPINFOW si;PROCESS_INFORMATION pi;WCHAR cmd[80];int k;
 for(k=0;k<2;k++){
  ZeroMemory(&si,sizeof(si));si.cb=sizeof(si);ZeroMemory(&pi,sizeof(pi));
  _snwprintf(cmd,80,L"cmd.exe /c ver");
  if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
   CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}}}

int main(int argc,char**argv){
 HMODULE o,a;PFN_COINIT ci;PFN_COSEC cs;PFN_COCREATE cc;
 void *loc=NULL,*svc=NULL,*enm=NULL; long hr; int slot; char mode;
 VARP v; long ty,fl;
 if(argc<3){printf("usage: wmi_slot_map.exe <slot> <Q|N|A7>\n");return 2;}
 slot=atoi(argv[1]);mode=argv[2][0];
 if(slot<0||slot>40){printf("bad slot\n");return 2;}
 o=LoadLibraryW(L"ole32.dll");a=LoadLibraryW(L"oleaut32.dll");
 ci=(PFN_COINIT)GetProcAddress(o,"CoInitializeEx");
 cs=(PFN_COSEC)GetProcAddress(o,"CoInitializeSecurity");
 cc=(PFN_COCREATE)GetProcAddress(o,"CoCreateInstance");
 hr=ci(NULL,2);
 printf("CoInit hr=0x%08lx\n",(unsigned long)hr);
 hr=cs(NULL,-1,NULL,NULL,0,3,NULL,0,NULL,NULL);
 printf("CoSec hr=0x%08lx\n",(unsigned long)hr);
 hr=cc(&CLSID_LOC,NULL,1,&IID_LOC,&loc);
 printf("CoCreate hr=0x%08lx loc=%p\n",(unsigned long)hr,loc);fflush(stdout);
 if(hr<0||!loc)return 1;
 hr=((LOBJ*)loc)->v->conn(loc,L"ROOT\\CIMV2",NULL,NULL,NULL,0,NULL,NULL,&svc);
 printf("ConnectServer hr=0x%08lx svc=%p\n",(unsigned long)hr,svc);fflush(stdout);
 if(hr<0||!svc)return 1;
 {void** vt=*(void***)svc; /* object's first field = vtable pointer */
  if(mode=='A'){
   PFN7 f7=(PFN7)vt[slot];
   hr=f7(svc,L"WQL",L"SELECT * FROM Win32_ProcessStartTrace",0,NULL,NULL,NULL);
   printf("A7 slot=%d hr=0x%08lx\n",slot,(unsigned long)hr);
  }else{
   PFN6 f6=(PFN6)vt[slot];
   static WCHAR qbuf[512];
   const WCHAR* q;
   if(argc>=4){MultiByteToWideChar(65001,0,argv[3],-1,qbuf,512);q=qbuf;}
   else q=(mode=='N')?L"SELECT * FROM Win32_ProcessStartTrace"
                     :L"SELECT * FROM Win32_Process";
   printf("call slot=%d mode=%c\n",slot,mode);fflush(stdout);
   if(mode=='B'){
    void* bl, *bq;
    {PFN_ALLOC sa=(PFN_ALLOC)GetProcAddress(a,"SysAllocString");bl=sa(L"WQL");bq=sa(q);}
    hr=f6(svc,bl,bq,0,NULL,&enm);
    {PFN_FREE sf=(PFN_FREE)GetProcAddress(a,"SysFreeString");if(sf){sf(bl);sf(bq);}}
   }else hr=f6(svc,L"WQL",q,0,NULL,&enm);
   printf("call6 slot=%d mode=%c hr=0x%08lx enm=0x%016llx\n",slot,mode,(unsigned long)hr,(unsigned long long)(size_t)enm);
   fflush(stdout);
   if(hr>=0&&enm&&(mode=='N'||mode=='B')){
    int k;unsigned long ret;void* obj;
    printf("spawning children\n");fflush(stdout);spawn_children();
    for(k=0;k<10;k++){
     obj=NULL;ret=0;
     hr=((EOBJ*)enm)->v->next(enm,3000,1,&obj,&ret);
     if((k%3)==2){printf("  respawn kids\n");fflush(stdout);spawn_children();}
     printf("Next[%d] hr=0x%08lx ret=%lu\n",k,(unsigned long)hr,(unsigned long)ret);
     fflush(stdout);
     if(hr<0||!ret||!obj)break;
     ZeroMemory(&v,sizeof(v));ty=0;fl=0;
     if(((OOBJ*)obj)->v->get(obj,L"ProcessID",0,&v,&ty,&fl)>=0)
      printf("  PID=%ld vt=%ld\n",(unsigned long)v.u.lVal,(unsigned long)v.vt);
     ZeroMemory(&v,sizeof(v));ty=0;fl=0;
     if(((OOBJ*)obj)->v->get(obj,L"ProcessName",0,&v,&ty,&fl)>=0&&v.vt==8&&v.u.pVal){
      printf("  NAME=%S\n",(WCHAR*)v.u.pVal);
      {typedef void (WINAPI*PFN_FREE)(void*);PFN_FREE f=(PFN_FREE)GetProcAddress(a,"SysFreeString");if(f)f(v.u.pVal);}}
     fflush(stdout);
     ((OOBJ*)obj)->v->rl(obj);}}}}
 {void** vt2=*(void***)svc;
  {void* bl=0,*bq=0,*q2=0;long h2;LARGE_INTEGER t0,t1,freq;int cyc;static void* arr[100];
   QueryPerformanceFrequency(&freq);
   {typedef void* (WINAPI*PA)(const WCHAR*);PA pa=(PA)GetProcAddress(a,"SysAllocString");bl=pa(L"WQL");bq=pa(L"SELECT ProcessId FROM Win32_Process");}
   {typedef long (WINAPI*P6)(void*,const WCHAR*,const WCHAR*,long,void*,void**);P6 f=(P6)vt2[20];h2=f(svc,bl,bq,0,NULL,&q2);}
   printf("bulk query hr=0x%08lx enm=%d\n",(unsigned long)h2,q2?1:0);fflush(stdout);
   QueryPerformanceCounter(&t0);
   for(cyc=0;cyc<3&&q2;cyc++){
    {void** ev=*(void***)q2;
     typedef unsigned long (WINAPI*PN)(void*,long,unsigned long,void**,unsigned long*);
     PN fn=(PN)ev[4];
     unsigned long ret=0;int total=0;
     for(;;){ret=0;hr=fn(q2,1000,100,arr,&ret);if(hr<0||!ret)break;total+=(int)ret;
      {int zz;for(zz=0;zz<(int)ret;zz++)((OOBJ*)arr[zz])->v->rl(arr[zz]);}
      if(ret<100)break;}
     QueryPerformanceCounter(&t1);
     printf("cycle %d procs=%d ms=%.1f\n",cyc,total,(double)(t1.QuadPart-t0.QuadPart)*1000.0/(double)freq.QuadPart);fflush(stdout);
     t0=t1;}
    Sleep(300);}}
 printf("BULKDONE\n");
 return 0;}}
