from pathlib import Path
p=Path(__file__).with_name('SevenAgent.c')
s=p.read_text(encoding='utf-8')
old='if(ids[i]&&process_path(ids[i],p,MAX_PATH)&&has(p,L"\\\\sevenendpoint.exe"))return ids[i];'
new='if(ids[i]&&ids[i]!=GetCurrentProcessId()&&process_path(ids[i],p,MAX_PATH)){WCHAR*base=wcsrchr(p,L"\\\\");base=base?base+1:p;if(!_wcsicmp(base,L"SevenEndPoint.exe"))return ids[i];}'
if s.count(old)!=1: raise SystemExit(f'controller predicate count {s.count(old)}')
p.write_text(s.replace(old,new,1),encoding='utf-8',newline='')
