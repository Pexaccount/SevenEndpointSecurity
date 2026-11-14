from pathlib import Path
p=Path(__file__).with_name('SevenAgent.c')
s=p.read_text(encoding='utf-8')
old='ImageLoad.SensitiveDll.UserWritablePath'
if s.count(old)!=1: raise SystemExit(f'expected one behavior token, got {s.count(old)}')
p.write_text(s.replace(old,'ImageLoad.SuspiciousSideload',1),encoding='utf-8',newline='')
