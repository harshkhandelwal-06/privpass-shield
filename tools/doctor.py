from __future__ import annotations
import importlib, os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
print('PrivPass Shield doctor')
print('Python:',sys.version.split()[0])
print('Root:',ROOT)
for mod in ['fastapi','sqlalchemy','cryptography','argon2','jwt']:
    try: importlib.import_module(mod); print('OK ',mod)
    except Exception as e: print('FAIL',mod,e)
print('Static:', 'OK' if (ROOT/'static'/'index.html').exists() else 'MISSING')
print('Demo repo:', 'OK' if (ROOT/'data'/'demo-repo').exists() else 'MISSING')
print('Runtime DB:', 'PRESENT' if (ROOT/'runtime'/'privpass.db').exists() else 'not created yet (normal)')

try:
    import subprocess
    r=subprocess.run([sys.executable,str(ROOT/'tools'/'ui_check.py')],capture_output=True,text=True)
    print(r.stdout.strip() or r.stderr.strip())
except Exception as e:
    print('FAIL ui_check',e)
