from __future__ import annotations
import os, subprocess, sys, time, urllib.request, secrets, hashlib, socket, webbrowser
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
API=ROOT/'app'; VENV=ROOT/'.venv'; PY=VENV/'Scripts'/'python.exe' if os.name=='nt' else VENV/'bin'/'python'

def run(args,cwd=ROOT,env=None):
    print('+',' '.join(map(str,args)),flush=True)
    subprocess.check_call([str(x) for x in args],cwd=str(cwd),env=env)

def free_port(start=8000):
    for port in range(start,start+20):
        with socket.socket() as s:
            try: s.bind(("127.0.0.1",port)); return port
            except OSError: continue
    raise RuntimeError("no free local port found")

def main():
    if sys.version_info < (3,10): raise SystemExit('Python 3.10+ is required.')
    if not PY.exists(): run([sys.executable,'-m','venv',str(VENV)])
    req=ROOT/'requirements.txt'
    digest=hashlib.sha256(req.read_bytes()).hexdigest()
    marker=ROOT/'runtime'/'.deps.sha256'
    (ROOT/'runtime').mkdir(exist_ok=True)
    if not marker.exists() or marker.read_text().strip()!=digest:
        try:
            run([str(PY),'-m','pip','install','--disable-pip-version-check','--upgrade','pip'])
            run([str(PY),'-m','pip','install','--disable-pip-version-check','-r',str(req)])
        except subprocess.CalledProcessError:
            print('\nERROR: installing the required Python packages failed (see pip output above).', flush=True)
            print('Check your internet connection, then run scripts\\RESET-PRIVPASS.bat and START-PRIVPASS.bat again.', flush=True)
            return 2
        marker.write_text(digest)
    env=os.environ.copy();env['PYTHONPATH']=str(ROOT);env.setdefault('APP_ENV','development')
    env_file=ROOT/'.env'
    if not env_file.exists():
        env_file.write_text('APP_ENV=development\nAPP_SECRET='+secrets.token_urlsafe(48)+'\nCOOKIE_SECURE=false\nDATABASE_URL=sqlite:///'+str((ROOT/'runtime'/'privpass.db').as_posix())+'\nHIBP_USER_AGENT=PrivPass-Shield/6.2\n'
                            '\n# AI features: paste your Claude API key after the = sign (from console.anthropic.com), then restart.\n'
                            '# Leave it empty to use offline AI mode. Never commit this file.\nANTHROPIC_API_KEY=\nPRIVPASS_AI_MODEL=claude-sonnet-5\n# Your private (non-demo) admin account. Leave the password empty to have one generated into runtime/ADMIN-CREDENTIALS.txt\nPRIVPASS_ADMIN_EMAIL=\nPRIVPASS_ADMIN_PASSWORD=\n'
                            '\n# Optional integrations: GitHub token (private repos + fix PRs) and Slack/Teams webhook for alerts.\nGITHUB_TOKEN=\nALERT_WEBHOOK_URL=\n')
    elif 'ANTHROPIC_API_KEY' not in env_file.read_text(encoding='utf-8'):
        with open(env_file,'a',encoding='utf-8') as fh:
            fh.write('\n# AI features: paste your Claude API key after the = sign (from console.anthropic.com), then restart.\n'
                     '# Leave it empty to use offline AI mode. Never commit this file.\nANTHROPIC_API_KEY=\nPRIVPASS_AI_MODEL=claude-sonnet-5\n# Your private (non-demo) admin account. Leave the password empty to have one generated into runtime/ADMIN-CREDENTIALS.txt\nPRIVPASS_ADMIN_EMAIL=\nPRIVPASS_ADMIN_PASSWORD=\n')
    env['_PRIVPASS_READY']='1'
    env['PORT']=str(free_port(int(os.getenv('PORT','8000')) if os.getenv('PORT') else 8000))
    run([str(PY),str(ROOT/'tools'/'ui_check.py')],env=env)
    run([str(PY),'-c','from app.db import init_db; init_db(); from app.bootstrap import ensure_demo_admin; ensure_demo_admin()'],env=env)
    print(f'PrivPass Shield -> http://localhost:{env["PORT"]}  (use localhost, not 127.0.0.1, so passkeys work)',flush=True)
    cred=ROOT/'runtime'/'ADMIN-CREDENTIALS.txt'
    if cred.exists():
        print('\n'+'='*72+'\n'+cred.read_text(encoding='utf-8').strip()+'\n'+'='*72+'\n',flush=True)
    else:
        print('Real admin: set in .env (PRIVPASS_ADMIN_EMAIL / PRIVPASS_ADMIN_PASSWORD), or run: python tools/admin_account.py --reset',flush=True)
    proc=subprocess.Popen([str(PY),'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',env['PORT']],cwd=str(ROOT),env=env)
    base=f'http://127.0.0.1:{env["PORT"]}'
    ready=False
    for _ in range(60):
        try:
            with urllib.request.urlopen(base+'/api/health',timeout=1) as r:  # nosec B310 - fixed local http://127.0.0.1 health URL
                if r.status==200:
                    ready=True
                    break
        except Exception: time.sleep(.25)
    if not ready:
        proc.terminate(); proc.wait(timeout=5)
        raise RuntimeError('PrivPass API did not become healthy within 15 seconds; check logs and run scripts\\DOCTOR-PRIVPASS.bat.')
    webbrowser.open(f'http://localhost:{env["PORT"]}')  # passkeys (WebAuthn) require a domain name, not an IP
    try: return proc.wait()
    except KeyboardInterrupt:
        proc.terminate(); proc.wait(timeout=5); return 0
if __name__=='__main__':
    raise SystemExit(main())
