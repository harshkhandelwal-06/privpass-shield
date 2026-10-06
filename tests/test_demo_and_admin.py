from __future__ import annotations
import base64, hashlib, hmac, io, zipfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.passwords import analyze

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def client_login(c, email, password):
    from conftest import login_as
    res = login_as(c, email, password)
    assert res.status_code == 200, res.text
    return res

def test_password_model_examples():
    weak = analyze('aaaasfiefifosdnofsdfn', ['divy', 'acme'])
    identity = analyze('divy1023divy1032', ['divy', 'acme'])
    numeric = analyze('3492847592039485720', ['divy', 'acme'])
    gibberish = analyze('asfajfbjadbfiwebfiwefiewb', ['divy', 'acme'])
    generated = analyze('N7p#xQ2!mR8@zK4$uP6^wL9?cD3&fH5*', ['divy'], generated=True)
    assert weak['score'] < 60
    assert identity['score'] <= 35
    assert identity['flags']['identity_like'] is True
    assert numeric['score'] <= 35
    assert gibberish['score'] < 65
    assert generated['score'] >= 92
    assert generated['flags']['generated'] is True

def test_demo_info_and_repository():
    with TestClient(app) as c:
        info = c.get('/api/demo/info')
        assert info.status_code == 200
        data = info.json()
        assert data['demo_mode'] is True
        assert data['admin']['role'] == 'admin'
        demo = c.get('/api/demo/repository.zip')
        assert demo.status_code == 200
        with zipfile.ZipFile(io.BytesIO(demo.content)) as z:
            names = z.namelist()
        assert 'src/config.py' in names
        assert 'docs/remediation.md' in names

def test_admin_metrics_and_judge_scan():
    with TestClient(app) as c:
        client_login(c, 'admin@privpass.local', 'PrivPass!Demo#2026-Admin')
        overview = c.get('/api/admin/overview')
        assert overview.status_code == 200
        data = overview.json()
        assert data['user_count'] >= 2
        assert 'average_password_score' in data
        demo_scan = c.post('/api/judge/demo-scan')
        assert demo_scan.status_code == 200, demo_scan.text
        payload = demo_scan.json()
        assert len(payload['findings']) >= 4
        assert all('reason' in finding for finding in payload['findings'])
