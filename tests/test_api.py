import base64, hashlib, hmac, io, os, zipfile
from fastapi.testclient import TestClient
from app.main import app
from conftest import breach_gate, material, verifier_for, login_as

def b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')

def test_auth_and_scan_e2e():
    with TestClient(app) as c:
        email='e2e-'+os.urandom(4).hex()+'@example.com'
        pw='This is a safe demo passphrase 2026!'
        salt=os.urandom(16)
        verifier=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,310000,32)
        res=c.post('/api/auth/signup',json={
            'email':email,**material(pw),
            'verifier_hash':'ignored','score':90,'score_label':'Excellent','breached':False,'breach_gate':breach_gate(c)})
        assert res.status_code==200
        challenge=c.post('/api/auth/challenge',json={'email':email}).json()
        proof=hmac.new(verifier_for(pw,challenge),challenge['nonce'].encode(),hashlib.sha256).hexdigest()
        login=c.post('/api/auth/login',json={'email':email,'nonce':challenge['nonce'],'proof':proof})
        assert login.status_code==200
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('.env','AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n')
        scan=c.post('/api/scans/upload',files={'file':('repo.zip',buf.getvalue(),'application/zip')})
        assert scan.status_code==200
        assert any(x['secret_type']=='AWS access key' for x in scan.json()['findings'])


def test_vault_crypto_envelope_e2e():
    with TestClient(app) as c:
        email='vault-'+os.urandom(4).hex()+'@example.com'
        pw='Long unique vault demo passphrase 2026!'
        salt=os.urandom(16)
        verifier=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,310000,32)
        signup=c.post('/api/auth/signup',json={'email':email,**material(pw),'verifier_hash':'ignored','score':90,'score_label':'Excellent','breached':False,'breach_gate':breach_gate(c)})
        assert signup.status_code==200
        challenge=c.post('/api/auth/challenge',json={'email':email}).json()
        proof=hmac.new(verifier_for(pw,challenge),challenge['nonce'].encode(),hashlib.sha256).hexdigest()
        assert c.post('/api/auth/login',json={'email':email,'nonce':challenge['nonce'],'proof':proof}).status_code==200
        config=c.get('/api/vault/config').json()
        vchallenge=c.post('/api/vault/challenge',json={}).json()
        vproof=hmac.new(verifier_for(pw,challenge),vchallenge['nonce'].encode(),hashlib.sha256).hexdigest()
        unlock=c.post('/api/vault/unlock',json={'proof':vproof,'nonce':vchallenge['nonce']})
        assert unlock.status_code==200
        blob='{"v":1,"iv":"AAAAAAAAAAAAAAAA","ct":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}'
        created=c.post('/api/vault/items',json={'ciphertext_b64':blob})
        assert created.status_code==200
        item_id=created.json()['id']
        rows=c.get('/api/vault/items').json()
        assert rows[0]['id']==item_id
        assert rows[0]['ciphertext_b64']==blob
        deleted=c.delete(f'/api/vault/items/{item_id}')
        assert deleted.status_code==200


def login_with_password(client, email, password):
    response=login_as(client,email,password)
    assert response.status_code==200
    return response


def test_admin_cannot_view_vault_plaintext_and_cross_user_isolation():
    with TestClient(app) as owner, TestClient(app) as other:
        email='owner-'+os.urandom(4).hex()+'@example.com'
        other_email='other-'+os.urandom(4).hex()+'@example.com'
        pw='Owner vault passphrase 2026 with enough length!'
        for client, em in [(owner,email),(other,other_email)]:
            salt=os.urandom(16)
            verifier=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,310000,32)
            assert client.post('/api/auth/signup',json={'email':em,**material(pw),'verifier_hash':'ignored','score':90,'score_label':'Excellent','breached':False,'breach_gate':breach_gate(client)}).status_code==200
            ch=client.post('/api/auth/challenge',json={'email':em}).json()
            proof=hmac.new(verifier_for(pw,ch),ch['nonce'].encode(),hashlib.sha256).hexdigest()
            assert client.post('/api/auth/login',json={'email':em,'nonce':ch['nonce'],'proof':proof}).status_code==200
        blob='{"v":1,"iv":"safe-iv","ct":"opaque-ciphertext-only"}'
        assert owner.post('/api/vault/items',json={'ciphertext_b64':blob}).status_code==200
        assert len(owner.get('/api/vault/items').json())==1
        assert other.get('/api/vault/items').json()==[]

        # Admin uses aggregate metadata only; plaintext/ciphertext is intentionally absent from the admin response.
        # Accounts created by sign-up live in the live workspace, so the real admin inspects them.
        from conftest import real_admin
        real_admin(owner)
        rows=owner.get('/api/admin/users').json()
        mine=next(x for x in rows if x['email']==email)
        assert mine['vault_items']==1
        assert 'ciphertext_b64' not in mine and 'password' not in mine and 'username' not in mine



def test_finding_transition_json_and_lifecycle():
    with TestClient(app) as c:
        email='transition-'+os.urandom(4).hex()+'@example.com'
        pw='Transition demo passphrase 2026 long enough!'
        salt=os.urandom(16)
        verifier=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,310000,32)
        assert c.post('/api/auth/signup',json={'email':email,**material(pw),'verifier_hash':'ignored','score':90,'score_label':'Excellent','breached':False,'breach_gate':breach_gate(c)}).status_code==200
        ch=c.post('/api/auth/challenge',json={'email':email}).json()
        proof=hmac.new(verifier_for(pw,ch),ch['nonce'].encode(),hashlib.sha256).hexdigest()
        assert c.post('/api/auth/login',json={'email':email,'nonce':ch['nonce'],'proof':proof}).status_code==200
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('config.py','AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n')
        scan=c.post('/api/scans/upload',files={'file':('repo.zip',buf.getvalue(),'application/zip')})
        assert scan.status_code==200
        finding=scan.json()['findings'][0]
        fid=finding['id']
        # JSON is the preferred browser contract.
        r=c.post(f'/api/findings/{fid}/transition',json={'status':'TRIAGED'})
        assert r.status_code==200 and r.json()['status']=='TRIAGED'
        # Skipping a lifecycle stage is rejected.
        bad=c.post(f'/api/findings/{fid}/transition',json={'status':'VERIFIED'})
        assert bad.status_code==409
        # PATCH is supported as a compatibility verb.
        r=c.patch(f'/api/findings/{fid}/transition',json={'status':'CONTAINED'})
        assert r.status_code==200 and r.json()['status']=='CONTAINED'



def test_exposure_graph_and_incident_center_use_latest_scan_data():
    with TestClient(app) as c:
        email='graph-'+os.urandom(4).hex()+'@example.com'
        pw='Graph demo password 2026 with enough length!'
        salt=os.urandom(16)
        verifier=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,310000,32)
        assert c.post('/api/auth/signup',json={'email':email,**material(pw),'verifier_hash':'ignored','score':85,'score_label':'Strong','breached':False,'breach_gate':breach_gate(c)}).status_code==200
        ch=c.post('/api/auth/challenge',json={'email':email}).json()
        proof=hmac.new(verifier_for(pw,ch),ch['nonce'].encode(),hashlib.sha256).hexdigest()
        assert c.post('/api/auth/login',json={'email':email,'nonce':ch['nonce'],'proof':proof}).status_code==200
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('payments/config.py','STRIPE_SECRET_KEY="sk_test_fake_example_value_1234567890"\n')
            z.writestr('src/token.js','token="eyJhbGciOiJIUzI1NiJ9.demo.signature"\n')
        scan=c.post('/api/scans/upload',files={'file':('payments-api.zip',buf.getvalue(),'application/zip')})
        assert scan.status_code==200
        findings=scan.json()['findings']
        assert findings
        graph=c.get('/api/exposure/graph')
        assert graph.status_code==200
        payload=graph.json()
        assert payload['scan']['repo_name']=='payments-api.zip'
        assert payload['scan']['findings']==len(findings)
        assert payload['repository']['value']=='payments-api.zip'
        assert payload['secret']['value']
        assert payload['risk'] in {'CRITICAL','HIGH','ELEVATED','GUARDED'}
        incidents=c.get('/api/incidents')
        assert incidents.status_code==200
        ip=incidents.json()
        assert ip['scan']['repo_name']=='payments-api.zip'
        assert ip['total']==len(findings)
        assert ip['counts']['DETECTED']==len(findings)
        fid=findings[0]['id']
        assert c.post(f'/api/findings/{fid}/transition',json={'status':'TRIAGED'}).status_code==200
        assert c.post(f'/api/findings/{fid}/transition',json={'status':'CONTAINED'}).status_code==200
        updated=c.get('/api/incidents').json()
        assert updated['counts']['CONTAINED']==1
        assert updated['counts']['DETECTED']==len(findings)-1
        graph2=c.get('/api/exposure/graph').json()
        assert graph2['status']['CONTAINED']==1
