import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PKG))

from app.admin.store import AdminError, AdminStore, password_hash

@pytest.fixture
def model_registry(monkeypatch):
    import app
    fake = types.ModuleType('app.model_registry')
    fake.MODEL_MAP={'claude-opus5.5':'albuquerque-quinn','claude-opus5.5-effort-high':'albuquerque-quinn','gpt-6.1-sol':'omniberry-sundae'}
    fake.DISPLAY_NAMES={'claude-opus5.5':'Opus 5.5','claude-opus5.5-effort-high':'Opus 5.5 HIGH','gpt-6.1-sol':'GPT-6.1 Sol'}
    fake.MODEL_ICONS={key:'◇' for key in fake.MODEL_MAP}
    fake.NOTION_MODEL_REVERSE_MAP={v:k for k,v in fake.MODEL_MAP.items()}
    fake.is_supported_model=lambda k:k in fake.MODEL_MAP
    fake.list_available_models=lambda:list(fake.MODEL_MAP)
    fake.get_display_name=lambda k:fake.DISPLAY_NAMES.get(k,k)
    pool_module=types.ModuleType('app.account_pool')
    class FakePool:
        def __init__(self,accounts):self.clients=accounts
        def get_status_summary(self):return {'active':len(self.clients),'cooling':0,'total':len(self.clients)}
    pool_module.AccountPool=FakePool
    monkeypatch.setitem(sys.modules,'app.account_pool',pool_module)
    monkeypatch.setitem(sys.modules,'app.model_registry',fake)
    monkeypatch.setattr(app,'model_registry',fake,raising=False)
    return fake

@pytest.fixture
def store(tmp_path,model_registry):
    creds=[{'token_v2':'first-secret','space_id':'first-space','user_id':'first-user', 'user_email':'user@example.com'}]
    s=AdminStore(str(tmp_path/'admin.sqlite'),Fernet.generate_key().decode(),password_hash('VeryLongSecurePassword_123'),creds)
    s.reload_custom_models()
    return s


def test_auth_and_account_crud(store):
    assert store.list_accounts()[0]['email']=='user@example.com'
    assert 'token_v2' not in store.list_accounts()[0]
    with pytest.raises(AdminError): store.login('incorrect-password')
    token,csrf=store.login('VeryLongSecurePassword_123')
    assert store.authorize_session(token,csrf)
    assert not store.authorize_session(token,csrf+'x')
    assert store.session_csrf(token)==csrf
    account={'token_v2':'second-secret','space_id':'second-space','user_id':'second-user'}
    second=store.add_account(account,'Second')
    assert len(store.enabled_accounts())==2
    store.update_account(second,enabled=False)
    assert len(store.enabled_accounts())==1
    with pytest.raises(AdminError):store.update_account(next(x['id'] for x in store.list_accounts() if x['email']=='user@example.com'),enabled=False)
    store.delete_account(second)
    assert len(store.list_accounts())==1
    store.logout(token)
    assert not store.authorize_session(token)


def test_key_quotas_and_revocation(store):
    secret=store.create_key('Workstation',daily_limit=2,monthly_limit=3,rpm_limit=0,models=['claude-opus5.5'])
    key=store.key_from_bearer(secret['secret'])
    assert key is not None
    assert secret['secret'] not in str(store.list_keys())
    assert store.model_allowed('claude-opus5.5',key)
    assert not store.model_allowed('gpt-6.1-sol',key)
    store.finish_usage(store.reserve_usage(key,'claude-opus5.5'),200,30)
    store.finish_usage(store.reserve_usage(key,'claude-opus5.5'),429,20)
    with pytest.raises(AdminError) as info: store.reserve_usage(key,'claude-opus5.5')
    assert info.value.status==429
    store.revoke_key(secret['id'])
    assert store.key_from_bearer(secret['secret']) is None


def test_model_flags_custom_and_alias(store,model_registry):
    store.update_model('claude-opus5.5',False)
    assert not store.model_allowed('claude-opus5.5-effort-high')
    store.update_model('claude-opus5.5',True)
    assert store.model_allowed('claude-opus5.5-effort-high')
    store.add_custom_model('my-model','custom-upstream','My Custom Model')
    assert store.model_allowed('my-model')
    assert model_registry.MODEL_MAP['my-model']=='custom-upstream'
    store.delete_custom_model('my-model')
    assert 'my-model' not in model_registry.MODEL_MAP


def test_no_credentials_in_reports(store):
    key=store.create_key('Daily',daily_limit=10)
    store.finish_usage(store.reserve_usage(store.key_from_bearer(key['secret']),'claude-opus5.5'),200,123)
    report=json.dumps({'dashboard':store.dashboard(),'keys':store.list_keys(),'accounts':store.list_accounts()})
    assert 'first-secret' not in report
    assert key['secret'] not in report
    assert store.dashboard()['today_requests']==1


def test_install_patches():
    import install
    server='''from app.limiter import limiter\n\nasync def lifespan(app):\n    app.state.start_time = time.time()\n    yield\n\n# 简易 API Key 鉴权中间件\n@app.middleware("http")\nasync def api_key_auth(request: Request, call_next):\n    return await call_next(request)\n\n# 挂载路由，前缀统一为 /v1\napp.include_router(models_router, prefix="/v1")\n'''
    out=install.patch_server(server)
    assert 'initialize_admin(app)' in out
    assert 'authenticate_api_request(request, call_next)' in out
    assert 'app.include_router(admin_router' in out
    assert install.patch_server(out)==out
    model='''from fastapi import APIRouter\nfrom typing import Dict,Any\nasync def list_models() -> Dict[str, Any]:\n    return [x for model_id in list_available_models()\n            for model_id in list_available_models()\n    ]\n'''
    # Protect exact source layout, not arbitrary incompatible code.
    with pytest.raises(RuntimeError):install.patch_models('from fastapi import APIRouter\n')


def make_web_app(store,monkeypatch):
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from app.admin.routes import router
    from app.admin.middleware import authenticate_api_request
    app=FastAPI()
    app.state.admin_store=store
    class Pool:
        def get_status_summary(self):
            return {'active':1,'cooling':0,'total':1}
    app.state.account_pool=Pool()
    monkeypatch.setenv('API_KEY','legacy-key')
    app.include_router(router,prefix='/admin/api')
    @app.middleware('http')
    async def check_key(request,call_next):
        if request.url.path.startswith('/v1'):
            return await authenticate_api_request(request,call_next)
        return await call_next(request)
    @app.post('/v1/chat/completions')
    async def chat(request: Request):
        return {'model':(await request.json())['model']}
    @app.get('/v1/models')
    async def all_models(request: Request):
        return {'models':[m['id'] for m in store.list_models() if store.model_allowed(m['id'],getattr(request.state,'admin_key',None))]}
    return TestClient(app,base_url='https://vps.example')


def test_full_http_routes(store,monkeypatch):
    client=make_web_app(store,monkeypatch)
    assert client.get('/admin/api/accounts').status_code==401
    r=client.post('/admin/api/login',json={'password':'VeryLongSecurePassword_123'})
    assert r.status_code==200,r.text
    csrf=r.json()['csrf']
    assert client.get('/admin/api/session').json()['csrf']==csrf
    assert client.post('/admin/api/keys',json={'label':'X'}).status_code==403
    res=client.post('/admin/api/keys',headers={'X-CSRF-Token':csrf},json={'label':'Cherry Studio','daily_limit':2,'allowed_models':['claude-opus5.5']})
    assert res.status_code==201,res.text
    secret=res.json()['secret']
    assert not any(secret in str(x) for x in client.get('/admin/api/keys').json()['items'])
    headers={'Authorization':'Bearer '+secret}
    assert client.get('/v1/models',headers=headers).json()['models']==['claude-opus5.5']
    first=client.post('/v1/chat/completions',headers=headers,json={'model':'claude-opus5.5'})
    second=client.post('/v1/chat/completions',headers=headers,json={'model':'claude-opus5.5'})
    assert first.status_code==second.status_code==200
    assert client.post('/v1/chat/completions',headers=headers,json={'model':'claude-opus5.5'}).status_code==429
    assert client.post('/v1/chat/completions',headers=headers,json={'model':'gpt-6.1-sol'}).status_code==403
    assert client.post('/v1/chat/completions',headers={'Authorization':'Bearer legacy-key'},json={'model':'gpt-6.1-sol'}).status_code==200
    changed=client.put('/admin/api/settings',headers={'X-CSRF-Token':csrf},json={'legacy_api_key_enabled':False})
    assert changed.status_code==200
    assert client.post('/v1/chat/completions',headers={'Authorization':'Bearer legacy-key'},json={'model':'gpt-6.1-sol'}).status_code==401
    assert client.post('/admin/api/logout',headers={'X-CSRF-Token':csrf},json={}).status_code==200
    assert client.get('/admin/api/session').status_code==401


def test_http_admin_login_rejected(store,monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.admin.routes import router
    monkeypatch.delenv('ADMIN_ALLOW_INSECURE_HTTP',raising=False)
    app=FastAPI();app.state.admin_store=store
    app.include_router(router,prefix='/admin/api')
    client=TestClient(app,base_url='http://test-vps')
    assert client.post('/admin/api/login',json={'password':'VeryLongSecurePassword_123'}).status_code==403