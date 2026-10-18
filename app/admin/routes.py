"""Authenticated personal management API. No credential-bearing response bodies."""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.admin.runtime import reload_pool
from app.admin.store import AdminError

router = APIRouter()
COOKIE = 'n2a_admin_session'
_FAILURES: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()


def _store(request: Request):
    store = getattr(request.app.state, 'admin_store', None)
    if not store:
        raise HTTPException(503, '管理后台尚未初始化')
    return store


def _secure(request: Request):
    # Behind a reverse proxy, only trust properly configured, server-verified scheme.
    https = request.url.scheme == 'https'
    if not https and os.getenv('ADMIN_ALLOW_INSECURE_HTTP', '0') != '1':
        raise HTTPException(403, '管理后台需要 HTTPS。仅本地测试可显式设置 ADMIN_ALLOW_INSECURE_HTTP=1')
    return https


def auth(request: Request):
    _secure(request)
    store = _store(request)
    token = request.cookies.get(COOKIE, '')
    if not store.authorize_session(token):
        raise HTTPException(401, '管理员未登录或会话已过期')
    if request.method not in ('GET','HEAD','OPTIONS'):
        if not store.authorize_session(token, request.headers.get('X-CSRF-Token', '')):
            raise HTTPException(403, 'CSRF 校验失败')
    return store


def _check_login_limit(ip: str):
    now = time.monotonic()
    with _LOGIN_LOCK:
        _FAILURES[ip] = [value for value in _FAILURES.get(ip, []) if now-value<900]
        if len(_FAILURES[ip]) >= 8:
            raise HTTPException(429, '尝试次数过多，请稍后重试')


def _login_failed(ip: str):
    with _LOGIN_LOCK:
        _FAILURES.setdefault(ip, []).append(time.monotonic())


def _apply(error: AdminError):
    raise HTTPException(status_code=error.status, detail=str(error)) from error


@router.post('/login')
def login(request: Request, response: Response, payload: dict = Body(...)):
    secure = _secure(request)
    store = _store(request)
    ip = request.client.host if request.client else 'unknown'
    _check_login_limit(ip)
    password = payload.get('password')
    if not isinstance(password, str) or len(password) > 2000:
        raise HTTPException(400, '密码格式错误')
    try:
        token, csrf = store.login(password)
    except AdminError as e:
        _login_failed(ip)
        _apply(e)
    with _LOGIN_LOCK:
        _FAILURES.pop(ip, None)
    response.set_cookie(COOKIE, token, max_age=7*86400, httponly=True,
                        secure=secure, samesite='strict', path='/admin')
    return {'ok':True,'csrf':csrf, 'secure':secure}


@router.get('/session')
def session(request: Request, store=Depends(auth)):
    return {'ok': True, 'csrf': store.session_csrf(request.cookies.get(COOKIE,'')),
            'secure':request.url.scheme=='https'}


@router.post('/logout')
def logout(request: Request, response: Response, store=Depends(auth)):
    store.logout(request.cookies.get(COOKIE,''))
    response.delete_cookie(COOKIE, path='/admin', samesite='strict')
    return {'ok':True}


@router.post('/password')
def change_password(request: Request, payload: dict = Body(...), store=Depends(auth)):
    try:
        store.change_password(str(payload.get('old','')), str(payload.get('new','')),
                              request.cookies.get(COOKIE,''))
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.get('/overview')
def overview(request: Request, store=Depends(auth)):
    result = store.dashboard()
    result['pool'] = request.app.state.account_pool.get_status_summary()
    return result


@router.get('/accounts')
def accounts(store=Depends(auth)):
    return {'items': store.list_accounts()}


@router.post('/accounts', status_code=201)
def add_account(request: Request, payload: dict = Body(...), store=Depends(auth)):
    creds = payload.get('credentials')
    try:
        aid = store.add_account(creds, str(payload.get('label','')), payload.get('enabled',True))
        reload_pool(request.app)
        return {'ok': True, 'id':aid}
    except AdminError as e:
        _apply(e)


@router.put('/accounts/{aid}')
def update_account(aid: str, request: Request, payload: dict = Body(...), store=Depends(auth)):
    try:
        store.update_account(aid, label=payload.get('label'), enabled=payload.get('enabled'),
                             credentials=payload.get('credentials'))
        reload_pool(request.app)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.delete('/accounts/{aid}')
def delete_account(aid: str, request: Request, store=Depends(auth)):
    try:
        store.delete_account(aid)
        reload_pool(request.app)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


def _test_account(credentials: dict):
    """Check authentication against model discovery; never log/return private headers."""
    try:
        from curl_cffi import requests as curls
        root = os.getenv('NOTION_URL','https://www.notion.so').rstrip('/')
        jar = dict(credentials.get('cookies') or {})
        jar['token_v2'] = credentials['token_v2']
        jar['notion_user_id'] = credentials['user_id']
        headers = {
            'Content-Type':'application/json','Accept':'application/json',
            'Origin':root,'Referer':root+'/chat',
            'x-notion-space-id':credentials['space_id'],
            'x-notion-active-user-header':credentials['user_id'],
            'notion-client-version':os.getenv('NOTION_CLIENT_VERSION','23.13.20260228.0625'),
            'Cookie':'; '.join('%s=%s'%(k,v) for k,v in jar.items() if v),
        }
        r = curls.post(root+'/api/v3/getAvailableModels', headers=headers,
                       json={'spaceId':credentials['space_id']}, impersonate='chrome', timeout=25)
        if r.status_code != 200:
            return {'ok':False,'status':r.status_code,'message':'Notion 模型接口未返回 200'}
        data = r.json()
        items = data.get('models',[]) if isinstance(data,dict) else data
        if not isinstance(items,list) or not items:
            return {'ok':False,'message':'未返回有效模型目录'}
        return {'ok':True,'models':len(items)}
    except Exception as e:
        return {'ok':False,'message':'连接或响应解析失败','error_type':type(e).__name__}


@router.post('/accounts/{aid}/test')
def test_account(aid: str, store=Depends(auth)):
    try:
        result = _test_account(store.get_account_credentials(aid))
        store.record_test(aid, 'OK' if result['ok'] else result.get('message','Error'))
        store.audit('account.test',aid,'ok' if result['ok'] else 'failed')
        return result
    except AdminError as e:
        _apply(e)


@router.get('/keys')
def keys(store=Depends(auth)):
    return {'items':store.list_keys()}


@router.post('/keys', status_code=201)
def create_key(payload: dict = Body(...), store=Depends(auth)):
    try:
        return store.create_key(label=payload.get('label'),
            daily_limit=payload.get('daily_limit',0),monthly_limit=payload.get('monthly_limit',0),
            rpm_limit=payload.get('rpm_limit',0),models=payload.get('allowed_models',[]),
            expires_at=payload.get('expires_at'))
    except AdminError as e:
        _apply(e)


@router.put('/keys/{kid}')
def update_key(kid: str, payload: dict = Body(...), store=Depends(auth)):
    try:
        store.update_key(kid,payload)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.post('/keys/{kid}/revoke')
def revoke_key(kid: str, store=Depends(auth)):
    try:
        store.revoke_key(kid)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.delete('/keys/{kid}')
def delete_key(kid: str, store=Depends(auth)):
    try:
        store.delete_key(kid)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.get('/models')
def models(store=Depends(auth)):
    return {'items':store.list_models()}


@router.put('/models/{mid}')
def toggle_model(mid: str, payload: dict = Body(...), store=Depends(auth)):
    if type(payload.get('enabled')) is not bool:
        raise HTTPException(400,'需要 enabled 布尔值')
    try:
        store.update_model(mid,payload['enabled'])
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.post('/models/custom', status_code=201)
def custom_model(payload: dict = Body(...), store=Depends(auth)):
    try:
        store.add_custom_model(str(payload.get('id','')), str(payload.get('code','')),
                               str(payload.get('name','')))
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.delete('/models/custom/{mid}')
def delete_custom(mid: str, store=Depends(auth)):
    try:
        store.delete_custom_model(mid)
        return {'ok':True}
    except AdminError as e:
        _apply(e)


@router.get('/usage')
def usage(store=Depends(auth)):
    return {'items':store.recent_usage()}


@router.get('/audits')
def audits(store=Depends(auth)):
    return {'items':store.recent_audits()}


@router.get('/settings')
def settings(store=Depends(auth)):
    return {'legacy_api_key_enabled':store.get_setting('legacy_api_key_enabled','1')=='1',
            'mode':os.getenv('APP_MODE','standard'),
            'https':os.getenv('ADMIN_ALLOW_INSECURE_HTTP','0')!='1',
            'notice':'运行模式来自 .env，需要重启；旧 API Key 可以在此停用。'}


@router.put('/settings')
def update_settings(payload: dict = Body(...), store=Depends(auth)):
    if set(payload) != {'legacy_api_key_enabled'} or type(payload['legacy_api_key_enabled']) is not bool:
        raise HTTPException(400,'仅支持 legacy_api_key_enabled 布尔值')
    try:
        store.set_setting('legacy_api_key_enabled', '1' if payload['legacy_api_key_enabled'] else '0')
    except AdminError as e:
        _apply(e)
    return {'ok':True}