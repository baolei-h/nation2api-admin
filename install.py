#!/usr/bin/env python3
"""Install, check or roll back Notion2API Personal Admin without overwriting old patches.

Executed INSIDE an existing notion2api checkout on the VPS, not in this source folder.
"""
from __future__ import annotations

import argparse
import ast
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen

ROOT = Path.cwd()
RAW = 'https://raw.githubusercontent.com/baolei-h/nation2api-admin/'
FILES = {
    'app/admin/__init__.py': 'app/admin/__init__.py',
    'app/admin/store.py': 'app/admin/store.py',
    'app/admin/middleware.py': 'app/admin/middleware.py',
    'app/admin/runtime.py': 'app/admin/runtime.py',
    'app/admin/routes.py': 'app/admin/routes.py',
    'frontend/admin/index.html': 'frontend/admin/index.html',
}
EXISTING = ['app/server.py','app/api/models.py','requirements.txt','.env']
START_MARKER = '# BEGIN NOTION2API PERSONAL ADMIN'
END_MARKER = '# END NOTION2API PERSONAL ADMIN'


def one(source, old, new, label):
    count = source.count(old)
    if count != 1:
        raise RuntimeError('%s: expected 1 matching source location, got %d. No file has been modified.' % (label,count))
    return source.replace(old,new,1)


def patch_server(source):
    if START_MARKER in source:
        # Idempotent upgrades: keep the already-installed FastAPI integration.
        return source
    imports = '''# BEGIN NOTION2API PERSONAL ADMIN
from app.admin.routes import router as admin_router
from app.admin.middleware import authenticate_api_request
from app.admin.runtime import initialize_admin
# END NOTION2API PERSONAL ADMIN
'''
    source = one(source, 'from app.limiter import limiter\n', 'from app.limiter import limiter\n'+imports, 'Server imports')
    source = one(source, '    app.state.start_time = time.time()\n',
                 '    app.state.start_time = time.time()\n    initialize_admin(app)\n', 'Startup account pool')
    anchor = '@app.middleware("http")\nasync def api_key_auth(request: Request, call_next):'
    start = source.find(anchor)
    end = source.find('# 挂载路由，前缀统一为 /v1',start)
    if start < 0 or end <= start:
        raise RuntimeError('Could not locate original API-key middleware: refuse unsafe patch')
    source = source[:start] + '''@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    if request.url.path.startswith("/v1") and request.method != "OPTIONS":
        return await authenticate_api_request(request, call_next)
    return await call_next(request)

''' + source[end:]
    source = one(source, 'app.include_router(models_router, prefix="/v1")\n',
                 'app.include_router(models_router, prefix="/v1")\napp.include_router(admin_router, prefix="/admin/api")\n',
                 'Admin routes')
    ast.parse(source)
    return source


def patch_models(source):
    if START_MARKER in source:
        return source
    source = one(source, 'from fastapi import APIRouter\n',
                 'from fastapi import APIRouter, Request\n'+START_MARKER+'\n'+END_MARKER+'\n', 'Model Request import')
    source = one(source, 'async def list_models() -> Dict[str, Any]:',
                 'async def list_models(request: Request) -> Dict[str, Any]:', 'Model list endpoint')
    source = one(source, '            for model_id in list_available_models()\n',
                 '            for model_id in list_available_models()\n'
                 '            if request.app.state.admin_store.model_allowed(model_id, getattr(request.state,"admin_key",None))\n',
                 'Model authorization filter')
    ast.parse(source)
    return source


def password_hash(password):
    if len(password) < 14:
        raise RuntimeError('Admin password must contain at least 14 characters')
    salt = secrets.token_bytes(20)
    n = 440000
    digest = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,n)
    return 'pbkdf2_sha256$%d$%s$%s' % (n,salt.hex(),digest.hex())


def read_env(source):
    result = {}
    for line in source.splitlines():
        if line and not line.lstrip().startswith('#') and '=' in line:
            k,v = line.split('=',1)
            result[k.strip()] = v.strip()
    return result


def env_install(source, password, allow_http):
    vars = read_env(source)
    additions = []
    if not vars.get('ADMIN_FERNET_KEY'):
        fernet_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii')
        additions.append('ADMIN_FERNET_KEY='+fernet_key)
    if not vars.get('ADMIN_PASSWORD_HASH'):
        if not password:
            raise RuntimeError('Admin password must be supplied for initial install')
        additions.append('ADMIN_PASSWORD_HASH='+password_hash(password))
    if not vars.get('ADMIN_ALLOW_INSECURE_HTTP'):
        additions.append('ADMIN_ALLOW_INSECURE_HTTP='+('1' if allow_http else '0'))
    return source.rstrip() + ('\n\n# Notion2API Personal Admin (protect this file)\n'+'\n'.join(additions)+'\n' if additions else '\n')


def fetch_files(ref):
    results = {}
    for local,remote in FILES.items():
        url = RAW + ref + '/' + remote
        with urlopen(url, timeout=25) as response:
            content = response.read(500000)
        text = content.decode('utf-8')
        if not text and not local.endswith('__init__.py'):
            raise RuntimeError('Empty downloaded file: '+url)
        if local.endswith('.py'):
            ast.parse(text, filename=local)
        results[local] = text
    return results


def make_backup(paths):
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    folder = ROOT/'backups'/('admin_'+stamp)
    folder.mkdir(parents=True,exist_ok=False)
    os.chmod(folder,0o700)
    manifest = {}
    for item in paths:
        p = ROOT/item
        manifest[item] = p.is_file()
        if p.is_file():
            dest = folder/item
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(p,dest)
            os.chmod(dest,0o600)
    (folder/'manifest.json').write_text(json.dumps(manifest, indent=2),encoding='utf-8')
    return folder


def install(ref, password, allow_http):
    for p in EXISTING:
        if not (ROOT/p).is_file():
            raise RuntimeError('Run this script from the root of your EXISTING notion2api clone; missing '+p)
    original = {p:(ROOT/p).read_text(encoding='utf-8') for p in EXISTING}
    print('Fetching admin source from your GitHub repository ...')
    source = fetch_files(ref)
    original['app/server.py'] = patch_server(original['app/server.py'])
    original['app/api/models.py'] = patch_models(original['app/api/models.py'])
    requirements = original['requirements.txt']
    if not any(line.strip().startswith('cryptography') for line in requirements.splitlines()):
        requirements += '\ncryptography>=42,<48\n'
    original['requirements.txt'] = requirements
    env = read_env(original['.env'])
    if not env.get('ADMIN_PASSWORD_HASH') and not password:
        password = getpass.getpass('New admin password (14+ characters, hidden): ')
        if password != getpass.getpass('Repeat admin password: '):
            raise RuntimeError('Passwords do not match. No files changed.')
    original['.env'] = env_install(original['.env'],password,allow_http)
    for p in ('app/server.py','app/api/models.py'):
        ast.parse(original[p],filename=p)
    backup = make_backup(EXISTING+list(FILES))
    for p,value in {**original,**source}.items():
        target = ROOT/p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value,encoding='utf-8')
    os.chmod(ROOT/'.env',0o600)
    print('INSTALLED: admin routes, encrypted account vault, per-key quotas, model switches')
    print('BACKUP_DIR='+str(backup))
    print('ADMIN_URL=/admin/')
    print('ADMIN_HTTPS_REQUIRED='+('no (explicit HTTP opt-in)' if read_env(original['.env']).get('ADMIN_ALLOW_INSECURE_HTTP')=='1' else 'yes'))
    print('NEXT: docker compose config -q && docker compose up -d --build --force-recreate notion-ai')


def rollback():
    root = ROOT/'backups'
    backups = sorted([p for p in root.glob('admin_*') if (p/'manifest.json').is_file()])
    if not backups:
        raise RuntimeError('No admin backup found')
    backup = backups[-1]
    manifest = json.loads((backup/'manifest.json').read_text(encoding='utf-8'))
    for name, existed in manifest.items():
        target = ROOT/name
        if name == '.env':
            # Preserve the encryption key needed to reopen the existing admin DB.
            # The original app ignores the extra ADMIN_* environment variables.
            continue
        if existed:
            src = backup/name
            if not src.is_file():
                raise RuntimeError('Backup incomplete, aborting rollback: '+name)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(src,target)
        elif target.is_file():
            target.unlink()
    print('RESTORED_FROM='+str(backup))
    print('Retained encrypted admin data and ADMIN_FERNET_KEY in .env for safe reinstall.')
    print('NEXT: docker compose up -d --build --force-recreate notion-ai')


def check():
    for name in ('app/admin/store.py','app/admin/routes.py','frontend/admin/index.html'):
        if not (ROOT/name).is_file():
            raise RuntimeError('Not installed: '+name)
    assert START_MARKER in (ROOT/'app/server.py').read_text()
    assert 'admin_store.model_allowed' in (ROOT/'app/api/models.py').read_text()
    print('CHECK OK: admin integration present and original Notion files retained')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    action = ap.add_mutually_exclusive_group()
    action.add_argument('--rollback',action='store_true')
    action.add_argument('--check',action='store_true')
    ap.add_argument('--ref',default='main',help='Git commit SHA or branch to fetch admin files from')
    ap.add_argument('--allow-http',action='store_true',help='Unsafe: allow admin login over unencrypted public HTTP')
    args = ap.parse_args()
    try:
        if args.rollback: rollback()
        elif args.check: check()
        else: install(args.ref,None,args.allow_http)
    except Exception as e:
        print('INSTALL ERROR:',e,file=sys.stderr)
        sys.exit(1)