"""Persistent configuration, API-key quotas and audit records for Notion2API Admin.

No message text, bearer secret, session token or Notion token is stored in cleartext.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet


class AdminError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def password_hash(password: str) -> str:
    if len(password) < 14:
        raise AdminError('管理员密码至少 14 个字符')
    salt = secrets.token_bytes(20)
    rounds = 440000
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds)
    return 'pbkdf2_sha256$%d$%s$%s' % (rounds, salt.hex(), key.hex())


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, digest = encoded.split('$')
        if scheme != 'pbkdf2_sha256' or int(rounds) < 200000:
            return False
        calculated = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(calculated, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def _utc_day_start(timestamp: int) -> int:
    return int(datetime.fromtimestamp(timestamp, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def _utc_month_start(timestamp: int) -> int:
    return int(datetime.fromtimestamp(timestamp, timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


class AdminStore:
    def __init__(self, path: str, fernet_key: str, boot_password_hash: str, legacy_accounts: list[dict]):
        if not fernet_key or not boot_password_hash:
            raise RuntimeError('ADMIN_FERNET_KEY and ADMIN_PASSWORD_HASH must be configured')
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.crypto = Fernet(fernet_key.encode('ascii'))
        self.lock = threading.RLock()
        self._init_schema()
        self._bootstrap(boot_password_hash, legacy_accounts)

    @contextmanager
    def db(self):
        con = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA busy_timeout=15000')
        con.execute('PRAGMA foreign_keys=ON')
        try:
            yield con
        finally:
            con.close()

    def _init_schema(self):
        with self.db() as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.executescript('''
                CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, label TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
                    encrypted TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL, last_test_at INTEGER, last_test_result TEXT
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY, label TEXT NOT NULL, prefix TEXT NOT NULL,
                    secret_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
                    daily_limit INTEGER NOT NULL DEFAULT 0, monthly_limit INTEGER NOT NULL DEFAULT 0,
                    rpm_limit INTEGER NOT NULL DEFAULT 0, allowed_models TEXT NOT NULL DEFAULT '[]',
                    expires_at INTEGER, created_at INTEGER NOT NULL, last_used_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS usage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT,
                    model TEXT NOT NULL, at INTEGER NOT NULL, status INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER, FOREIGN KEY(key_id) REFERENCES api_keys(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_usage_key_time ON usage_events(key_id, at);
                CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_events(at);
                CREATE TABLE IF NOT EXISTS model_flags (
                    id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS custom_models (
                    id TEXT PRIMARY KEY, upstream_code TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_audits_time ON audits(at);
            ''')

    def _bootstrap(self, pwd_hash: str, legacy_accounts: list[dict]):
        with self.lock, self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                c.execute('INSERT OR IGNORE INTO meta(name,value) VALUES (?,?)', ('password_hash', pwd_hash))
                total = c.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]
                if total == 0:
                    for index, item in enumerate(legacy_accounts):
                        if all(item.get(field) for field in ('token_v2', 'space_id', 'user_id')):
                            self._insert_account(c, item, item.get('profile_name') or ('Imported account %d' % (index + 1)), True)
                c.execute('COMMIT')
            except Exception:
                c.execute('ROLLBACK')
                raise

    def _encrypt(self, value: dict) -> str:
        return self.crypto.encrypt(json.dumps(value, ensure_ascii=False).encode()).decode('ascii')

    def _decrypt(self, value: str) -> dict:
        return json.loads(self.crypto.decrypt(value.encode('ascii')).decode())

    def _insert_account(self, c, account: dict, label: str, enabled: bool):
        account_id = secrets.token_hex(12)
        c.execute('INSERT INTO accounts VALUES (?,?,?,?,?,?,NULL,NULL)',
                  (account_id, label, str(account.get('user_email') or ''), self._encrypt(account), int(enabled), int(time.time())))
        return account_id

    def audit(self, action: str, target: str, detail: str = ''):
        with self.db() as c:
            c.execute('INSERT INTO audits(at,action,target,detail) VALUES (?,?,?,?)',
                      (int(time.time()), action, target, detail[:300]))

    def list_accounts(self) -> list[dict]:
        with self.db() as c:
            rows = c.execute('SELECT id,label,email,enabled,created_at,last_test_at,last_test_result FROM accounts ORDER BY created_at,id').fetchall()
        return [dict(row) for row in rows]

    def enabled_accounts(self) -> list[dict]:
        with self.db() as c:
            rows = c.execute('SELECT encrypted FROM accounts WHERE enabled=1 ORDER BY created_at,id').fetchall()
        return [self._decrypt(row['encrypted']) for row in rows]

    def get_account_credentials(self, account_id: str) -> dict:
        with self.db() as c:
            row = c.execute('SELECT encrypted FROM accounts WHERE id=?', (account_id,)).fetchone()
        if not row:
            raise AdminError('账号不存在', 404)
        return self._decrypt(row['encrypted'])

    @staticmethod
    def validate_credentials(item: dict):
        if not isinstance(item, dict):
            raise AdminError('账号必须是 JSON 对象')
        for key in ('token_v2', 'space_id', 'user_id'):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise AdminError('缺少账号字段：' + key)
        for key, value in item.items():
            if isinstance(value, str) and len(value) > 12000:
                raise AdminError('账号字段过长：' + key)
        if item.get('cookies') is not None and not isinstance(item['cookies'], dict):
            raise AdminError('cookies 必须是 JSON 对象')

    def add_account(self, item: dict, label: str, enabled: bool = True) -> str:
        self.validate_credentials(item)
        label = label.strip()[:120]
        if not label:
            raise AdminError('必须填写账号名称')
        with self.lock, self.db() as c:
            aid = self._insert_account(c, item, label, enabled)
        self.audit('account.create', aid)
        return aid

    def update_account(self, aid: str, *, label=None, enabled=None, credentials=None):
        with self.lock, self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row = c.execute('SELECT * FROM accounts WHERE id=?', (aid,)).fetchone()
                if not row:
                    raise AdminError('账号不存在', 404)
                newlabel = (label.strip()[:120] if label is not None else row['label'])
                if not newlabel:
                    raise AdminError('账号名称不能为空')
                newenabled = int(enabled) if enabled is not None else row['enabled']
                if not newenabled and row['enabled'] and c.execute('SELECT COUNT(*) FROM accounts WHERE enabled=1').fetchone()[0] <= 1:
                    raise AdminError('必须保留至少一个已启用账号')
                newcreds = self._decrypt(row['encrypted'])
                if credentials:
                    newcreds.update({k: v for k, v in credentials.items() if v is not None and v != ''})
                    self.validate_credentials(newcreds)
                c.execute('UPDATE accounts SET label=?,enabled=?,encrypted=?,email=? WHERE id=?',
                          (newlabel, newenabled, self._encrypt(newcreds), str(newcreds.get('user_email') or ''), aid))
                c.execute('COMMIT')
            except Exception:
                c.execute('ROLLBACK')
                raise
        self.audit('account.update', aid)

    def delete_account(self, aid: str):
        with self.lock, self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row = c.execute('SELECT enabled FROM accounts WHERE id=?', (aid,)).fetchone()
                if not row:
                    raise AdminError('账号不存在', 404)
                if row['enabled'] and c.execute('SELECT COUNT(*) FROM accounts WHERE enabled=1').fetchone()[0] <= 1:
                    raise AdminError('无法删除最后一个已启用账号')
                c.execute('DELETE FROM accounts WHERE id=?', (aid,))
                c.execute('COMMIT')
            except Exception:
                c.execute('ROLLBACK')
                raise
        self.audit('account.delete', aid)

    def record_test(self, aid: str, result: str):
        with self.db() as c:
            c.execute('UPDATE accounts SET last_test_at=?,last_test_result=? WHERE id=?', (int(time.time()), result[:180], aid))

    def login(self, password: str) -> tuple[str, str]:
        with self.db() as c:
            row = c.execute("SELECT value FROM meta WHERE name='password_hash'").fetchone()
            if not row or not verify_password(password, row['value']):
                raise AdminError('管理员密码错误', 401)
            token = secrets.token_urlsafe(42)
            csrf = _hash('admin-csrf:' + token)
            now = int(time.time())
            c.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
            c.execute('INSERT INTO sessions VALUES (?,?,?,?)', (_hash(token), _hash(csrf), now, now + 7*86400))
        self.audit('admin.login', 'admin')
        return token, csrf

    def authorize_session(self, token: str, csrf: str | None = None) -> bool:
        if not token:
            return False
        with self.db() as c:
            row = c.execute('SELECT csrf_hash FROM sessions WHERE token_hash=? AND expires_at>?', (_hash(token), int(time.time()))).fetchone()
        if not row:
            return False
        return csrf is None or hmac.compare_digest(row['csrf_hash'], _hash(csrf))

    def session_csrf(self, token: str) -> str | None:
        if not self.authorize_session(token):
            return None
        return _hash('admin-csrf:' + token)

    def logout(self, token: str):
        with self.db() as c:
            c.execute('DELETE FROM sessions WHERE token_hash=?', (_hash(token),))

    def change_password(self, old: str, new: str, token: str):
        with self.db() as c:
            row = c.execute("SELECT value FROM meta WHERE name='password_hash'").fetchone()
            if not row or not verify_password(old, row['value']):
                raise AdminError('原密码错误', 403)
            c.execute('UPDATE meta SET value=? WHERE name=?', (password_hash(new), 'password_hash'))
            c.execute('DELETE FROM sessions WHERE token_hash<>?', (_hash(token),))
        self.audit('admin.password_changed', 'admin')

    def create_key(self, label: str, daily_limit=0, monthly_limit=0, rpm_limit=0, models=None, expires_at=None) -> dict:
        label = str(label or '').strip()[:120]
        if not label:
            raise AdminError('需要 API Key 名称')
        for name, value in (('每日', daily_limit), ('每月', monthly_limit), ('每分钟', rpm_limit)):
            if type(value) is not int or value < 0 or value > 10000000:
                raise AdminError(name + '限额必须是非负整数（0 表示不限制）')
        if expires_at is not None and (type(expires_at) is not int or expires_at <= int(time.time())):
            raise AdminError('到期时间必须是未来的 Unix 秒时间戳')
        if not isinstance(models, list) and models is not None:
            raise AdminError('模型权限必须是模型 ID 数组')
        allowed = list(dict.fromkeys(models or []))
        if any(not isinstance(mid, str) or len(mid) > 130 for mid in allowed):
            raise AdminError('模型 ID 不合法')
        from app.model_registry import is_supported_model
        if any(not is_supported_model(mid) for mid in allowed):
            raise AdminError('模型权限包含未注册的模型 ID')
        raw = 'n2a_' + secrets.token_urlsafe(38)
        kid = secrets.token_hex(12)
        now = int(time.time())
        with self.db() as c:
            c.execute('INSERT INTO api_keys VALUES (?,?,?,?,1,?,?,?,?,?,?,NULL)',
                      (kid, label, raw[:12], _hash(raw), daily_limit, monthly_limit, rpm_limit, json.dumps(allowed), expires_at, now))
        self.audit('key.create', kid, label)
        return {'id': kid, 'secret': raw}

    def list_keys(self) -> list[dict]:
        with self.db() as c:
            rows = c.execute('SELECT id,label,prefix,enabled,daily_limit,monthly_limit,rpm_limit,allowed_models,expires_at,created_at,last_used_at FROM api_keys ORDER BY created_at DESC,id DESC').fetchall()
        result = []
        now = int(time.time())
        for row in rows:
            obj = {**dict(row), 'allowed_models': json.loads(row['allowed_models'])}
            with self.db() as c:
                obj['day_used'] = c.execute('SELECT COUNT(*) FROM usage_events WHERE key_id=? AND at>=?',
                                            (row['id'], _utc_day_start(now))).fetchone()[0]
                obj['month_used'] = c.execute('SELECT COUNT(*) FROM usage_events WHERE key_id=? AND at>=?',
                                              (row['id'], _utc_month_start(now))).fetchone()[0]
            result.append(obj)
        return result

    def update_key(self, kid: str, values: dict):
        allowed_fields = {'label','enabled','daily_limit','monthly_limit','rpm_limit','allowed_models','expires_at'}
        if not values or any(k not in allowed_fields for k in values):
            raise AdminError('API Key 修改字段不合法')
        with self.lock, self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row = c.execute('SELECT * FROM api_keys WHERE id=?', (kid,)).fetchone()
                if not row:
                    raise AdminError('API Key 不存在', 404)
                merged = dict(row)
                merged.update(values)
                if not str(merged['label']).strip():
                    raise AdminError('API Key 名称不能为空')
                for f in ('daily_limit','monthly_limit','rpm_limit'):
                    if type(merged[f]) is not int or not 0 <= merged[f] <= 10000000:
                        raise AdminError('无效限额：' + f)
                if type(merged['enabled']) not in (int,bool):
                    raise AdminError('启用状态不合法')
                allowed = merged['allowed_models']
                if isinstance(allowed, str):
                    allowed = json.loads(allowed)
                if not isinstance(allowed,list) or any(not isinstance(x,str) for x in allowed):
                    raise AdminError('模型权限不合法')
                from app.model_registry import is_supported_model
                if any(not is_supported_model(x) for x in allowed):
                    raise AdminError('模型权限包含未注册的模型 ID')
                exp = merged['expires_at']
                if exp is not None and type(exp) is not int:
                    raise AdminError('到期时间不合法')
                c.execute('UPDATE api_keys SET label=?,enabled=?,daily_limit=?,monthly_limit=?,rpm_limit=?,allowed_models=?,expires_at=? WHERE id=?',
                    (str(merged['label'])[:120],int(bool(merged['enabled'])),merged['daily_limit'],merged['monthly_limit'],merged['rpm_limit'],json.dumps(allowed),exp,kid))
                c.execute('COMMIT')
            except Exception:
                c.execute('ROLLBACK')
                raise
        self.audit('key.update', kid)

    def revoke_key(self, kid: str):
        with self.db() as c:
            if not c.execute('UPDATE api_keys SET enabled=0 WHERE id=?', (kid,)).rowcount:
                raise AdminError('API Key 不存在', 404)
        self.audit('key.revoke', kid)

    def delete_key(self, kid: str):
        with self.db() as c:
            if not c.execute('DELETE FROM api_keys WHERE id=?', (kid,)).rowcount:
                raise AdminError('API Key 不存在', 404)
        self.audit('key.delete', kid)

    def key_from_bearer(self, raw: str) -> dict | None:
        if not raw or len(raw) > 512:
            return None
        with self.db() as c:
            row = c.execute('SELECT * FROM api_keys WHERE secret_hash=? AND enabled=1 AND (expires_at IS NULL OR expires_at>?)',
                            (_hash(raw), int(time.time()))).fetchone()
        return dict(row) if row else None

    def enabled_model_ids(self) -> set[str]:
        with self.db() as c:
            rows = c.execute('SELECT id FROM model_flags WHERE enabled=0').fetchall()
        return {row['id'] for row in rows}

    def model_allowed(self, model: str, key: dict | None = None) -> bool:
        from app.model_registry import is_supported_model
        disabled = self.enabled_model_ids()
        base = model.split('-effort-', 1)[0]
        if not is_supported_model(model) or model in disabled or base in disabled:
            return False
        if key is None:
            return True
        allowed = json.loads(key['allowed_models'])
        return not allowed or model in allowed

    def list_models(self) -> list[dict]:
        from app.model_registry import MODEL_MAP, get_display_name
        disabled = self.enabled_model_ids()
        with self.db() as c:
            customs = {row['id'] for row in c.execute('SELECT id FROM custom_models').fetchall()}
        return [{'id':mid,'name':get_display_name(mid),'code':code,'enabled':mid not in disabled,
                 'custom':mid in customs, 'effort_variant':'-effort-' in mid}
                for mid,code in MODEL_MAP.items()]

    def update_model(self, mid: str, enabled: bool):
        from app.model_registry import is_supported_model
        if not is_supported_model(mid):
            raise AdminError('模型不存在', 404)
        with self.db() as c:
            c.execute('INSERT INTO model_flags(id,enabled) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled',
                      (mid, int(bool(enabled))))
        self.audit('model.set_enabled', mid, str(bool(enabled)))

    def add_custom_model(self, mid: str, code: str, display: str):
        import re
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,90}', mid or ''):
            raise AdminError('模型 ID 只能包含小写字母、数字、点、下划线或短横线')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{1,150}', code or ''):
            raise AdminError('Notion 内部代号不合法')
        if not (display or '').strip():
            raise AdminError('缺少模型显示名称')
        from app.model_registry import MODEL_MAP
        if mid in MODEL_MAP or code in MODEL_MAP.values():
            raise AdminError('模型 ID 或内部代号已存在', 409)
        with self.db() as c:
            try:
                c.execute('INSERT INTO custom_models VALUES (?,?,?,1)', (mid,code,display[:120]))
            except sqlite3.IntegrityError as exc:
                raise AdminError('重复的自定义模型', 409) from exc
        self.reload_custom_models()
        self.audit('model.create',mid)

    def delete_custom_model(self, mid: str):
        with self.db() as c:
            if not c.execute('DELETE FROM custom_models WHERE id=?', (mid,)).rowcount:
                raise AdminError('只能删除自定义模型', 404)
            c.execute('DELETE FROM model_flags WHERE id=?', (mid,))
        self.reload_custom_models()
        self.audit('model.delete',mid)

    def reload_custom_models(self):
        from app import model_registry as r
        if not hasattr(self, '_base_model_map'):
            self._base_model_map = dict(r.MODEL_MAP)
            self._base_display_names = dict(r.DISPLAY_NAMES)
            self._base_icons = dict(r.MODEL_ICONS)
        with self.lock, self.db() as c:
            rows = c.execute('SELECT * FROM custom_models').fetchall()
            codes = set(self._base_model_map.values())
            for row in rows:
                if row['id'] in self._base_model_map or row['upstream_code'] in codes:
                    raise RuntimeError('Custom model collides with registered model: ' + row['id'])
                codes.add(row['upstream_code'])
            r.MODEL_MAP.clear(); r.MODEL_MAP.update(self._base_model_map)
            r.DISPLAY_NAMES.clear(); r.DISPLAY_NAMES.update(self._base_display_names)
            r.MODEL_ICONS.clear(); r.MODEL_ICONS.update(self._base_icons)
            for row in rows:
                r.MODEL_MAP[row['id']] = row['upstream_code']
                r.DISPLAY_NAMES[row['id']] = row['display_name']
                r.MODEL_ICONS[row['id']] = '◇'
            r.NOTION_MODEL_REVERSE_MAP.clear()
            r.NOTION_MODEL_REVERSE_MAP.update({code: mid for mid,code in r.MODEL_MAP.items()})

    def reserve_usage(self, key: dict | None, model: str) -> int:
        now = int(time.time())
        kid = key['id'] if key else None
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                if key:
                    latest = c.execute('SELECT enabled,expires_at,daily_limit,monthly_limit,rpm_limit,allowed_models FROM api_keys WHERE id=?', (kid,)).fetchone()
                    if not latest or not latest['enabled'] or (latest['expires_at'] and latest['expires_at'] <= now):
                        raise AdminError('API Key 已停用或已过期', 401)
                    if not self.model_allowed(model, dict(latest)):
                        raise AdminError('此 API Key 无权使用该模型', 403)
                    for quota, after, label in (
                        ('rpm_limit', now-60, '每分钟'),
                        ('daily_limit', _utc_day_start(now), '每日'),
                        ('monthly_limit', _utc_month_start(now), '每月')):
                        limit = latest[quota]
                        if limit:
                            used = c.execute('SELECT COUNT(*) FROM usage_events WHERE key_id=? AND at>=?', (kid,after)).fetchone()[0]
                            if used >= limit:
                                raise AdminError(label + '请求配额已耗尽', 429)
                elif not self.model_allowed(model):
                    raise AdminError('模型已禁用或不存在', 403)
                cur = c.execute('INSERT INTO usage_events(key_id,model,at,status) VALUES (?,?,?,0)', (kid,model,now))
                if kid:
                    c.execute('UPDATE api_keys SET last_used_at=? WHERE id=?', (now,kid))
                c.execute('COMMIT')
                return cur.lastrowid
            except Exception:
                c.execute('ROLLBACK')
                raise

    def finish_usage(self, eid: int, status: int, elapsed: int):
        with self.db() as c:
            c.execute('UPDATE usage_events SET status=?,duration_ms=? WHERE id=?', (status,elapsed,eid))

    def dashboard(self) -> dict:
        now = int(time.time())
        with self.db() as c:
            total = c.execute('SELECT COUNT(*) FROM usage_events').fetchone()[0]
            day = c.execute('SELECT COUNT(*) FROM usage_events WHERE at>=?',(_utc_day_start(now),)).fetchone()[0]
            failed = c.execute('SELECT COUNT(*) FROM usage_events WHERE at>=? AND status>=400', (_utc_day_start(now),)).fetchone()[0]
            keys = c.execute('SELECT COUNT(*) FROM api_keys WHERE enabled=1').fetchone()[0]
            accounts = c.execute('SELECT COUNT(*) FROM accounts WHERE enabled=1').fetchone()[0]
            day_rows = c.execute('SELECT date(at,"unixepoch") AS day,COUNT(*) AS count FROM usage_events WHERE at>=? GROUP BY day ORDER BY day', (now-6*86400,)).fetchall()
            model_rows = c.execute('SELECT model, COUNT(*) AS count FROM usage_events WHERE at>=? GROUP BY model ORDER BY count DESC LIMIT 12', (now-30*86400,)).fetchall()
        return {'accounts':accounts,'keys':keys,'all_requests':total,'today_requests':day,'today_failed_http':failed,
                'daily':[dict(x) for x in day_rows],'by_model':[dict(x) for x in model_rows],
                'note':'统计本地代理接收的调用；流式 HTTP 200 不等于上游完整生成，Notion 官方剩余额度未知。'}

    def recent_usage(self, limit=100) -> list[dict]:
        with self.db() as c:
            rows = c.execute('SELECT u.at,u.model,u.status,u.duration_ms,COALESCE(k.label,"Legacy key") AS key_label FROM usage_events u LEFT JOIN api_keys k ON k.id=u.key_id ORDER BY u.id DESC LIMIT ?', (min(max(int(limit),1),300),)).fetchall()
        return [dict(x) for x in rows]

    def recent_audits(self, limit=100) -> list[dict]:
        with self.db() as c:
            rows = c.execute('SELECT at,action,target,detail FROM audits ORDER BY id DESC LIMIT ?', (min(max(int(limit),1),200),)).fetchall()
        return [dict(x) for x in rows]

    def get_setting(self, name: str, default: str = '') -> str:
        with self.db() as c:
            row = c.execute('SELECT value FROM meta WHERE name=?', ('setting:'+name,)).fetchone()
        return row['value'] if row else default

    def set_setting(self, name: str, value: str):
        if name not in ('legacy_api_key_enabled',):
            raise AdminError('不支持修改该设置')
        if value not in ('0','1'):
            raise AdminError('设置值必须是 0 或 1')
        with self.db() as c:
            c.execute('INSERT INTO meta(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',
                      ('setting:'+name,value))
        self.audit('settings.update',name,value)