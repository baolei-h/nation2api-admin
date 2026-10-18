"""Authenticate every /v1 request and meter only accepted chat-completion calls."""
import hmac
import json
import os
import time
from fastapi.responses import JSONResponse
from app.admin.store import AdminError


def _error(status: int, message: str):
    return JSONResponse(status_code=status, content={
        'error': {'type': 'admin_gateway_error', 'message': message, 'code': status}
    })


async def authenticate_api_request(request, call_next):
    """Used by the existing api_key_auth HTTP middleware in app/server.py."""
    store = getattr(request.app.state, 'admin_store', None)
    if store is None:
        return _error(503, 'Admin gateway is not initialized')
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        return _error(401, '需要 Bearer API Key')
    raw = header[7:].strip()
    legacy = os.getenv('API_KEY', '')
    is_legacy = bool(legacy and store.get_setting('legacy_api_key_enabled', '1') == '1' and hmac.compare_digest(raw, legacy))
    key = None if is_legacy else store.key_from_bearer(raw)
    if not is_legacy and key is None:
        return _error(401, 'API Key 无效、已停用或已过期')
    request.state.admin_key = key

    path = request.url.path
    if path == '/v1/models':
        return await call_next(request)
    if path != '/v1/chat/completions' or request.method != 'POST':
        return await call_next(request)

    try:
        raw_body = await request.body()
        if len(raw_body) > 3_000_000:
            return _error(413, '请求过大')
        body = json.loads(raw_body)
        if not isinstance(body, dict):
            return _error(400, '请求必须是 JSON 对象')
        model = body.get('model', 'claude-opus4.6')
        if not isinstance(model, str) or len(model) > 200:
            return _error(400, '模型 ID 格式不正确')
        event = store.reserve_usage(key, model)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return _error(400, '无效 JSON 请求')
    except AdminError as e:
        return _error(e.status, str(e))

    started = time.monotonic()
    try:
        result = await call_next(request)
        status = result.status_code
        return result
    except Exception:
        status = 500
        raise
    finally:
        store.finish_usage(event, status, int((time.monotonic()-started)*1000))