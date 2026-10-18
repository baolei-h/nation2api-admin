"""Initialize AdminStore and safely replace the running account pool."""
import os
import threading
from pathlib import Path
from app.admin.store import AdminStore
from app.account_pool import AccountPool

_POOL_LOCK = threading.RLock()


def initialize_admin(app):
    from app.config import ACCOUNTS
    root = Path(os.environ.get('DB_PATH', '/app/data/conversations.db')).parent
    store = AdminStore(
        str(root / 'notion_admin.sqlite3'),
        os.getenv('ADMIN_FERNET_KEY', ''),
        os.getenv('ADMIN_PASSWORD_HASH', ''),
        ACCOUNTS,
    )
    app.state.admin_store = store
    store.reload_custom_models()
    reload_pool(app)


def reload_pool(app):
    """Swap the pool, allowing already-running requests to finish on old clients."""
    with _POOL_LOCK:
        credentials = app.state.admin_store.enabled_accounts()
        if not credentials:
            raise RuntimeError('At least one Notion account must remain enabled')
        replacement = AccountPool(credentials)
        app.state.account_pool = replacement
        return len(credentials)