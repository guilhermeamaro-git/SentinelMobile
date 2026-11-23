"""SQLite (arquivo unico) com acesso serializado por lock."""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "sentinel.db"
_LOCK = threading.RLock()

DEFAULTS = {
    "R1_MAX_FALHAS": 3,
    "R1_JANELA_S": 120,
    "R2_MAX_ACESSOS": 3,
    "R2_JANELA_S": 120,
    "R3_JANELA_S": 90,
    "COOLDOWN_S": 30,
    "AUTO_LOCK_RULES": ["R1", "R3"],
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  device_id TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, locked INTEGER DEFAULT 0,
  token_hash TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS ix_devices_token ON devices(token_hash);
CREATE TABLE IF NOT EXISTS pairing_codes(
  code_hash TEXT PRIMARY KEY, created INTEGER, expires INTEGER, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS seen_ids(id TEXT PRIMARY KEY, ts INTEGER);
CREATE TABLE IF NOT EXISTS locations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, ts INTEGER, lat REAL, lon REAL,
  accuracy REAL, source TEXT, received INTEGER);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, event_type TEXT, ts INTEGER,
  received INTEGER, meta TEXT);
CREATE INDEX IF NOT EXISTS ix_events ON events(device_id, event_type, ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, rule_id TEXT, severity TEXT,
  ts INTEGER, received INTEGER, lat REAL, lon REAL, accuracy REAL, source TEXT,
  photo_path TEXT, origin TEXT, detail TEXT, auto_lock INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS commands(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, command TEXT, status TEXT,
  created INTEGER, sent_ts INTEGER, ack_ts INTEGER, origin TEXT);
CREATE TABLE IF NOT EXISTS rule_state(
  device_id TEXT, rule_id TEXT, last_ts INTEGER, PRIMARY KEY(device_id, rule_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def tx():
    """Transacao atomica: commit se OK, rollback se qualquer excecao."""
    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _migrate(conn: sqlite3.Connection):
    """Atualiza bancos criados por versoes antigas (antes do token por aparelho)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
    if cols and "token_hash" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN token_hash TEXT")


def init():
    conn = _connect()
    _migrate(conn)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def mark_seen(c, id_: str) -> bool:
    """Idempotencia: True se o id e novo, False se ja foi processado."""
    cur = c.execute("INSERT OR IGNORE INTO seen_ids(id, ts) VALUES(?, ?)", (id_, now_ms()))
    return cur.rowcount == 1


def touch_device(c, device_id: str):
    n = now_ms()
    c.execute("INSERT OR IGNORE INTO devices(device_id, first_seen, last_seen) VALUES(?,?,?)",
              (device_id, n, n))
    c.execute("UPDATE devices SET last_seen=? WHERE device_id=?", (n, device_id))


def get_settings(c) -> dict:
    out = dict(DEFAULTS)
    for r in c.execute("SELECT key, value FROM settings").fetchall():
        try:
            if r["key"] in out:
                out[r["key"]] = json.loads(r["value"])
        except ValueError:
            pass
    return out


def set_settings(c, values: dict):
    for k, v in values.items():
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, json.dumps(v)))