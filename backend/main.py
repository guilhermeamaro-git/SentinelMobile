"""SentinelMobile - Backend (FastAPI + SQLite + HTTPS/TLS)."""
import argparse
import base64
import binascii
import hmac
import json
import logging
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import certs
import db

BASE = Path(__file__).parent
PHOTO_DIR = BASE / "photos"
STATIC_DIR = BASE / "static"
CFG_PATH = BASE / "config.json"
DEFAULT_PORT = 8443
log = logging.getLogger("sentinel")

# ----------------------------------------------------------------- config/tokens
def load_config() -> dict:
    if CFG_PATH.exists():
        try:
            cfg = json.loads(CFG_PATH.read_text())
            if cfg.get("admin_token") and cfg.get("device_token"):
                return cfg
        except ValueError:
            pass
    cfg = {"admin_token": secrets.token_urlsafe(18), "device_token": secrets.token_urlsafe(24)}
    CFG_PATH.write_text(json.dumps(cfg, indent=2))
    return cfg


CFG = load_config()
PHOTO_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

app = FastAPI(title="SentinelMobile", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(Exception)
async def unhandled(request, exc):
    log.exception("Erro nao tratado em %s", request.url.path)
    return JSONResponse({"ok": False, "detail": "erro interno"}, status_code=500)


# ----------------------------------------------------------------- autenticacao
def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def auth_device(authorization: Optional[str] = Header(None),
                x_device_id: Optional[str] = Header(None)) -> str:
    token = authorization or ""
    if token.startswith("Bearer "):
        token = token[7:]
    if not _eq(token.strip(), CFG["device_token"]):
        raise HTTPException(401, "token invalido")
    did = (x_device_id or "").strip()
    if not did or len(did) > 64:
        raise HTTPException(400, "X-Device-Id ausente ou invalido")
    with db.tx() as c:
        db.touch_device(c, did)
    return did


def auth_admin(x_admin_token: Optional[str] = Header(None), t: Optional[str] = Query(None)) -> bool:
    if not _eq(x_admin_token or t or "", CFG["admin_token"]):
        raise HTTPException(401, "token admin invalido")
    return True


# ----------------------------------------------------------------- modelos
class LocationIn(BaseModel):
    event_id: str = Field(..., min_length=8, max_length=64)
    lat: float = Field(..., ge=-90, le=90)
    lon: float = Field(..., ge=-180, le=180)
    accuracy: Optional[float] = Field(None, ge=0)
    ts: Optional[int] = None
    source: str = Field("GPS", max_length=20)


class EventIn(BaseModel):
    event_id: str = Field(..., min_length=8, max_length=64)
    event_type: Literal["PIN_FAIL", "SENSITIVE_APP_OPEN", "PASSWORD_CHANGE"]
    ts: Optional[int] = None
    meta: Optional[str] = Field(None, max_length=200)


class AlertIn(BaseModel):
    event_id: str = Field(..., min_length=8, max_length=64)
    rule_id: str = Field(..., max_length=16)
    ts: Optional[int] = None
    lat: Optional[float] = Field(None, ge=-90, le=90)
    lon: Optional[float] = Field(None, ge=-180, le=180)
    accuracy: Optional[float] = Field(None, ge=0)
    source: Optional[str] = Field(None, max_length=20)
    photo_b64: Optional[str] = Field(None, max_length=5_000_000)
    locked: bool = False
    detail: Optional[str] = Field(None, max_length=300)


class CommandIn(BaseModel):
    command: Literal["LOCK", "UNLOCK"]
    device_id: Optional[str] = None


class SimIn(BaseModel):
    scenario: Literal["R1", "R2", "R3", "PIN_FAIL", "SENSITIVE_APP_OPEN", "PASSWORD_CHANGE", "RESET"]
    device_id: Optional[str] = None


# ----------------------------------------------------------------- utilitarios
def norm_ts(ts: Optional[int]) -> int:
    """Usa o ts do aparelho (hora real do evento, mesmo se veio da fila),
    mas descarta valores invalidos ou no futuro (relogio errado)."""
    now = db.now_ms()
    if not ts or ts <= 0 or ts > now + 60_000:
        return now
    return ts


def decode_photo(b64: str) -> bytes:
    if b64[:64].startswith("data:"):
        b64 = b64.split(",", 1)[-1]
    b64 = "".join(b64.split())
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "foto base64 invalida")
    if len(raw) > 3_000_000 or raw[:2] != b"\xff\xd8":
        raise HTTPException(400, "foto deve ser JPEG de ate 3 MB")
    return raw


def resolve_device(c, device_id: Optional[str], allow_sim: bool = False) -> str:
    if device_id:
        if not c.execute("SELECT 1 FROM devices WHERE device_id=?", (device_id,)).fetchone():
            raise HTTPException(404, "dispositivo nao encontrado")
        return device_id
    row = c.execute("SELECT device_id FROM devices ORDER BY last_seen DESC LIMIT 1").fetchone()
    if row:
        return row["device_id"]
    if allow_sim:
        db.touch_device(c, "SIM-DEVICE")
        return "SIM-DEVICE"
    raise HTTPException(409, "nenhum dispositivo conectado ainda")


def enqueue_command(c, did: str, command: str, origin: str, replace: bool = False):
    if replace:  # comando manual cancela pendencias anteriores
        c.execute("UPDATE commands SET status='cancelled' WHERE device_id=? AND status IN ('pending','sent')", (did,))
    elif c.execute("SELECT 1 FROM commands WHERE device_id=? AND command=? AND status IN ('pending','sent')",
                   (did, command)).fetchone():
        return
    c.execute("INSERT INTO commands(device_id,command,status,created,origin) VALUES(?,?,?,?,?)",
              (did, command, "pending", db.now_ms(), origin))


# ----------------------------------------------------------------- heuristica (servidor)
RULES = {
    "R1": ("ALTA", "Forca bruta de PIN/senha"),
    "R2": ("MEDIA", "Acessos encadeados a apps sensiveis"),
    "R3": ("CRITICA", "Troca de senha seguida de acesso sensivel"),
}


def _count(c, did, etype, lo, hi) -> int:
    return c.execute("SELECT COUNT(*) FROM events WHERE device_id=? AND event_type=? AND ts>? AND ts<=?",
                     (did, etype, lo, hi)).fetchone()[0]


def ingest_event(c, did: str, etype: str, ts: int, meta: Optional[str], cfg: dict) -> List[dict]:
    """Grava o evento e avalia R1/R2/R3 com janela deslizante relativa ao ts do evento."""
    c.execute("INSERT INTO events(device_id,event_type,ts,received,meta) VALUES(?,?,?,?,?)",
              (did, etype, ts, db.now_ms(), meta))
    c.execute("DELETE FROM events WHERE ts < ?", (db.now_ms() - 86_400_000,))

    def window_start(rule: str, secs: int) -> Optional[int]:
        row = c.execute("SELECT last_ts FROM rule_state WHERE device_id=? AND rule_id=?", (did, rule)).fetchone()
        base = row["last_ts"] if row else 0
        if base and 0 <= ts - base < cfg["COOLDOWN_S"] * 1000:
            return None  # em cooldown
        return max(ts - secs * 1000, base)  # contadores "zerados" no ultimo disparo

    hits: List[str] = []
    if etype == "PIN_FAIL":
        lo = window_start("R1", cfg["R1_JANELA_S"])
        if lo is not None and _count(c, did, "PIN_FAIL", lo, ts) > cfg["R1_MAX_FALHAS"]:
            hits.append("R1")
    if etype == "SENSITIVE_APP_OPEN":
        lo = window_start("R2", cfg["R2_JANELA_S"])
        if lo is not None and _count(c, did, "SENSITIVE_APP_OPEN", lo, ts) > cfg["R2_MAX_ACESSOS"]:
            hits.append("R2")
        lo = window_start("R3", cfg["R3_JANELA_S"])
        if lo is not None and _count(c, did, "PASSWORD_CHANGE", lo, ts) >= 1:
            hits.append("R3")

    out = []
    for r in hits:
        sev, desc = RULES[r]
        auto = r in cfg["AUTO_LOCK_RULES"]
        c.execute("INSERT OR REPLACE INTO rule_state(device_id,rule_id,last_ts) VALUES(?,?,?)", (did, r, ts))
        c.execute("""INSERT INTO alerts(device_id,rule_id,severity,ts,received,origin,detail,auto_lock)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (did, r, sev, ts, db.now_ms(), "server", desc + " (reavaliado no servidor)", int(auto)))
        if auto:
            enqueue_command(c, did, "LOCK", "rule:" + r)
        out.append({"rule_id": r, "severity": sev, "auto_lock": auto})
    return out


# ----------------------------------------------------------------- endpoints (dispositivo)
@app.get("/api/v1/health")
def health():
    return {"status": "ok", "server_time": db.now_ms()}


@app.get("/api/v1/config")
def get_config(did: str = Depends(auth_device)):
    with db.tx() as c:
        return db.get_settings(c)


@app.post("/api/v1/location")
def post_location(p: LocationIn, did: str = Depends(auth_device)):
    ts = norm_ts(p.ts)
    with db.tx() as c:
        if not db.mark_seen(c, p.event_id):
            return {"ok": True, "duplicate": True}
        c.execute("INSERT INTO locations(device_id,ts,lat,lon,accuracy,source,received) VALUES(?,?,?,?,?,?,?)",
                  (did, ts, p.lat, p.lon, p.accuracy, p.source, db.now_ms()))
    return {"ok": True, "duplicate": False}


@app.post("/api/v1/events")
def post_event(p: EventIn, did: str = Depends(auth_device)):
    ts = norm_ts(p.ts)
    with db.tx() as c:
        if not db.mark_seen(c, p.event_id):
            return {"ok": True, "duplicate": True, "triggered": []}
        hits = ingest_event(c, did, p.event_type, ts, p.meta, db.get_settings(c))
    return {"ok": True, "duplicate": False, "triggered": hits}


@app.post("/api/v1/alerts")
def post_alert(p: AlertIn, did: str = Depends(auth_device)):
    ts = norm_ts(p.ts)
    photo = decode_photo(p.photo_b64) if p.photo_b64 else None
    sev = RULES.get(p.rule_id, ("MEDIA", ""))[0]
    with db.tx() as c:
        if not db.mark_seen(c, p.event_id):
            return {"ok": True, "duplicate": True}
        # Se o servidor ja gerou o alerta da mesma regra (sem foto), complementa em vez de duplicar
        row = c.execute("""SELECT id FROM alerts WHERE device_id=? AND rule_id=? AND origin='server'
                           AND photo_path IS NULL AND ts BETWEEN ? AND ? ORDER BY id DESC LIMIT 1""",
                        (did, p.rule_id, ts - 60_000, ts + 60_000)).fetchone()
        if row:
            aid = row["id"]
            c.execute("UPDATE alerts SET origin='merged', lat=?, lon=?, accuracy=?, source=?, "
                      "detail=COALESCE(?, detail) WHERE id=?",
                      (p.lat, p.lon, p.accuracy, p.source, p.detail, aid))
        else:
            cur = c.execute("""INSERT INTO alerts(device_id,rule_id,severity,ts,received,lat,lon,accuracy,
                               source,origin,detail,auto_lock) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (did, p.rule_id, sev, ts, db.now_ms(), p.lat, p.lon, p.accuracy, p.source,
                             "device", p.detail, int(p.locked)))
            aid = cur.lastrowid
        if photo:
            name = "alert_%d.jpg" % aid
            (PHOTO_DIR / name).write_bytes(photo)
            c.execute("UPDATE alerts SET photo_path=? WHERE id=?", (name, aid))
        if p.locked:
            c.execute("UPDATE devices SET locked=1 WHERE device_id=?", (did,))
    return {"ok": True, "duplicate": False, "alert_id": aid}


@app.get("/api/v1/commands/poll")
def poll(did: str = Depends(auth_device)):
    now = db.now_ms()
    with db.tx() as c:
        row = c.execute("""SELECT id, command FROM commands WHERE device_id=?
                           AND (status='pending' OR (status='sent' AND sent_ts<?)) ORDER BY id LIMIT 1""",
                        (did, now - 10_000)).fetchone()
        if row:  # 'sent' sem ACK por 10 s volta a ser entregue (resiliencia)
            c.execute("UPDATE commands SET status='sent', sent_ts=? WHERE id=?", (now, row["id"]))
    return {"command": dict(row) if row else None, "server_time": now}


@app.post("/api/v1/commands/{cid}/ack")
def ack(cid: int, did: str = Depends(auth_device)):
    with db.tx() as c:
        row = c.execute("SELECT command, status FROM commands WHERE id=? AND device_id=?", (cid, did)).fetchone()
        if not row:
            raise HTTPException(404, "comando nao encontrado")
        if row["status"] != "done":
            c.execute("UPDATE commands SET status='done', ack_ts=? WHERE id=?", (db.now_ms(), cid))
            c.execute("UPDATE devices SET locked=? WHERE device_id=?",
                      (1 if row["command"] == "LOCK" else 0, did))
    return {"ok": True}


# ----------------------------------------------------------------- endpoints (dashboard)
@app.post("/api/v1/commands")
def create_command(p: CommandIn, _: bool = Depends(auth_admin)):
    with db.tx() as c:
        did = resolve_device(c, p.device_id)
        enqueue_command(c, did, p.command, "dashboard", replace=True)
    return {"ok": True, "device_id": did}


@app.post("/api/v1/sim")
def simulate(p: SimIn, _: bool = Depends(auth_admin)):
    with db.tx() as c:
        did = resolve_device(c, p.device_id, allow_sim=True)
        cfg = db.get_settings(c)
        if p.scenario == "RESET":
            c.execute("DELETE FROM events WHERE device_id=?", (did,))
            c.execute("DELETE FROM rule_state WHERE device_id=?", (did,))
            return {"ok": True, "reset": True, "triggered": []}
        seqs = {
            "R1": ["PIN_FAIL"] * (cfg["R1_MAX_FALHAS"] + 1),
            "R2": ["SENSITIVE_APP_OPEN"] * (cfg["R2_MAX_ACESSOS"] + 1),
            "R3": ["PASSWORD_CHANGE", "SENSITIVE_APP_OPEN"],
        }
        seq = seqs.get(p.scenario, [p.scenario])
        t0, hits = db.now_ms(), []
        for i, et in enumerate(seq):
            hits += ingest_event(c, did, et, t0 + i, "sim", cfg)
    return {"ok": True, "device_id": did, "triggered": hits}


INT_LIMITS = {"R1_MAX_FALHAS": (1, 50), "R1_JANELA_S": (10, 3600), "R2_MAX_ACESSOS": (1, 50),
              "R2_JANELA_S": (10, 3600), "R3_JANELA_S": (10, 3600), "COOLDOWN_S": (0, 600)}


@app.get("/api/v1/settings")
def get_settings(_: bool = Depends(auth_admin)):
    with db.tx() as c:
        return db.get_settings(c)


@app.put("/api/v1/settings")
def put_settings(body: Dict[str, Any], _: bool = Depends(auth_admin)):
    clean: Dict[str, Any] = {}
    for k, v in body.items():
        if k in INT_LIMITS:
            lo, hi = INT_LIMITS[k]
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise HTTPException(400, "%s deve ser inteiro entre %d e %d" % (k, lo, hi))
            clean[k] = v
        elif k == "AUTO_LOCK_RULES":
            if not isinstance(v, list) or not set(v) <= set(RULES):
                raise HTTPException(400, "AUTO_LOCK_RULES invalido")
            clean[k] = sorted(set(v))
        else:
            raise HTTPException(400, "parametro desconhecido: %s" % k)
    with db.tx() as c:
        db.set_settings(c, clean)
        return db.get_settings(c)


@app.get("/api/v1/state")
def state(_: bool = Depends(auth_admin)):
    now = db.now_ms()
    with db.tx() as c:
        def rows(q, a=()):
            return [dict(r) for r in c.execute(q, a).fetchall()]
        devices = rows("SELECT * FROM devices ORDER BY last_seen DESC")
        for d in devices:
            loc = c.execute("SELECT lat,lon,accuracy,source,ts FROM locations WHERE device_id=? "
                            "ORDER BY ts DESC, id DESC LIMIT 1", (d["device_id"],)).fetchone()
            d["last_location"] = dict(loc) if loc else None
            d["online"] = now - d["last_seen"] < 15_000
        return {
            "now": now,
            "devices": devices,
            "alerts": rows("""SELECT id,device_id,rule_id,severity,ts,received,lat,lon,accuracy,source,origin,
                              detail,auto_lock,(photo_path IS NOT NULL) AS has_photo
                              FROM alerts ORDER BY id DESC LIMIT 30"""),
            "locations": rows("SELECT device_id,ts,lat,lon,accuracy,source FROM locations ORDER BY id DESC LIMIT 10"),
            "events": rows("SELECT device_id,event_type,ts,meta FROM events ORDER BY id DESC LIMIT 15"),
            "commands": rows("SELECT id,device_id,command,status,created,origin FROM commands ORDER BY id DESC LIMIT 10"),
            "settings": db.get_settings(c),
        }


@app.get("/api/v1/photos/{alert_id}")
def photo(alert_id: int, _: bool = Depends(auth_admin)):
    with db.tx() as c:
        row = c.execute("SELECT photo_path FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row or not row["photo_path"]:
        raise HTTPException(404, "sem foto")
    p = PHOTO_DIR / row["photo_path"]
    if not p.is_file():
        raise HTTPException(404, "arquivo ausente")
    return FileResponse(p, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})


@app.get("/")
def index():
    f = STATIC_DIR / "index.html"
    if not f.is_file():
        raise HTTPException(404, "static/index.html nao encontrado")
    return FileResponse(f)


# ----------------------------------------------------------------- inicializacao
def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="SentinelMobile backend (HTTPS)")
    ap.add_argument("--ip", nargs="*", default=[], help="IP(s) do PC para o SAN do certificado")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--regen-cert", action="store_true", help="forca novo certificado")
    args = ap.parse_args()

    db.init()
    try:
        crt, key, ips, fp, regen = certs.ensure_cert(args.ip, force=args.regen_cert)
    except ValueError as e:
        sys.exit("IP invalido em --ip: %s" % e)

    host_ip = (args.ip[0] if args.ip else (ips[0] if ips else "127.0.0.1"))
    print("=" * 66)
    print(" SentinelMobile backend")
    print("=" * 66)
    print(" Certificado:", "NOVO (recopie para o app!)" if regen else "reaproveitado")
    print(" IPs no SAN :", ", ".join(ips))
    print(" SHA-256    :", fp)
    print(" Copiar para o Android:", crt)
    print("             -> android/app/src/main/res/raw/sentinel_cert.crt")
    print("-" * 66)
    print(" Dashboard (PC) : https://127.0.0.1:%d/?t=%s" % (args.port, CFG["admin_token"]))
    print(" Dashboard (rede): https://%s:%d/?t=%s" % (host_ip, args.port, CFG["admin_token"]))
    print(" DEVICE_TOKEN (colar no app):", CFG["device_token"])
    print(" Alternativa USB: adb reverse tcp:%d tcp:%d  (app usa 127.0.0.1)" % (args.port, args.port))
    print("=" * 66)

    uvicorn.run(app, host="0.0.0.0", port=args.port, ssl_certfile=str(crt), ssl_keyfile=str(key),
                timeout_keep_alive=5, log_level="info")


if __name__ == "__main__":
    main()