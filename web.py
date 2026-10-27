"""
FaiLive2 Cloud — Single-file Web VPS Panel
Run:  uvicorn web:app --host 0.0.0.0 --port 3000
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import re
import secrets
import shlex
import sqlite3
import string
from datetime import datetime, timedelta
from typing import Optional

from fastapi import (
    Depends, FastAPI, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.hash import bcrypt
from jinja2 import Environment, BaseLoader


# ============================================================================
#  CONFIG
# ============================================================================
SECRET_KEY       = os.getenv("SECRET_KEY", "change-me")
ADMIN_EMAIL      = os.getenv("ADMIN_EMAIL", "admin@localhost")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD", "changeme")
PUBLIC_IP        = os.getenv("PUBLIC_IP", "127.0.0.1")
LXC_STORAGE_POOL = os.getenv("LXC_STORAGE_POOL", "default")
MAX_VPS_PER_USER = int(os.getenv("MAX_VPS_PER_USER", "3"))
APP_NAME         = "FaiLive2 Cloud"
DB_PATH          = "failive2.db"
COOKIE           = "fl_session"
ALGO             = "HS256"
ALLOWED_OS = [
    ("Ubuntu 22.04 LTS", "ubuntu:22.04"),
    ("Ubuntu 24.04 LTS", "ubuntu:24.04"),
    ("Debian 12 (Bookworm)", "images:debian/12"),
    ("Debian 13 (Trixie)", "images:debian/13"),
]
ALLOWED_OS_VALUES = {v for _, v in ALLOWED_OS}


# ============================================================================
#  DATABASE
# ============================================================================
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    c = get_db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        container TEXT UNIQUE NOT NULL,
        os_image TEXT NOT NULL,
        ram_mb INTEGER NOT NULL,
        cpu INTEGER NOT NULL,
        disk_gb INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'created',
        root_password TEXT DEFAULT '',
        pinggy_address TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS port_forwards(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vps_id INTEGER NOT NULL,
        vps_port INTEGER NOT NULL,
        host_port INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT
    );
    """)
    if not c.execute("SELECT 1 FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone():
        c.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
                  (ADMIN_EMAIL, bcrypt.hash(ADMIN_PASSWORD), "admin", datetime.utcnow().isoformat()))
    c.commit(); c.close()


def audit(actor: str, action: str, detail: str = ""):
    c = get_db()
    c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
              (datetime.utcnow().isoformat(), actor, action, detail))
    c.commit(); c.close()


def user_by_email(email): return get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
def user_by_id(uid):     return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
def list_users():        return get_db().execute("SELECT id,email,role,created_at FROM users ORDER BY id").fetchall()

def create_user(email: str, pw: str, role: str = "user"):
    c = get_db()
    c.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
              (email, bcrypt.hash(pw), role, datetime.utcnow().isoformat()))
    c.commit(); c.close()

def vps_count_for_user(uid: int) -> int:
    return get_db().execute("SELECT COUNT(*) FROM vps WHERE user_id=?", (uid,)).fetchone()[0]

def list_vps(uid: Optional[int] = None):
    if uid is None:
        return get_db().execute(
            "SELECT v.*, u.email FROM vps v JOIN users u ON u.id=v.user_id ORDER BY v.id DESC"
        ).fetchall()
    return get_db().execute(
        "SELECT v.*, u.email FROM vps v JOIN users u ON u.id=v.user_id WHERE v.user_id=? ORDER BY v.id DESC",
        (uid,)
    ).fetchall()

def get_vps(vid: int):
    return get_db().execute(
        "SELECT v.*, u.email FROM vps v JOIN users u ON u.id=v.user_id WHERE v.id=?", (vid,)
    ).fetchone()

def insert_vps(uid, container, os_image, ram_mb, cpu, disk_gb, pw, pinggy) -> int:
    c = get_db()
    cur = c.execute(
        "INSERT INTO vps(user_id,container,os_image,ram_mb,cpu,disk_gb,status,root_password,pinggy_address,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uid, container, os_image, ram_mb, cpu, disk_gb, "running", pw, pinggy, datetime.utcnow().isoformat())
    )
    vid = cur.lastrowid; c.commit(); c.close(); return vid

def update_vps(vid: int, **fields):
    if not fields: return
    keys = ",".join(f"{k}=?" for k in fields)
    c = get_db()
    c.execute(f"UPDATE vps SET {keys} WHERE id=?", (*fields.values(), vid))
    c.commit(); c.close()

def delete_vps_row(vid: int):
    c = get_db()
    c.execute("DELETE FROM vps WHERE id=?", (vid,))
    c.execute("DELETE FROM port_forwards WHERE vps_id=?", (vid,))
    c.commit(); c.close()

def list_forwards(vid: int):
    return get_db().execute("SELECT * FROM port_forwards WHERE vps_id=? ORDER BY id DESC", (vid,)).fetchall()

def add_forward(vid, vp, hp):
    c = get_db()
    c.execute("INSERT INTO port_forwards(vps_id,vps_port,host_port,created_at) VALUES(?,?,?,?)",
              (vid, vp, hp, datetime.utcnow().isoformat()))
    c.commit(); c.close()

def delete_forward(fid: int):
    c = get_db()
    row = c.execute("SELECT * FROM port_forwards WHERE id=?", (fid,)).fetchone()
    c.execute("DELETE FROM port_forwards WHERE id=?", (fid,))
    c.commit(); c.close(); return row


# ============================================================================
#  LXC DRIVER
# ============================================================================
def gen_password(n=16) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


async def _run(*args: str, timeout: int = 120) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait(); raise RuntimeError(f"timeout: {' '.join(args)}")
    if proc.returncode != 0:
        raise RuntimeError(err.decode().strip() or f"failed: {' '.join(args)}")
    return out.decode().strip()


async def lxc(*parts: str, timeout: int = 120) -> str:
    return await _run("lxc", *parts, timeout=timeout)


async def _apply_config(container: str):
    await lxc("config", "set", container, "security.nesting", "true")
    await lxc("config", "set", container, "security.privileged", "false")
    try:
        await lxc("config", "device", "add", container, "fuse", "unix-char", "path=/dev/fuse")
    except RuntimeError:
        pass


async def _apply_internal(container: str):
    for cmd in [
        "mkdir -p /etc/sysctl.d",
        "echo net.ipv4.ip_unprivileged_port_start=0 > /etc/sysctl.d/99-fl.conf",
        "sysctl -p /etc/sysctl.d/99-fl.conf || true",
    ]:
        try:
            await lxc("exec", container, "--", "bash", "-c", cmd, timeout=120)
        except RuntimeError:
            pass


async def lxc_create(uid: int, os_image: str, ram_gb: int, cpu: int,
                     disk_gb: int, container: str) -> tuple[str, str]:
    await lxc("init", os_image, container, "-s", LXC_STORAGE_POOL, timeout=900)
    await lxc("config", "set", container, "limits.memory", f"{ram_gb*1024}MB")
    await lxc("config", "set", container, "limits.cpu", str(cpu))
    await lxc("config", "device", "set", container, "root", f"size={disk_gb}GB")
    await _apply_config(container)
    await lxc("start", container, timeout=300)
    await _apply_internal(container)

    password = gen_password()
    for cmd in [
        "DEBIAN_FRONTEND=noninteractive apt-get update -y",
        "DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server",
        f"echo 'root:{password}' | chpasswd",
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config",
        "systemctl restart ssh || service ssh restart || true",
    ]:
        try:
            await lxc("exec", container, "--", "bash", "-c", cmd, timeout=300)
        except RuntimeError:
            pass

    pinggy = ""
    try:
        pinggy = await pinggy_establish(container) or ""
    except Exception:
        pass
    return password, pinggy


async def lxc_start(container: str):
    try:
        await lxc("start", container, timeout=180)
    except RuntimeError as e:
        if "already running" not in str(e).lower():
            raise


async def lxc_stop(container: str):
    await lxc("stop", container, timeout=180)


async def lxc_delete(container: str):
    try:
        await lxc("delete", container, "--force", timeout=180)
    except RuntimeError as e:
        if "not found" not in str(e).lower():
            raise


async def lxc_reinstall(row) -> str:
    await lxc_delete(row["container"])
    pw, _ = await lxc_create(row["user_id"], row["os_image"],
                             row["ram_mb"] // 1024, row["cpu"], row["disk_gb"], row["container"])
    return pw


async def lxc_status(container: str) -> str:
    try:
        out = await lxc("info", container, timeout=20)
        for line in out.splitlines():
            if line.startswith("Status:"):
                return line.split(":", 1)[1].strip().lower()
    except RuntimeError:
        pass
    return "unknown"


async def lxc_stats(container: str) -> dict:
    st = await lxc_status(container)
    if st != "running":
        return {"status": st, "cpu": 0.0, "ram_used": 0, "ram_total": 0, "ram_pct": 0.0, "disk": "—"}
    cpu = 0.0
    try:
        out = await lxc("exec", container, "--", "top", "-bn1", timeout=20)
        for line in out.splitlines():
            if "%Cpu(s):" in line:
                p = line.split()
                cpu = float(p[1]) + float(p[3]) + float(p[5]) + float(p[9])
                break
    except RuntimeError: pass
    used = total = 0
    try:
        out = await lxc("exec", container, "--", "free", "-m", timeout=20)
        lines = out.splitlines()
        if len(lines) > 1:
            p = lines[1].split(); total = int(p[1]); used = int(p[2])
    except RuntimeError: pass
    disk = "—"
    try:
        out = await lxc("exec", container, "--", "df", "-h", "/", timeout=20)
        for line in out.splitlines():
            if "/dev/" in line and " /" in line:
                p = line.split()
                if len(p) >= 5:
                    disk = f"{p[2]}/{p[1]} ({p[4]})"; break
    except RuntimeError: pass
    pct = (used / total * 100) if total else 0.0
    return {"status": st, "cpu": cpu, "ram_used": used, "ram_total": total, "ram_pct": pct, "disk": disk}


async def lxc_add_forward(container: str, host_port: int, vps_port: int):
    await lxc("config", "device", "add", container, f"tcp_{host_port}",
              "proxy", f"listen=tcp:0.0.0.0:{host_port}", f"connect=tcp:127.0.0.1:{vps_port}")
    await lxc("config", "device", "add", container, f"udp_{host_port}",
              "proxy", f"listen=udp:0.0.0.0:{host_port}", f"connect=udp:127.0.0.1:{vps_port}")


async def lxc_remove_forward(container: str, host_port: int):
    for name in (f"tcp_{host_port}", f"udp_{host_port}"):
        try:
            await lxc("config", "device", "remove", container, name)
        except RuntimeError:
            pass


# ============================================================================
#  PINGGY TUNNEL (optional)
# ============================================================================
PINGGY_LOG = "/root/.pinggy.log"

def _parse_pinggy(text: str) -> Optional[str]:
    m = re.search(r"tcp://([\w.\-]+):(\d+)", text or "")
    return f"{m.group(1)}:{m.group(2)}" if m else None


async def _pexec(container: str, cmd: str, timeout: int = 180) -> str:
    proc = await asyncio.create_subprocess_exec(
        "lxc", "exec", container, "--", "bash", "-c", cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return out.decode().strip() if proc.returncode == 0 else ""


async def pinggy_establish(container: str, retries=3, wait=6) -> Optional[str]:
    await _pexec(container, "command -v ssh >/dev/null || (apt-get update -y && apt-get install -y openssh-client)", 300)
    await _pexec(container, f"pkill -f free.pinggy.io || true; rm -f {PINGGY_LOG}", 30)
    await _pexec(container,
        f"setsid nohup ssh -p 443 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ServerAliveInterval=30 -R0:localhost:22 qr+tcp@free.pinggy.io > {PINGGY_LOG} 2>&1 < /dev/null & disown",
        60)
    for _ in range(retries):
        await asyncio.sleep(wait)
        log = await _pexec(container, f"cat {PINGGY_LOG} 2>/dev/null || true", 30)
        addr = _parse_pinggy(log)
        if addr:
            return addr
    return None


# ============================================================================
#  AUTH
# ============================================================================
def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.verify(plain, hashed)


def make_token(uid: int, role: str) -> str:
    return jwt.encode({"uid": uid, "role": role, "exp": datetime.utcnow() + timedelta(days=7)},
                      SECRET_KEY, algorithm=ALGO)


def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "not logged in")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(401, "invalid token")
    u = user_by_id(payload["uid"])
    if not u:
        raise HTTPException(401, "user gone")
    return {"id": u["id"], "email": u["email"], "role": u["role"]}


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    return user


# ============================================================================
#  TEMPLATES (inline)
# ============================================================================
_BASE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}{{ app_name }}{% endblock %}</title>
<style>
:root{--bg:#0b0f17;--card:#131a26;--card2:#0f1620;--line:#1f2a3a;--txt:#e6edf7;--muted:#8595aa;
      --accent:#4f8cff;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
     background:var(--bg);color:var(--txt);min-height:100vh}
a{color:var(--accent);text-decoration:none}
nav{display:flex;align-items:center;gap:16px;padding:14px 22px;border-bottom:1px solid var(--line);
    background:var(--card2);position:sticky;top:0;z-index:20}
nav .brand{font-weight:700;letter-spacing:.3px}
nav .brand span{color:var(--accent)}
nav .spacer{flex:1}
nav .who{color:var(--muted);font-size:14px}
main{max-width:1100px;margin:0 auto;padding:22px}
h1{margin:6px 0 18px}
.grid{display:grid;gap:16px}
.g2{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h3{margin:0 0 8px;font-size:16px}
.muted{color:var(--muted)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{background:var(--accent);color:#fff;border:none;border-radius:8px;padding:8px 12px;
     font-weight:600;cursor:pointer;font-size:14px;display:inline-block}
.btn:hover{filter:brightness(1.08)}
.btn.sec{background:#25324a}
.btn.ok{background:var(--ok)}
.btn.warn{background:var(--warn)}
.btn.err{background:var(--err)}
.btn.sm{padding:5px 9px;font-size:13px}
input,select{background:#0d1420;border:1px solid var(--line);color:var(--txt);
              padding:8px 10px;border-radius:8px;font-size:14px;width:100%}
label{font-size:13px;color:var(--muted);display:block;margin:10px 0 4px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}
.badge.run{background:rgba(34,197,94,.15);color:var(--ok)}
.badge.stop{background:rgba(239,68,68,.15);color:var(--err)}
.badge.unk{background:rgba(133,149,170,.15);color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}
pre,code{font-family:ui-monospace,Menlo,Consolas,monospace}
pre{background:#070b12;border:1px solid var(--line);border-radius:8px;padding:10px;
    overflow:auto;font-size:13px;max-height:320px}
.flash{padding:10px 12px;border-radius:8px;margin-bottom:14px;font-size:14px}
.flash.err{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4)}
.flash.ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.4)}
.stat{font-size:22px;font-weight:800}
.stat-l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.flex{display:flex;gap:16px;flex-wrap:wrap}
.flex>*{flex:1;min-width:140px}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-box{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);
           border-radius:14px;padding:28px}
.login-box h1{margin:0 0 6px;font-size:22px}
.login-box p{margin:0 0 18px;color:var(--muted);font-size:14px}
#term{background:#05080d;border:1px solid var(--line);border-radius:10px;
      height:70vh;padding:10px;overflow:auto;font-family:ui-monospace,monospace;
      font-size:13px;white-space:pre-wrap;word-break:break-all}
</style>
</head><body>
{% if user %}
<nav>
  <div class="brand">☁ {{ app_name }}<span>.</span></div>
  <a href="/">Dashboard</a>
  {% if user.role == 'admin' %}<a href="/admin">Admin</a>{% endif %}
  <div class="spacer"></div>
  <div class="who">{{ user.email }} · {{ user.role }}</div>
  <a href="/logout" class="btn sec sm">Logout</a>
</nav>
{% endif %}
<main>{% block content %}{% endblock %}</main>
</body></html>"""


_LOGIN = r"""{% extends "base" %}{% block title %}Login · {{ app_name }}{% endblock %}
{% block content %}
<div class="login-wrap"><div class="login-box">
  <h1>☁ {{ app_name }}</h1>
  <p>Sign in to manage your VPS.</p>
  {% if error %}<div class="flash err">{{ error }}</div>{% endif %}
  <form method="post" action="/login">
    <label>Email</label><input name="email" type="email" required autofocus>
    <label>Password</label><input name="password" type="password" required>
    <div style="height:16px"></div>
    <button class="btn" style="width:100%">Sign in</button>
  </form>
</div></div>
{% endblock %}"""


_DASH = r"""{% extends "base" %}{% block title %}Dashboard · {{ app_name }}{% endblock %}
{% block content %}
<h1>My VPS</h1>

<div class="card" style="margin-bottom:20px">
  <h3>Create a new VPS</h3>
  <form method="post" action="/vps/create" class="row" style="align-items:flex-end">
    <div style="flex:1;min-width:200px">
      <label>OS</label>
      <select name="os_image" required>
        {% for label, val in os_options %}<option value="{{ val }}">{{ label }}</option>{% endfor %}
      </select>
    </div>
    <div style="width:110px"><label>RAM (GB)</label><input name="ram_gb" type="number" min="1" value="1" required></div>
    <div style="width:110px"><label>CPU</label><input name="cpu" type="number" min="1" value="1" required></div>
    <div style="width:130px"><label>Disk (GB)</label><input name="disk_gb" type="number" min="5" value="10" required></div>
    {% if user.role == 'admin' %}
    <div style="width:200px"><label>For user ID (empty = you)</label><input name="target_user" placeholder="user id"></div>
    {% endif %}
    <button class="btn ok">Deploy</button>
  </form>
  <p class="muted" style="margin:10px 0 0;font-size:13px">Limit per user: {{ max_vps }}</p>
</div>

{% if vps_list %}
<div class="grid g2">
  {% for v in vps_list %}
  <div class="card">
    <div class="row" style="justify-content:space-between">
      <h3 style="margin:0"><a href="/vps/{{ v.id }}">{{ v.container }}</a></h3>
      {% if v.status == 'running' %}<span class="badge run">running</span>
      {% elif v.status == 'stopped' %}<span class="badge stop">stopped</span>
      {% else %}<span class="badge unk">{{ v.status }}</span>{% endif %}
    </div>
    <div class="muted" style="font-size:13px;margin:6px 0 10px">
      {{ v.os_image }} · {{ v.ram_mb//1024 }}GB RAM · {{ v.cpu }} CPU · {{ v.disk_gb }}GB disk
      {% if user.role == 'admin' %} · owner: {{ v.email }}{% endif %}
    </div>
    <div class="row">
      <a href="/vps/{{ v.id }}" class="btn sm">Manage</a>
    </div>
  </div>
  {% endfor %}
</div>
{% else %}
<div class="card"><p class="muted">No VPS yet. Deploy one above.</p></div>
{% endif %}
{% endblock %}"""


_VPS = r"""{% extends "base" %}{% block title %}{{ vps.container }} · {{ app_name }}{% endblock %}
{% block content %}
<h1>{{ vps.container }}
  {% if stats.status == 'running' %}<span class="badge run">running</span>
  {% elif stats.status == 'stopped' %}<span class="badge stop">stopped</span>
  {% else %}<span class="badge unk">{{ stats.status }}</span>{% endif %}
</h1>

<div class="flex" style="margin-bottom:18px">
  <div class="card"><div class="stat-l">CPU</div><div class="stat" id="s-cpu">{{ '%.1f'|format(stats.cpu) }}%</div></div>
  <div class="card"><div class="stat-l">RAM</div><div class="stat" id="s-ram">{{ stats.ram_used }}/{{ stats.ram_total }} MB</div></div>
  <div class="card"><div class="stat-l">RAM %</div><div class="stat" id="s-rampct">{{ '%.1f'|format(stats.ram_pct) }}%</div></div>
  <div class="card"><div class="stat-l">Disk</div><div class="stat" id="s-disk">{{ stats.disk }}</div></div>
</div>

<div class="card" style="margin-bottom:18px">
  <h3>Actions</h3>
  <div class="row">
    <form method="post" action="/vps/{{ vps.id }}/start"><button class="btn ok">Start</button></form>
    <form method="post" action="/vps/{{ vps.id }}/stop"><button class="btn warn">Stop</button></form>
    <a class="btn sec" href="/vps/{{ vps.id }}/terminal">Terminal</a>
    <form method="post" action="/vps/{{ vps.id }}/reinstall" onsubmit="return confirm('Reinstall wipes ALL data. Continue?')">
      <button class="btn sec">Reinstall</button>
    </form>
    <form method="post" action="/vps/{{ vps.id }}/delete" onsubmit="return confirm('Delete this VPS permanently?')">
      <button class="btn err">Delete</button>
    </form>
  </div>
</div>

<div class="card" style="margin-bottom:18px">
  <h3>Connection</h3>
  {% if vps.pinggy_address %}
    {% set hp = vps.pinggy_address.split(':') %}
    <p><strong>SSH (Pinggy tunnel):</strong> <code>ssh root@{{ hp[0] }} -p {{ hp[1] }}</code></p>
  {% else %}
    <p class="muted">No Pinggy tunnel active. Use the Terminal button, or add a port forward below.</p>
  {% endif %}
  <p><strong>Root password:</strong> <code>{{ vps.root_password }}</code></p>
  <p class="muted" style="font-size:13px">Public IP of host: <code>{{ public_ip }}</code></p>
</div>

<div class="card" style="margin-bottom:18px">
  <h3>Port forwards</h3>
  <form method="post" action="/vps/{{ vps.id }}/forward" class="row" style="margin-bottom:10px">
    <div style="width:180px"><label>VPS port (1-65535)</label><input name="vps_port" type="number" min="1" max="65535" value="8080" required></div>
    <button class="btn">Add forward</button>
  </form>
  {% if forwards %}
    <table>
      <tr><th>ID</th><th>VPS port</th><th>Host port</th><th>Access</th><th></th></tr>
      {% for f in forwards %}
      <tr>
        <td>{{ f.id }}</td>
        <td>{{ f.vps_port }}</td>
        <td>{{ f.host_port }}</td>
        <td><code>{{ public_ip }}:{{ f.host_port }}</code></td>
        <td>
          <form method="post" action="/vps/{{ vps.id }}/forward/{{ f.id }}/delete">
            <button class="btn err sm">Remove</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </table>
  {% else %}
    <p class="muted">No port forwards.</p>
  {% endif %}
</div>

<script>
async function tick(){
  try{
    const r = await fetch('/vps/{{ vps.id }}/stats.json');
    if(!r.ok) return;
    const s = await r.json();
    document.getElementById('s-cpu').textContent = s.cpu.toFixed(1)+'%';
    document.getElementById('s-ram').textContent = s.ram_used+'/'+s.ram_total+' MB';
    document.getElementById('s-rampct').textContent = s.ram_pct.toFixed(1)+'%';
    document.getElementById('s-disk').textContent = s.disk;
  }catch(e){}
}
setInterval(tick, 3000);
</script>
{% endblock %}"""


_TERM = r"""{% extends "base" %}{% block title %}Terminal · {{ vps.container }}{% endblock %}
{% block content %}
<h1>Terminal · {{ vps.container }}</h1>
<div id="term" tabindex="0"></div>
<p class="muted" style="font-size:13px;margin-top:10px">
  Runs <code>lxc exec {{ vps.container }} -- bash -i</code>. Click the panel and type. Ctrl-D to exit.
</p>
<script>
const term = document.getElementById('term');
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(`${proto}://${location.host}/ws/terminal/{{ vps.id }}`);
ws.binaryType = 'arraybuffer';

const dec = new TextDecoder();
ws.onmessage = (ev) => {
  const text = typeof ev.data === 'string' ? ev.data : dec.decode(ev.data);
  term.textContent += text;
  term.scrollTop = term.scrollHeight;
};
ws.onopen = () => { term.textContent = '[connected]\n'; term.focus(); };
ws.onclose = () => { term.textContent += '\n[disconnected]'; };

function send(data){
  if(ws.readyState === 1) ws.send(JSON.stringify({type:'input', data}));
}

term.addEventListener('keydown', (e) => {
  if(e.key === 'Enter'){ send('\n'); e.preventDefault(); }
  else if(e.key === 'Backspace'){ send('\x7f'); e.preventDefault(); }
  else if(e.key === 'Tab'){ send('\t'); e.preventDefault(); }
  else if(e.key === 'Escape'){ send('\x1b'); e.preventDefault(); }
  else if(e.key.length === 1){ send(e.key); e.preventDefault(); }
});
</script>
{% endblock %}"""


_ADMIN = r"""{% extends "base" %}{% block title %}Admin · {{ app_name }}{% endblock %}
{% block content %}
<h1>Admin</h1>

<div class="card" style="margin-bottom:18px">
  <h3>Create user</h3>
  <form method="post" action="/admin/users" class="row" style="align-items:flex-end">
    <div style="flex:1;min-width:180px"><label>Email</label><input name="email" type="email" required></div>
    <div style="flex:1;min-width:180px"><label>Password</label><input name="password" required></div>
    <div style="width:140px"><label>Role</label>
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
    </div>
    <button class="btn ok">Create</button>
  </form>
</div>

<div class="card" style="margin-bottom:18px">
  <h3>Users</h3>
  <table>
    <tr><th>ID</th><th>Email</th><th>Role</th><th>Created</th></tr>
    {% for u in users %}
    <tr><td>{{ u.id }}</td><td>{{ u.email }}</td><td>{{ u.role }}</td><td>{{ u.created_at[:19] }}</td></tr>
    {% endfor %}
  </table>
</div>

<div class="card">
  <h3>All VPS</h3>
  <table>
    <tr><th>ID</th><th>Container</th><th>Owner</th><th>OS</th><th>Status</th><th></th></tr>
    {% for v in all_vps %}
    <tr>
      <td>{{ v.id }}</td>
      <td>{{ v.container }}</td>
      <td>{{ v.email }}</td>
      <td>{{ v.os_image }}</td>
      <td>{{ v.status }}</td>
      <td><a href="/vps/{{ v.id }}" class="btn sm">Open</a></td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endblock %}"""


_env = Environment(loader=BaseLoader(), autoescape=True)
_env.globals["app_name"] = APP_NAME
TEMPLATES = {
    "base": _env.from_string(_BASE),
    "login": _env.from_string(_LOGIN),
    "dashboard": _env.from_string(_DASH),
    "vps_detail": _env.from_string(_VPS),
    "terminal": _env.from_string(_TERM),
    "admin": _env.from_string(_ADMIN),
}


def render(name: str, **ctx) -> HTMLResponse:
    tpl = TEMPLATES[name]
    return HTMLResponse(tpl.render(**ctx))


# ============================================================================
#  FASTAPI APP
# ============================================================================
app = FastAPI(title=APP_NAME)
init_db()


# ---------- auth ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return render("login", user=None)


@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    u = user_by_email(email)
    if not u or not verify_password(password, u["password_hash"]):
        return render("login", user=None, error="Invalid email or password")
    token = make_token(u["id"], u["role"])
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=7 * 24 * 3600)
    audit(u["email"], "login", "")
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


# ---------- dashboard ----------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(current_user)):
    rows = list_vps(None if user["role"] == "admin" else user["id"])
    return render("dashboard", user=user, vps_list=rows, os_options=ALLOWED_OS,
                  max_vps=MAX_VPS_PER_USER)


# ---------- VPS lifecycle ----------
def _own_or_403(row, user):
    if user["role"] != "admin" and row["user_id"] != user["id"]:
        raise HTTPException(403, "not your VPS")
    return row


@app.post("/vps/create")
async def create_vps(request: Request,
                     os_image: str = Form(...),
                     ram_gb: int = Form(...),
                     cpu: int = Form(...),
                     disk_gb: int = Form(...),
                     target_user: str = Form(""),
                     user: dict = Depends(current_user)):
    if user["role"] != "admin" and target_user:
        raise HTTPException(403)
    owner_id = int(target_user) if target_user else user["id"]
    if vps_count_for_user(owner_id) >= MAX_VPS_PER_USER:
        raise HTTPException(400, "VPS limit reached for this user")
    if os_image not in ALLOWED_OS_VALUES:
        raise HTTPException(400, "unsupported OS")
    container = f"fl2-vps-{owner_id}-{random.randint(1000, 9999)}"
    try:
        password, pinggy = await lxc_create(owner_id, os_image, ram_gb, cpu, disk_gb, container)
    except Exception as e:
        raise HTTPException(500, f"LXC create failed: {e}")
    vid = insert_vps(owner_id, container, os_image, ram_gb * 1024, cpu, disk_gb, password, pinggy)
    audit(user["email"], "vps.create", f"{container} -> user {owner_id}")
    return RedirectResponse(f"/vps/{vid}", status_code=303)


@app.get("/vps/{vps_id}", response_class=HTMLResponse)
async def vps_detail(request: Request, vps_id: int, user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    stats = await lxc_stats(row["container"])
    return render("vps_detail", user=user, vps=row, stats=stats,
                  forwards=list_forwards(vps_id), public_ip=PUBLIC_IP)


@app.post("/vps/{vps_id}/{action}")
async def vps_action(vps_id: int, action: str, user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    try:
        if action == "start":
            await lxc_start(row["container"]); update_vps(vps_id, status="running")
        elif action == "stop":
            await lxc_stop(row["container"]); update_vps(vps_id, status="stopped")
        elif action == "delete":
            await lxc_delete(row["container"]); delete_vps_row(vps_id)
            audit(user["email"], "vps.delete", row["container"])
            return RedirectResponse("/", status_code=303)
        elif action == "reinstall":
            pw = await lxc_reinstall(row)
            update_vps(vps_id, root_password=pw, status="running", pinggy_address="")
        else:
            raise HTTPException(400, "unknown action")
    except Exception as e:
        raise HTTPException(500, str(e))
    audit(user["email"], f"vps.{action}", row["container"])
    return RedirectResponse(f"/vps/{vps_id}", status_code=303)


@app.get("/vps/{vps_id}/stats.json")
async def vps_stats_json(vps_id: int, user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    return JSONResponse(await lxc_stats(row["container"]))


# ---------- port forwards ----------
@app.post("/vps/{vps_id}/forward")
async def add_fwd(vps_id: int, vps_port: int = Form(...), user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    if not (1 <= vps_port <= 65535):
        raise HTTPException(400, "invalid port")
    host_port = random.randint(20000, 50000)
    try:
        await lxc_add_forward(row["container"], host_port, vps_port)
    except Exception as e:
        raise HTTPException(500, f"forward failed: {e}")
    add_forward(vps_id, vps_port, host_port)
    return RedirectResponse(f"/vps/{vps_id}", status_code=303)


@app.post("/vps/{vps_id}/forward/{fid}/delete")
async def del_fwd(vps_id: int, fid: int, user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    f = delete_forward(fid)
    if f:
        await lxc_remove_forward(row["container"], f["host_port"])
    return RedirectResponse(f"/vps/{vps_id}", status_code=303)


# ---------- terminal ----------
@app.get("/vps/{vps_id}/terminal", response_class=HTMLResponse)
async def terminal_page(vps_id: int, user: dict = Depends(current_user)):
    row = get_vps(vps_id)
    if not row:
        raise HTTPException(404)
    _own_or_403(row, user)
    return render("terminal", user=user, vps=row)


@app.websocket("/ws/terminal/{vps_id}")
async def terminal_ws(ws: WebSocket, vps_id: int):
    token = ws.cookies.get(COOKIE)
    if not token:
        await ws.close(code=4401); return
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        await ws.close(code=4401); return
    row = get_vps(vps_id)
    if not row:
        await ws.close(code=4404); return
    if payload["role"] != "admin" and row["user_id"] != payload["uid"]:
        await ws.close(code=4403); return

    await ws.accept()
    proc = await asyncio.create_subprocess_exec(
        "lxc", "exec", row["container"], "--", "bash", "-i",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={"TERM": "xterm-256color", "HOME": "/root", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )

    async def pump_out():
        try:
            while True:
                chunk = await proc.stdout.read(1024)
                if not chunk:
                    break
                await ws.send_bytes(chunk)
        except Exception:
            pass

    out_task = asyncio.create_task(pump_out())
    try:
        while True:
            msg = await ws.receive_text()
            try:
                data = json.loads(msg)
                if data.get("type") == "input":
                    proc.stdin.write(data["data"].encode())
                    await proc.stdin.drain()
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        try:
            proc.kill()
        except Exception:
            pass
        out_task.cancel()


# ---------- admin ----------
@app.get("/admin", response_class=HTMLResponse)
async def admin_home(user: dict = Depends(require_admin)):
    return render("admin", user=user, users=list_users(), all_vps=list_vps(None))


@app.post("/admin/users")
async def admin_create_user(email: str = Form(...), password: str = Form(...),
                            role: str = Form("user"),
                            user: dict = Depends(require_admin)):
    try:
        create_user(email, password, role)
    except Exception as e:
        raise HTTPException(400, str(e))
    audit(user["email"], "user.create", email)
    return RedirectResponse("/admin", status_code=303)


# ---------- health ----------
@app.get("/healthz")
async def healthz():
    return {"ok": True, "time": datetime.utcnow().isoformat()}
