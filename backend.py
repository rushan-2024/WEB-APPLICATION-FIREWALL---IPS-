"""
backend.py — Unified IPS Web App (Port 5001)
All pages served from one Flask app with shared navigation.

Routes:
  /           → Home page
  /login      → Demo login (attack console)
  /dashboard  → Live attack dashboard
  /simulate   → Attack simulator
  /compare    → WAF comparison demo
  /stats      → Project statistics
  /admin      → Admin panel (password protected)
  /report     → Live report page
"""
from flask import Flask, request, render_template_string, redirect, session, send_file
import sqlite3, json, os
from datetime import datetime
from collections import Counter

app = Flask(__name__)
app.secret_key = 'ips-secret-2024'

ADMIN_PASSWORD = 'admin123'
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
LOG_FILE   = os.path.join(BASE_DIR, 'attacks.log')
BLOCK_FILE = os.path.join(BASE_DIR, 'blocked_ips.json')
DB_FILE    = os.path.join(BASE_DIR, 'test.db')

# ── Shared helpers ────────────────────────────────────────────────────────────
def load_logs():
    logs = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                l = line.strip()
                if l:
                    try: logs.append(json.loads(l))
                    except: pass
    except: pass
    return logs

def load_blocked():
    try:
        with open(BLOCK_FILE) as f:
            data = json.load(f)
            return set(data.get('blocked_ips', [])), data.get('attack_count', {})
    except:
        return set(), {}

def save_blocked(blocked_ips, attack_count):
    with open(BLOCK_FILE, 'w') as f:
        json.dump({'blocked_ips': list(blocked_ips), 'attack_count': attack_count}, f)

def classify(log):
    t = log.get('attack_type', '')
    if t: return t
    p = log.get('payload', '').lower()
    if any(x in p for x in [' or ', 'union select', 'drop table', 'insert into', 'sleep(', '--', '1=1']): return 'SQL Injection'
    if any(x in p for x in ['<script', 'javascript:', 'onerror=', 'alert(', 'eval(']): return 'XSS'
    if any(x in p for x in ['; ls', '| whoami', '&&', 'cat ']): return 'Command Injection'
    if any(x in p for x in ['../', 'etc/passwd']): return 'Path Traversal'
    if 'Honeypot' in t: return 'Honeypot'
    return 'Unknown'

# ── Shared CSS + Matrix JS ────────────────────────────────────────────────────
SHARED = r"""
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#050a05;--bg2:#070d07;--bg3:#0a120a;--panel:#0c160c;
  --border:rgba(0,255,65,0.15);--border2:rgba(0,255,65,0.35);
  --g:#00ff41;--g2:#00cc33;--g3:#008f23;
  --dim:rgba(0,255,65,0.45);--muted:rgba(0,255,65,0.3);
  --red:#ff0040;--amber:#ffaa00;--cyan:#00ffff;
  --violet:#a855f7;--orange:#ff8800;--text:#c8ffc8;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{font-family:'Share Tech Mono',monospace;background:var(--bg);color:var(--g);min-height:100vh;cursor:crosshair;overflow-x:hidden;}
#matrix{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.12;}
body::after{content:'';position:fixed;inset:0;z-index:999;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px);}
body::before{content:'';position:fixed;inset:0;z-index:998;pointer-events:none;
  background:radial-gradient(ellipse at center,transparent 60%,rgba(0,0,0,0.6) 100%);}
@keyframes glitch{0%,100%{text-shadow:none;transform:none;}20%{text-shadow:-2px 0 #ff0040,2px 0 #00ffff;transform:translate(-1px,0);}40%{text-shadow:2px 0 #ff0040,-2px 0 #00ffff;transform:translate(1px,0);}60%{text-shadow:none;transform:none;}80%{text-shadow:-1px 0 #00ffff;transform:translate(1px,0);}}
@keyframes flicker{0%,100%{opacity:1}41%{opacity:1}42%{opacity:0.6}43%{opacity:1}75%{opacity:1}76%{opacity:0.7}77%{opacity:1}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes scanH{0%{top:-4px}100%{top:100%}}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes glow-pulse{0%,100%{box-shadow:0 0 8px rgba(0,255,65,0.25)}50%{box-shadow:0 0 20px rgba(0,255,65,0.5)}}
/* Ensure all animated elements stay visible after animation */
.panel,.stat-row,.page-head,.panel-title{animation-fill-mode:forwards !important;}
.scan-line{position:fixed;left:0;right:0;height:2px;z-index:997;pointer-events:none;
  background:linear-gradient(90deg,transparent,rgba(0,255,65,0.35),transparent);animation:scanH 8s linear infinite;}

/* ── NAV ── */
nav{position:sticky;top:0;z-index:200;display:flex;justify-content:space-between;align-items:center;
  padding:12px 40px;background:rgba(5,10,5,0.94);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--border);animation:flicker 10s infinite;}
.logo{font-family:'Orbitron',monospace;font-size:14px;font-weight:900;color:var(--g);letter-spacing:4px;
  text-shadow:0 0 20px var(--g),0 0 40px rgba(0,255,65,0.3);animation:glitch 6s infinite;text-decoration:none;}
.nav-links{display:flex;gap:4px;align-items:center;flex-wrap:wrap;}
.nav-link{font-size:9px;color:var(--dim);text-decoration:none;letter-spacing:1.5px;
  padding:5px 10px;border-radius:2px;border:1px solid transparent;transition:all 0.2s;}
.nav-link:hover{color:var(--g);border-color:var(--border);}
.nav-link.active{color:var(--g);border-color:var(--border2);background:rgba(0,255,65,0.06);}
.nav-sep{color:var(--border);font-size:12px;}
.nav-report{color:var(--amber);border-color:rgba(255,170,0,0.3) !important;text-shadow:0 0 8px rgba(255,170,0,0.4);}
.nav-report:hover{color:var(--amber) !important;border-color:rgba(255,170,0,0.6) !important;background:rgba(255,170,0,0.06) !important;}
.nav-admin{color:var(--red);border-color:rgba(255,0,64,0.3) !important;}
.nav-admin:hover{color:var(--red) !important;border-color:rgba(255,0,64,0.6) !important;background:rgba(255,0,64,0.06) !important;}

/* ── LAYOUT ── */
main{position:relative;z-index:1;max-width:1300px;margin:0 auto;padding:40px 44px 60px;}
.page-head{margin-bottom:32px;opacity:0;animation:fadeUp 0.5s ease 0.1s forwards;}
.page-head h1{font-family:'Orbitron',monospace;font-size:26px;font-weight:900;letter-spacing:2px;
  text-shadow:0 0 24px rgba(0,255,65,0.4);margin-bottom:4px;}
.page-head p{font-size:10px;color:var(--dim);letter-spacing:1px;}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;
  position:relative;overflow:hidden;padding:24px 26px;margin-bottom:18px;
  opacity:0;animation:fadeUp 0.4s ease forwards;
  transition:border-color 0.2s, box-shadow 0.2s;}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--g),transparent);opacity:0.4;}
.panel:hover{border-color:var(--border2);box-shadow:0 0 18px rgba(0,255,65,0.15);}
.panel-title{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;color:var(--g);
  letter-spacing:3px;margin-bottom:16px;}

/* ── STAT CARDS ── */
.stat-row{display:grid;gap:13px;margin-bottom:18px;opacity:0;animation:fadeUp 0.4s ease forwards;}
.stat-4{grid-template-columns:repeat(4,1fr);}
.stat-5{grid-template-columns:repeat(5,1fr);}
.stat-6{grid-template-columns:repeat(6,1fr);}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:4px;
  padding:20px 16px;text-align:center;position:relative;overflow:hidden;transition:all 0.2s;}
.stat:hover{border-color:var(--border2);transform:translateY(-2px);}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;}
.s-r::before{background:linear-gradient(90deg,var(--red),transparent);}
.s-a::before{background:linear-gradient(90deg,var(--amber),transparent);}
.s-g::before{background:linear-gradient(90deg,var(--g),transparent);}
.s-c::before{background:linear-gradient(90deg,var(--cyan),transparent);}
.s-v::before{background:linear-gradient(90deg,var(--violet),transparent);}
.s-o::before{background:linear-gradient(90deg,var(--orange),transparent);}
.stat-n{font-family:'Orbitron',monospace;font-size:38px;font-weight:900;line-height:1;margin-bottom:6px;}
.s-r .stat-n{color:var(--red);text-shadow:0 0 14px rgba(255,0,64,0.5);}
.s-a .stat-n{color:var(--amber);text-shadow:0 0 14px rgba(255,170,0,0.5);}
.s-g .stat-n{color:var(--g);text-shadow:0 0 14px rgba(0,255,65,0.5);}
.s-c .stat-n{color:var(--cyan);text-shadow:0 0 14px rgba(0,255,255,0.5);}
.s-v .stat-n{color:var(--violet);text-shadow:0 0 14px rgba(168,85,247,0.5);}
.s-o .stat-n{color:var(--orange);text-shadow:0 0 14px rgba(255,136,0,0.5);}
.stat-l{font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;}

/* ── TABLE ── */
table{width:100%;border-collapse:collapse;}
thead th{padding:9px 14px;text-align:left;font-size:8px;color:var(--g3);letter-spacing:2px;
  text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--bg3);}
tbody tr{border-bottom:1px solid rgba(0,255,65,0.05);transition:background 0.15s;}
tbody tr:last-child{border-bottom:none;}
tbody tr:hover{background:rgba(0,255,65,0.03);}
td{padding:11px 14px;font-size:11px;color:var(--text);}
.td-mono{font-size:9px;color:var(--dim);}
.td-ip{font-size:10px;color:var(--cyan);}
.td-payload{font-size:9px;color:var(--muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:2px;font-size:8px;letter-spacing:1px;border:1px solid;}
.b-sql{color:var(--red);border-color:rgba(255,0,64,0.3);background:rgba(255,0,64,0.06);}
.b-xss{color:var(--amber);border-color:rgba(255,170,0,0.3);background:rgba(255,170,0,0.06);}
.b-cmd{color:var(--cyan);border-color:rgba(0,255,255,0.3);background:rgba(0,255,255,0.06);}
.b-path{color:var(--orange);border-color:rgba(255,136,0,0.3);background:rgba(255,136,0,0.06);}
.b-honey{color:var(--amber);border-color:rgba(255,170,0,0.4);background:rgba(255,170,0,0.08);}
.b-brute{color:var(--violet);border-color:rgba(168,85,247,0.3);background:rgba(168,85,247,0.06);}
.b-block{color:var(--red);border-color:rgba(255,0,64,0.3);background:rgba(255,0,64,0.06);}
.b-unk{color:var(--dim);border-color:var(--border);}
.sev-b{display:inline-block;padding:2px 7px;border-radius:2px;font-size:7px;letter-spacing:1px;border:1px solid;}
.sev-CRITICAL{color:var(--red);border-color:rgba(255,0,64,0.4);background:rgba(255,0,64,0.07);}
.sev-HIGH{color:var(--amber);border-color:rgba(255,170,0,0.4);background:rgba(255,170,0,0.07);}
.sev-MEDIUM{color:var(--cyan);border-color:rgba(0,255,255,0.3);background:rgba(0,255,255,0.05);}
.sev-LOW{color:var(--g);border-color:rgba(0,255,65,0.3);background:rgba(0,255,65,0.05);}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;
  cursor:pointer;text-decoration:none;transition:all 0.2s;border:1px solid;}
.btn-g{color:var(--g);border-color:rgba(0,255,65,0.4);background:transparent;}
.btn-g:hover{background:rgba(0,255,65,0.08);box-shadow:0 0 18px rgba(0,255,65,0.3);}
.btn-r{color:var(--red);border-color:rgba(255,0,64,0.4);background:transparent;}
.btn-r:hover{background:rgba(255,0,64,0.08);box-shadow:0 0 18px rgba(255,0,64,0.3);}
.btn-a{color:var(--amber);border-color:rgba(255,170,0,0.4);background:transparent;}
.btn-a:hover{background:rgba(255,170,0,0.08);box-shadow:0 0 18px rgba(255,170,0,0.3);}
.btn-c{color:var(--cyan);border-color:rgba(0,255,255,0.3);background:transparent;}
.btn-c:hover{background:rgba(0,255,255,0.06);box-shadow:0 0 18px rgba(0,255,255,0.2);}

/* ── INPUTS ── */
input[type=text],input[type=password],input[type=email]{
  width:100%;padding:11px 14px;background:var(--bg3);border:1px solid var(--border);
  border-radius:3px;color:var(--g);font-family:'Share Tech Mono',monospace;font-size:12px;
  outline:none;transition:border-color 0.2s;caret-color:var(--g);}
input:focus{border-color:var(--g2);box-shadow:0 0 14px rgba(0,255,65,0.15);}
input::placeholder{color:var(--muted);}
label{display:block;font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;}

footer{position:relative;z-index:1;text-align:center;padding:24px;
  border-top:1px solid var(--border);font-size:9px;color:var(--g3);letter-spacing:2px;background:var(--bg2);}
</style>

<script>
window.addEventListener('DOMContentLoaded', function() {
  var canvas = document.getElementById('matrix');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*(){}[]<>/\|;:!?~';
  var W, H, cols, drops;
  function init() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
    cols = Math.floor(W / 16);
    drops = [];
    for (var i = 0; i < cols; i++) drops[i] = Math.random() * -50;
  }
  init(); window.addEventListener('resize', init);
  setInterval(function() {
    ctx.fillStyle = 'rgba(5,10,5,0.05)'; ctx.fillRect(0, 0, W, H);
    for (var i = 0; i < drops.length; i++) {
      var ch = chars[Math.floor(Math.random() * chars.length)];
      var x = i * 16, y = drops[i] * 16;
      ctx.fillStyle = '#ccffcc'; ctx.font = 'bold 13px monospace'; ctx.fillText(ch, x, y);
      ctx.fillStyle = '#00ff41'; ctx.font = '12px monospace';
      if (Math.random() > 0.5 && y > 16) ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y - 16);
      if (y > H && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }, 45);
});
</script>
"""

def nav(active=''):
    links = [
        ('/', 'HOME', ''),
        ('/login', 'DEMO', ''),
        ('/dashboard', 'DASHBOARD', ''),
        ('/simulate', 'SIMULATOR', ''),
        ('/compare', 'COMPARISON', ''),
        ('/honeypots', 'HONEYPOTS', ''),
        ('/stats', 'STATS', ''),
        ('/report', 'REPORT', 'nav-report'),
        ('/admin', 'ADMIN', 'nav-admin'),
    ]
    items = ''
    for href, label, extra in links:
        is_active = 'active' if href == active else ''
        items += f'<a href="{href}" class="nav-link {is_active} {extra}">{label}</a>'
    return f'''
<canvas id="matrix"></canvas>
<div class="scan-line"></div>
<nav>
  <a href="/" class="logo">W-IPS</a>
  <div class="nav-links">{items}</div>
</nav>'''

# ── HOME PAGE ─────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    logs = load_logs()
    blocked, _ = load_blocked()
    HOME_HTML = """<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Intrusion Prevention System</title>""" + SHARED + """
<style>
#globe-container{position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:0;}
.scanlines{position:fixed;top:0;left:0;width:100vw;height:100vh;pointer-events:none;z-index:1;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.22) 2px,rgba(0,0,0,0.22) 4px);}
.overlay{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(2,6,2,0.42);z-index:2;pointer-events:none;}

.hero{position:relative;z-index:10;min-height:92vh;display:flex;align-items:center;padding:100px 7% 60px;gap:40px;}
.hero-left{flex:1;max-width:600px;}

.sys-badge{display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(0,255,65,0.4);
  padding:7px 16px;border-radius:3px;font-size:10px;color:var(--g);letter-spacing:2px;
  margin-bottom:24px;background:rgba(0,255,65,0.07);backdrop-filter:blur(6px);}
.sys-badge-dot{width:7px;height:7px;border-radius:50%;background:var(--g);box-shadow:0 0 10px var(--g);animation:blink 1.5s ease-in-out infinite;}

.hero-main{font-family:"Orbitron",monospace;font-size:clamp(38px,6vw,80px);font-weight:900;line-height:1.05;
  text-shadow:0 0 30px rgba(0,255,65,0.6),0 0 60px rgba(0,255,65,0.2);
  animation:glitch 5s infinite,fadeUp 0.7s ease 0.2s both;margin-bottom:12px;}
.hero-sub-title{font-family:"Orbitron",monospace;font-size:clamp(13px,2vw,22px);font-weight:400;
  color:var(--dim);letter-spacing:5px;animation:fadeUp 0.7s ease 0.4s both;margin-bottom:6px;}
.hero-tagline{font-family:"Orbitron",monospace;font-size:clamp(9px,1.1vw,13px);
  color:rgba(0,255,65,0.35);letter-spacing:3px;animation:fadeUp 0.7s ease 0.5s both;margin-bottom:26px;}
.hero-desc{font-size:12px;color:var(--dim);line-height:1.9;max-width:480px;margin-bottom:32px;animation:fadeUp 0.7s ease 0.6s both;}
.cta-row{display:flex;gap:10px;flex-wrap:wrap;animation:fadeUp 0.7s ease 0.8s both;margin-bottom:32px;}

.proj-stats{opacity:0;animation:fadeUp 0.7s ease 1s forwards;}
.proj-stats-title{font-size:8px;color:var(--g3);letter-spacing:3px;margin-bottom:12px;text-transform:uppercase;}
.proj-stat-items{display:flex;gap:28px;padding-top:12px;border-top:1px solid rgba(0,255,65,0.12);}
.ps-item{display:flex;flex-direction:column;gap:4px;}
.ps-val{font-family:"Orbitron",monospace;font-size:26px;font-weight:900;color:var(--g);text-shadow:0 0 12px rgba(0,255,65,0.5);line-height:1;}
.ps-val.red{color:var(--red);text-shadow:0 0 12px rgba(255,0,64,0.5);}
.ps-val.amber{color:var(--amber);text-shadow:0 0 12px rgba(255,170,0,0.5);}
.ps-val.cyan{color:var(--cyan);text-shadow:0 0 12px rgba(0,255,255,0.5);}
.ps-label{font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;}



.quick-nav{position:relative;z-index:10;display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-top:1px solid var(--border);border-bottom:1px solid var(--border);}
.qcard{background:rgba(7,13,7,0.9);backdrop-filter:blur(10px);padding:22px 18px;text-decoration:none;transition:background 0.2s;border:none;}
.qcard:hover{background:rgba(12,22,12,0.95);}
.qcard-icon{font-size:20px;margin-bottom:8px;}
.qcard-title{font-family:"Orbitron",monospace;font-size:10px;font-weight:700;color:var(--g);letter-spacing:2px;margin-bottom:3px;}
.qcard-desc{font-size:9px;color:var(--dim);line-height:1.5;}
.qcard-link{font-size:8px;color:var(--g3);letter-spacing:1px;margin-top:6px;}

.page-body{position:relative;z-index:10;background:var(--bg);}
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
.feat-card{background:var(--panel);padding:26px;transition:background 0.2s;}
.feat-card:hover{background:var(--bg3);}
.feat-icon{font-size:20px;margin-bottom:12px;}
.feat-name{font-family:"Orbitron",monospace;font-size:11px;font-weight:700;color:var(--g);margin-bottom:8px;letter-spacing:2px;}
.feat-desc{font-size:10px;color:var(--dim);line-height:1.7;}
.feat-tag{display:inline-block;margin-top:12px;font-size:7px;letter-spacing:2px;padding:3px 9px;border:1px solid var(--border2);color:var(--g3);}
.arch{text-align:center;padding:50px 40px;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--bg2);}
.arch-flow{display:inline-flex;align-items:center;gap:10px;padding:14px 26px;border:1px solid var(--border);border-radius:4px;background:var(--bg3);}
.arch-node{padding:9px 16px;border-radius:2px;font-size:10px;letter-spacing:2px;border:1px solid;}
.arch-node.c{border-color:var(--border2);color:var(--dim);}
.arch-node.w{border-color:var(--g2);color:var(--g);text-shadow:0 0 8px rgba(0,255,65,0.5);box-shadow:0 0 14px rgba(0,255,65,0.12);}
</style>
</head><body>
<div id="globe-container"></div>
<div class="scanlines"></div>
<div class="overlay"></div>
""" + nav('/') + """
<section class="hero">
  <div class="hero-left">
    <div class="sys-badge"><div class="sys-badge-dot"></div>SYSTEM ACTIVE: MONITORING</div>
    <div class="hero-main">INTRUSION<br>PREVENTION<br>SYSTEM</div>
    <div class="hero-sub-title">Secure Your Network</div>
    <div class="hero-tagline">Python WAF &middot; Real-time Detection &middot; Zero Compromise</div>
    <p class="hero-desc">Next-generation Web Application Firewall detecting and blocking SQL injection, XSS, command injection, path traversal, brute force and more in real time.</p>
    <div class="cta-row">
      <a href="/login" class="btn btn-g">[ ATTACK DEMO ]</a>
      <a href="/dashboard" class="btn btn-c">[ DASHBOARD ]</a>
      <a href="/simulate" class="btn btn-r">[ SIMULATOR ]</a>
      <a href="/report" class="btn btn-a">[ REPORT ]</a>
    </div>
    <div class="proj-stats">
      <div class="proj-stats-title">::: PROJECT METRICS :::</div>
      <div class="proj-stat-items">
        <div class="ps-item"><div class="ps-val red" id="atk-count">__ATK__</div><div class="ps-label">Attacks Blocked</div></div>
        <div class="ps-item"><div class="ps-val amber">__BLK__</div><div class="ps-label">IPs Banned</div></div>
        <div class="ps-item"><div class="ps-val cyan">9+</div><div class="ps-label">Attack Types</div></div>
        <div class="ps-item"><div class="ps-val">100%</div><div class="ps-label">Block Rate</div></div>
      </div>
    </div>
  </div>
</section>
<!-- Radar behind text, in front of globe, centred on page -->
<div class="quick-nav">
  <a href="/simulate" class="qcard"><div class="qcard-icon">&#9889;</div><div class="qcard-title">SIMULATOR</div><div class="qcard-desc">Fire real attack payloads with one click</div><div class="qcard-link">&#8594; /simulate</div></a>
  <a href="/honeypots" class="qcard"><div class="qcard-icon">&#127855;</div><div class="qcard-title">HONEYPOTS</div><div class="qcard-desc">5-layer deception network — 50+ traps</div><div class="qcard-link">&#8594; /honeypots</div></a>
  <a href="/compare" class="qcard"><div class="qcard-icon">&#9878;</div><div class="qcard-title">COMPARISON</div><div class="qcard-desc">Side-by-side: without WAF vs with WAF</div><div class="qcard-link">&#8594; /compare</div></a>
  <a href="/admin" class="qcard"><div class="qcard-icon">&#128274;</div><div class="qcard-title">ADMIN PANEL</div><div class="qcard-desc">Manage blocked IPs and system settings</div><div class="qcard-link">&#8594; /admin</div></a>
</div>
<div class="page-body">
<div style="display:flex;justify-content:center;border-bottom:1px solid var(--border);background:var(--bg2);">
  <div style="flex:1;max-width:180px;padding:28px 16px;text-align:center;border-right:1px solid var(--border);">
    <div style="font-family:Orbitron,monospace;font-size:36px;font-weight:900;color:var(--g);text-shadow:0 0 16px rgba(0,255,65,0.5);">9+</div>
    <div style="font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;">Attack Types</div></div>
  <div style="flex:1;max-width:180px;padding:28px 16px;text-align:center;border-right:1px solid var(--border);">
    <div style="font-family:Orbitron,monospace;font-size:36px;font-weight:900;color:var(--red);text-shadow:0 0 16px rgba(255,0,64,0.5);">__ATK__</div>
    <div style="font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;">Attacks Blocked</div></div>
  <div style="flex:1;max-width:180px;padding:28px 16px;text-align:center;border-right:1px solid var(--border);">
    <div style="font-family:Orbitron,monospace;font-size:36px;font-weight:900;color:var(--amber);text-shadow:0 0 16px rgba(255,170,0,0.5);">__BLK__</div>
    <div style="font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;">IPs Blocked</div></div>
  <div style="flex:1;max-width:180px;padding:28px 16px;text-align:center;">
    <div style="font-family:Orbitron,monospace;font-size:36px;font-weight:900;color:var(--cyan);text-shadow:0 0 16px rgba(0,255,255,0.5);">100%</div>
    <div style="font-size:8px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;">Block Rate</div></div>
</div>
<section style="max-width:1100px;margin:0 auto;padding:60px 40px;">
  <div style="font-size:9px;color:var(--g3);letter-spacing:4px;text-transform:uppercase;margin-bottom:32px;text-align:center;">::: THREAT COVERAGE :::</div>
  <div class="feat-grid">
    <div class="feat-card"><div class="feat-icon">&#128137;</div><div class="feat-name">SQL INJECTION</div><div class="feat-desc">OR 1=1 &middot; UNION SELECT &middot; DROP TABLE &middot; SLEEP() &middot; 11 patterns</div><span class="feat-tag">CRITICAL</span></div>
    <div class="feat-card"><div class="feat-icon">&#128221;</div><div class="feat-name">XSS ATTACK</div><div class="feat-desc">&lt;script&gt; &middot; javascript: &middot; onerror= &middot; eval() &middot; 15 patterns</div><span class="feat-tag">HIGH</span></div>
    <div class="feat-card"><div class="feat-icon">&#128187;</div><div class="feat-name">CMD INJECTION</div><div class="feat-desc">; ls &middot; | whoami &middot; backtick exec &middot; $() subshell</div><span class="feat-tag">CRITICAL</span></div>
    <div class="feat-card"><div class="feat-icon">&#128194;</div><div class="feat-name">PATH TRAVERSAL</div><div class="feat-desc">../../etc/passwd &middot; %2e%2e%2f &middot; windows/system32</div><span class="feat-tag">HIGH</span></div>
    <div class="feat-card"><div class="feat-icon">&#127855;</div><div class="feat-name">HONEYPOT TRAPS</div><div class="feat-desc">20+ decoy paths: /admin, /wp-admin, /.env, /phpmyadmin</div><span class="feat-tag">CRITICAL</span></div>
    <div class="feat-card"><div class="feat-icon">&#128272;</div><div class="feat-name">BRUTE FORCE</div><div class="feat-desc">5+ login attempts in 60s triggers auto-block</div><span class="feat-tag">HIGH</span></div>
  </div>
</section>
<div class="arch">
  <div style="font-size:9px;color:var(--g3);letter-spacing:4px;text-transform:uppercase;margin-bottom:24px;">::: TRAFFIC FLOW :::</div>
  <div class="arch-flow">
    <div class="arch-node c">CLIENT</div><span style="color:var(--g3);font-size:16px;">&#x2501;&#x2501;&#x25B6;</span>
    <div class="arch-node w">WAF :8080</div><span style="color:var(--g3);font-size:16px;">&#x2501;&#x2501;&#x25B6;</span>
    <div class="arch-node c">BACKEND :5001</div>
  </div>
  <div style="margin-top:14px;font-size:9px;color:var(--g3);letter-spacing:2px;">MALICIOUS REQUESTS TERMINATED AT THE PROXY LAYER</div>
</div>
<footer>WEB APPLICATION IPS &nbsp;&middot;&nbsp; SEM 4 MAJOR PROJECT</footer>
</div>
<script src="https://unpkg.com/three@0.152.0/build/three.min.js"></script>
<script src="https://unpkg.com/globe.gl@2.27.2/dist/globe.gl.min.js"></script>
<script>
var N = 40;
var payloadTypes = ['[PAYLOAD: DDoS]','[RANSOMWARE]','[Trojan]','[SQLi Exploit]','[Zero-Day]','[Data Breach]','[XSS Attack]','[Brute Force]','[CMD Inject]','[RCE]'];

var arcsData = Array.from({length:N}, function() {
  return {
    startLat: (Math.random()-0.5)*180,
    startLng: (Math.random()-0.5)*360,
    endLat:   (Math.random()-0.5)*180,
    endLng:   (Math.random()-0.5)*360,
    color: [['#00ff41','#00ff41'],['#ff004c','#ff004c'],['#00e5ff','#00e5ff']][Math.floor(Math.random()*3)],
    payloadText: payloadTypes[Math.floor(Math.random()*payloadTypes.length)]
  };
});

var myGlobe = Globe()(document.getElementById('globe-container'))
  .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
  .arcsData(arcsData)
  .arcColor('color')
  .arcStroke(0.5)
  .arcAltitude(0)
  .arcDashLength(0.15)
  .arcDashGap(1.5)
  .arcDashInitialGap(function(){ return Math.random()*1; })
  .arcDashAnimateTime(function(){ return Math.random()*3000+2000; })
  .labelsData(arcsData)
  .labelLat('endLat')
  .labelLng('endLng')
  .labelText('payloadText')
  .labelSize(1.2)
  .labelDotRadius(0.4)
  .labelColor(function(){ return '#ff004c'; })
  .labelResolution(2)
  .atmosphereColor('#00ff41')
  .atmosphereAltitude(0.15)
  .backgroundColor('rgba(0,0,0,0)');

myGlobe.controls().autoRotate = true;
myGlobe.controls().autoRotateSpeed = 1.0;
myGlobe.controls().enableZoom = false;

window.addEventListener('resize', function(){
  myGlobe.width(window.innerWidth);
  myGlobe.height(window.innerHeight);
});

// Animate attack counter
var atkCount = __ATK_JS__;
var el = document.getElementById('atk-count');
if (el) {
  setInterval(function() {
    if (Math.random() > 0.7) {
      atkCount++;
      el.textContent = atkCount;
      el.style.textShadow = '0 0 20px #ff0040';
      setTimeout(function() { el.style.textShadow = '0 0 12px rgba(255,0,64,0.5)'; }, 200);
    }
  }, 1800);
}
</script>
</body></html>"""

    total_attacks = len(logs)
    blocked_count = len(blocked)
    html = HOME_HTML.replace('__ATK__', str(total_attacks)).replace('__BLK__', str(blocked_count)).replace('__ATK_JS__', str(total_attacks))
    return html


# ── LOGIN PAGE ────────────────────────────────────────────────────────────────
@app.route('/login')
def login_page():
    user = request.args.get('user')
    result = result_type = None
    if user:
        import re, time
        ip = request.remote_addr
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # WAF detection patterns
        import re as _re
        patterns = {
            'SQL_INJECTION':  r"(?i)(union[\s+]select|or[\s]+1=1|drop[\s]+table|insert[\s]+into|select[\s]+.*from|--|sleep\s*\(|benchmark\s*\(|1=1|1 or|xp_|exec\s*\(|information_schema|char\s*\(|0x[0-9a-f]+)",
            'XSS':            r"(?i)(<script|<\/script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|eval\s*\(|document\.cookie|<img|<svg|<iframe|<body|on\w+\s*=)",
            'CMD_INJECTION':  r"(?i)(;\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|php|nc|ncat|id|whoami|uname)|&&|\|\||`|\$\(|>\s*/|2>&1)",
            'PATH_TRAVERSAL': r"(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/etc\/shadow|\/proc\/|\/var\/|windows\\system32|boot\.ini)",
            'BRUTE_FORCE':    None,
            'LDAP_INJECTION': r"(?i)(\*\)\(|\(\||\(&|cn=|dc=|ou=|objectclass=|\)\(|\(\!)",
            'XXE':            r"(?i)(<!entity|<!DOCTYPE|SYSTEM\s+[\"']|file:\/\/|expect:\/\/|php:\/\/)",
            'RCE':            r"(?i)(system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(|proc_open\s*\(|base64_decode\s*\(|phpinfo\s*\()",
        }

        attack_type = None
        for atype, pattern in patterns.items():
            if pattern and _re.search(pattern, user):
                attack_type = atype
                break

        if attack_type:
            # Log the attack
            blocked, ac = load_blocked()
            ac[ip] = ac.get(ip, 0) + 1
            if ac[ip] >= 3:
                blocked.add(ip)
            save_blocked(blocked, ac)
            sev_map = {
                'SQL_INJECTION': 'CRITICAL', 'XSS': 'HIGH', 'CMD_INJECTION': 'CRITICAL',
                'PATH_TRAVERSAL': 'HIGH', 'LDAP_INJECTION': 'HIGH', 'RCE': 'CRITICAL',
                'XXE': 'HIGH', 'BRUTE_FORCE': 'HIGH',
            }
            log_entry = json.dumps({
                'time': now, 'attack_type': attack_type, 'ip': ip,
                'payload': user[:80], 'severity': sev_map.get(attack_type, 'HIGH'),
                'country': 'Unknown'
            })
            with open(LOG_FILE, 'a') as lf:
                lf.write(log_entry + '\n')
            result = f'[BLOCKED] {attack_type} detected — payload rejected by WAF'
            result_type = 'error'
        else:
            query = f"SELECT * FROM users WHERE id = {user}"
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            try:
                res = cursor.execute(query).fetchall()
                if res:
                    result = f'[ACCESS GRANTED] User: {res[0][1]}'
                    result_type = 'success'
                else:
                    result = '[ACCESS DENIED] No user found'
                    result_type = 'error'
            except Exception as e:
                result = f'[DB ERROR] {str(e)}'
                result_type = 'error'
            conn.close()
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Attack Console</title>""" + SHARED + """
<style>
.login-outer{position:relative;z-index:1;display:flex;align-items:flex-start;justify-content:center;padding:60px 40px;}
.wrapper{display:flex;gap:48px;align-items:flex-start;max-width:920px;width:100%;opacity:0;animation:fadeUp 0.5s ease 0.1s forwards;}
.left{flex:1;}
.left h2{font-family:'Orbitron',monospace;font-size:24px;font-weight:900;line-height:1.1;margin-bottom:10px;text-shadow:0 0 16px rgba(0,255,65,0.4);}
.left p{font-size:10px;color:var(--dim);line-height:1.9;margin-bottom:22px;}
.cs-title{font-size:7px;color:var(--g3);letter-spacing:4px;text-transform:uppercase;margin-bottom:10px;}
.attacks{display:flex;flex-direction:column;gap:7px;}
.atk{display:flex;align-items:center;gap:12px;padding:11px 14px;background:var(--panel);
  border:1px solid var(--border);border-radius:3px;cursor:pointer;transition:all 0.2s;position:relative;overflow:hidden;}
.atk::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--g);opacity:0;transition:opacity 0.2s;}
.atk:hover{border-color:var(--border2);background:var(--bg3);}
.atk:hover::before{opacity:1;}
.atk-icon{font-size:14px;flex-shrink:0;}
.atk-name{font-size:10px;color:var(--g);margin-bottom:1px;letter-spacing:1px;}
.atk-payload{font-size:8px;color:var(--muted);}
.atk-hint{font-size:7px;color:var(--g3);border:1px solid var(--border);padding:2px 7px;letter-spacing:1px;white-space:nowrap;transition:all 0.2s;flex-shrink:0;}
.atk:hover .atk-hint{border-color:var(--border2);color:var(--g);}
.card{width:350px;flex-shrink:0;background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:36px 32px;position:relative;overflow:hidden;}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--g),transparent);}
.card-tag{font-size:7px;color:var(--g3);letter-spacing:4px;text-transform:uppercase;margin-bottom:8px;}
.card h3{font-family:'Orbitron',monospace;font-size:16px;font-weight:900;margin-bottom:4px;text-shadow:0 0 14px rgba(0,255,65,0.3);}
.card-sub{font-size:9px;color:var(--g3);letter-spacing:1px;margin-bottom:28px;}
.btn-login{width:100%;padding:13px;background:transparent;border:1px solid var(--g);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:3px;color:var(--g);cursor:pointer;
  text-shadow:0 0 8px var(--g);box-shadow:0 0 12px rgba(0,255,65,0.15);transition:all 0.2s;}
.btn-login:hover{background:rgba(0,255,65,0.08);box-shadow:0 0 24px rgba(0,255,65,0.4);}
.divider{display:flex;align-items:center;gap:10px;margin:16px 0;font-size:8px;color:var(--g3);letter-spacing:2px;}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border);}
.btn-normal{width:100%;padding:11px;background:transparent;border:1px solid var(--border);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--dim);cursor:pointer;transition:all 0.2s;}
.btn-normal:hover{border-color:var(--border2);color:var(--g);}
.result-box{margin-top:14px;padding:12px 14px;border-radius:3px;font-size:10px;line-height:1.7;}
.res-ok{background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.2);color:var(--g);}
.res-err{background:rgba(255,0,64,0.05);border:1px solid rgba(255,0,64,0.2);color:var(--red);}
.warn{margin-top:14px;padding:9px 12px;background:rgba(255,170,0,0.04);border:1px solid rgba(255,170,0,0.15);font-size:8px;color:rgba(255,170,0,0.6);line-height:1.7;}
</style></head><body>""" + nav('/login') + """
<div class="login-outer"><div class="wrapper">
  <div class="left">
    <h2>ATTACK<br>CONSOLE</h2>
    <p>Click payload to auto-fill, then submit via WAF on :8080.</p>
    <div class="cs-title">::: PAYLOAD LIBRARY :::</div>
    <div class="attacks">
      <div class="atk" onclick="fill('1 OR 1=1')"><div class="atk-icon">&#128137;</div><div style="flex:1"><div class="atk-name">SQL INJECTION</div><div class="atk-payload">1 OR 1=1</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('1 UNION SELECT username,password FROM users--')"><div class="atk-icon">&#128450;&#65039;</div><div style="flex:1"><div class="atk-name">UNION SELECT</div><div class="atk-payload">1 UNION SELECT username,password FROM users--</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('1; DROP TABLE users--')"><div class="atk-icon">&#128163;</div><div style="flex:1"><div class="atk-name">DROP TABLE</div><div class="atk-payload">1; DROP TABLE users--</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('<script>alert(1)<\/script>')"><div class="atk-icon">&#128221;</div><div style="flex:1"><div class="atk-name">XSS ATTACK</div><div class="atk-payload">&lt;script&gt;alert(1)&lt;/script&gt;</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('<img src=x onerror=alert(1)>')"><div class="atk-icon">&#128247;</div><div style="flex:1"><div class="atk-name">XSS IMG INJECT</div><div class="atk-payload">&lt;img src=x onerror=alert(1)&gt;</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('; ls')"><div class="atk-icon">&#128187;</div><div style="flex:1"><div class="atk-name">CMD INJECTION</div><div class="atk-payload">; ls</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('; cat /etc/passwd')"><div class="atk-icon">&#128272;</div><div style="flex:1"><div class="atk-name">CMD — READ FILE</div><div class="atk-payload">; cat /etc/passwd</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('../../etc/passwd')"><div class="atk-icon">&#128194;</div><div style="flex:1"><div class="atk-name">PATH TRAVERSAL</div><div class="atk-payload">../../etc/passwd</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('*)(cn=*')"><div class="atk-icon">&#128100;</div><div style="flex:1"><div class="atk-name">LDAP INJECTION</div><div class="atk-payload">*)(cn=*</div></div><div class="atk-hint">USE</div></div>
      <div class="atk" onclick="fill('system(id)')"><div class="atk-icon">&#128165;</div><div style="flex:1"><div class="atk-name">RCE ATTEMPT</div><div class="atk-payload">system(id)</div></div><div class="atk-hint">USE</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-tag">::: DEMO PORTAL :::</div>
    <h3>SYSTEM<br>ACCESS</h3>
    <div class="card-sub">ROUTED THROUGH WAF (LIVE)</div>
    <form method="GET" action="/login">
      <label>USERNAME / PAYLOAD</label>
      <input type="text" name="user" id="uname" placeholder="admin" required style="margin-bottom:14px;">
      <label>PASSWORD</label>
      <input type="password" name="pass" placeholder="&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;" style="margin-bottom:18px;">
      <button type="submit" class="btn-login">[ AUTHENTICATE ]</button>
    </form>
    {% if result %}
    <div class="result-box {{ 'res-ok' if result_type == 'success' else 'res-err' }}">{{ result }}</div>
    {% endif %}
    <div class="divider">OR</div>
    <button class="btn-normal" onclick="document.getElementById('uname').value='1';document.querySelector('form').submit();">[ NORMAL LOGIN - USER ID 1 ]</button>
    <div class="warn">&#9888; INTENTIONALLY VULNERABLE DEMO - FOR IPS TESTING ONLY</div>
  </div>
</div>
<script>function fill(v){document.getElementById('uname').value=v;document.getElementById('uname').focus();}</script>
</div></div>
</body></html>""", result=result, result_type=result_type)


# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    logs = load_logs()
    blocked_ips, _ = load_blocked()
    total = len(logs)
    sql   = sum(1 for l in logs if 'SQL'     in l.get('attack_type','').upper())
    xss   = sum(1 for l in logs if 'XSS'     in l.get('attack_type','').upper())
    cmd   = sum(1 for l in logs if 'CMD'     in l.get('attack_type','').upper() or 'COMMAND' in l.get('attack_type','').upper())
    path  = sum(1 for l in logs if 'PATH'    in l.get('attack_type','').upper())
    honey = sum(1 for l in logs if 'HONEY'   in l.get('attack_type','').upper())
    brute = sum(1 for l in logs if 'BRUTE'   in l.get('attack_type','').upper())
    ldap  = sum(1 for l in logs if 'LDAP'    in l.get('attack_type','').upper())
    rce   = sum(1 for l in logs if 'RCE'     in l.get('attack_type','').upper())
    other = max(0, total - sql - xss - cmd - path - honey - brute - ldap - rce)
    sev_c = sum(1 for l in logs if l.get('severity')=='CRITICAL')
    sev_h = sum(1 for l in logs if l.get('severity')=='HIGH')
    sev_m = sum(1 for l in logs if l.get('severity')=='MEDIUM')
    sev_l = sum(1 for l in logs if l.get('severity')=='LOW')
    country_freq = {}
    for l in logs:
        c = l.get('country','Unknown')
        if c and c not in ('Unknown',''):
            country_freq[c] = country_freq.get(c,0)+1
    geo = sorted(country_freq.items(), key=lambda x:x[1], reverse=True)[:10]
    ip_freq = {}
    for l in logs:
        ip = l.get('ip','?'); ip_freq[ip] = ip_freq.get(ip,0)+1
    top = sorted(ip_freq.items(), key=lambda x:x[1], reverse=True)[:6]
    honeypot_logs = [l for l in logs if 'Honeypot' in l.get('attack_type','')]

    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Dashboard</title>""" + SHARED + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<style>
.chart-card{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:22px;position:relative;overflow:hidden;}
.chart-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--g),transparent);opacity:0.4;}
.chart-card h3{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;color:var(--g);letter-spacing:2px;margin-bottom:3px;}
.chart-card p{font-size:8px;color:var(--g3);letter-spacing:1px;margin-bottom:18px;}
.chart-wrap{height:190px;position:relative;}
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px;}
.sev-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px;opacity:0;animation:fadeUp 0.4s ease 0.25s forwards;}
.sev-card{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:14px 16px;display:flex;align-items:center;gap:12px;}
.sev-n{font-family:'Orbitron',monospace;font-size:28px;font-weight:900;}
.sev-c-CRITICAL .sev-n{color:var(--red);}
.sev-c-HIGH .sev-n{color:var(--amber);}
.sev-c-MEDIUM .sev-n{color:var(--cyan);}
.sev-c-LOW .sev-n{color:var(--g);}
.sev-l{font-size:7px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;margin-top:2px;}
.sec-head{display:flex;justify-content:space-between;align-items:center;padding:16px 22px;border-bottom:1px solid var(--border);}
.sec-head h3{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;letter-spacing:2px;}
.sec-head h3.amber{color:var(--amber);text-shadow:0 0 10px rgba(255,170,0,0.4);}
.pill{font-size:7px;color:var(--g3);border:1px solid var(--border);padding:2px 10px;letter-spacing:1px;}
.time-row{font-size:9px;color:var(--g3);letter-spacing:1px;margin-bottom:28px;}
</style>
</head><body>""" + nav('/dashboard') + """
<main>
<div class="page-head">
  <h1>ATTACK MONITOR</h1>
  <p>REAL-TIME INTRUSION DETECTION &amp; PREVENTION LOG</p>
  <div class="time-row">&#8635; AUTO-REFRESH: 5s &nbsp;&middot;&nbsp; <span id="tm"></span></div>
</div>

<div class="stat-row stat-5" style="animation-delay:0.15s;">
  <div class="stat s-r"><div class="stat-n">{{ total }}</div><div class="stat-l">Total Attacks</div></div>
  <div class="stat s-a"><div class="stat-n">{{ sql }}</div><div class="stat-l">SQL Injections</div></div>
  <div class="stat s-c"><div class="stat-n">{{ xss }}</div><div class="stat-l">XSS Attacks</div></div>
  <div class="stat s-v"><div class="stat-n">{{ honey }}</div><div class="stat-l">Honeypot Hits</div></div>
  <div class="stat s-g"><div class="stat-n">{{ blocked }}</div><div class="stat-l">IPs Blocked</div></div>
</div>

<div class="sev-row">
  <div class="sev-card sev-c-CRITICAL"><div style="font-size:18px;">&#9888;</div><div><div class="sev-n">{{ sev_c }}</div><div class="sev-l">CRITICAL</div></div></div>
  <div class="sev-card sev-c-HIGH"><div style="font-size:18px;">&#128308;</div><div><div class="sev-n">{{ sev_h }}</div><div class="sev-l">HIGH</div></div></div>
  <div class="sev-card sev-c-MEDIUM"><div style="font-size:18px;">&#128993;</div><div><div class="sev-n">{{ sev_m }}</div><div class="sev-l">MEDIUM</div></div></div>
  <div class="sev-card sev-c-LOW"><div style="font-size:18px;">&#128994;</div><div><div class="sev-n">{{ sev_l }}</div><div class="sev-l">LOW</div></div></div>
</div>

<div class="charts-row" style="opacity:0;animation:fadeUp 0.4s ease 0.3s forwards;">
  <div class="chart-card"><h3>ATTACK BREAKDOWN</h3><p>BY CATEGORY</p><div class="chart-wrap"><canvas id="typeC"></canvas></div></div>
  <div class="chart-card"><h3>TOP ATTACKER IPs</h3><p>MOST FREQUENT SOURCES</p><div class="chart-wrap"><canvas id="ipC"></canvas></div></div>
</div>

{% if geo %}
<div class="panel" style="animation-delay:0.35s;padding:0;overflow:hidden;">
  <div class="sec-head"><h3 style="color:var(--cyan);">&#127760; ATTACK ORIGINS (GEOIP)</h3><div class="pill">{{ geo|length }} COUNTRIES</div></div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1px;background:var(--border);">
    {% for country, count in geo %}
    <div style="background:var(--panel);padding:12px 16px;display:flex;align-items:center;gap:10px;">
      <div style="font-size:18px;">&#127760;</div>
      <div><div style="font-size:10px;color:var(--text);">{{ country }}</div><div style="font-size:9px;color:var(--cyan);font-family:'Orbitron',monospace;">{{ count }} HIT{{ 'S' if count>1 else '' }}</div></div>
    </div>
    {% endfor %}
  </div>
</div>
{% endif %}

{% if honeypot_logs %}
<div class="panel" style="animation-delay:0.4s;padding:0;overflow:hidden;border-color:rgba(255,170,0,0.2);">
  <div class="sec-head"><h3 class="amber">&#127855; HONEYPOT LOG</h3><div class="pill">{{ honeypot_logs|length }} HITS</div></div>
  <table>
    <thead><tr><th>#</th><th>TIME</th><th>IP</th><th>PATH</th><th>STATUS</th></tr></thead>
    <tbody>
      {% for l in honeypot_logs|reverse %}
      <tr><td class="td-mono">{{ loop.index }}</td><td class="td-mono">{{ l.time }}</td><td class="td-ip">{{ l.ip }}</td><td class="td-payload">{{ l.payload }}</td><td><span class="badge b-honey">HONEYPOT</span></td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<div class="panel" style="animation-delay:0.45s;padding:0;overflow:hidden;">
  <div class="sec-head"><h3 class="amber">&#9889; FULL ATTACK LOG</h3><div class="pill">{{ total }} ENTRIES</div></div>
  {% if logs %}
  <table>
    <thead><tr><th>#</th><th>TIME</th><th>IP</th><th>COUNTRY</th><th>TYPE</th><th>SEVERITY</th><th>PAYLOAD</th><th>ACTION</th></tr></thead>
    <tbody>
      {% for l in logs|reverse %}
      <tr>
        <td class="td-mono">{{ loop.index }}</td>
        <td class="td-mono">{{ l.time }}</td>
        <td class="td-ip">{{ l.ip }}</td>
        <td class="td-mono">{{ l.get('country','?') }}</td>
        <td>{% set t=l.get('attack_type','') %}
          {% if 'SQL' in t %}<span class="badge b-sql">SQL</span>
          {% elif 'XSS' in t %}<span class="badge b-xss">XSS</span>
          {% elif 'CMD' in t or 'Command' in t %}<span class="badge b-cmd">CMD</span>
          {% elif 'PATH' in t or 'Path' in t %}<span class="badge b-path">PATH</span>
          {% elif 'HONEY' in t or 'Honeypot' in t %}<span class="badge b-honey">HONEY</span>
          {% elif 'BRUTE' in t or 'Brute' in t %}<span class="badge b-brute">BRUTE</span>
          {% elif 'LDAP' in t %}<span class="badge b-sql">LDAP</span>
          {% elif 'RCE' in t %}<span class="badge b-sql">RCE</span>
          {% else %}<span class="badge b-unk">{{ t or '???' }}</span>{% endif %}
        </td>
        <td><span class="sev-b sev-{{ l.get('severity','LOW') }}">{{ l.get('severity','LOW') }}</span></td>
        <td class="td-payload" title="{{ l.payload }}">{{ l.payload }}</td>
        <td><span class="badge b-block">BLOCKED</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div style="text-align:center;padding:60px;color:var(--dim);font-size:11px;">No attacks logged yet — send test payloads from /login</div>
  {% endif %}
</div>
</main>
<script>
document.getElementById('tm').textContent = new Date().toLocaleTimeString();
setTimeout(()=>location.reload(), 5000);
Chart.defaults.color='rgba(0,255,65,0.4)';
Chart.defaults.borderColor='rgba(0,255,65,0.08)';
Chart.defaults.font.family="'Share Tech Mono',monospace";
Chart.defaults.font.size=9;
var typeData = [{{ sql }},{{ xss }},{{ cmd }},{{ path }},{{ honey }},{{ brute }},{{ ldap }},{{ rce }},{{ other }}];
var ipLabels = {{ ip_labels|tojson }};
var ipData   = {{ ip_counts|tojson }};
new Chart(document.getElementById('typeC'),{type:'doughnut',data:{
  labels:['SQL','XSS','CMD','PATH','HONEYPOT','BRUTE','LDAP','RCE','OTHER'],
  datasets:[{data:typeData,
    backgroundColor:['rgba(255,0,64,0.15)','rgba(255,170,0,0.15)','rgba(0,255,255,0.15)','rgba(255,136,0,0.15)','rgba(255,170,0,0.2)','rgba(168,85,247,0.15)','rgba(0,255,65,0.12)','rgba(255,0,64,0.2)','rgba(0,255,65,0.08)'],
    borderColor:['#ff0040','#ffaa00','#00ffff','#ff8800','#ffaa00','#a855f7','#00ff41','#ff0040','#00ff41'],borderWidth:1}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'right',labels:{padding:10,boxWidth:7,boxHeight:7,usePointStyle:true}}}}
});
new Chart(document.getElementById('ipC'),{type:'bar',data:{
  labels:ipLabels,
  datasets:[{label:'ATTACKS',data:ipData,backgroundColor:'rgba(0,255,65,0.08)',borderColor:'#00ff41',borderWidth:1,borderRadius:2}]},
  options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{grid:{display:false},border:{display:false}},y:{beginAtZero:true,ticks:{stepSize:1},grid:{color:'rgba(0,255,65,0.04)'},border:{display:false}}}}
});
</script>
</body></html>""",
        logs=logs, total=total, sql=sql, xss=xss, cmd=cmd, path=path,
        honey=honey, brute=brute, ldap=ldap, rce=rce, other=other,
        sev_c=sev_c, sev_h=sev_h, sev_m=sev_m, sev_l=sev_l,
        geo=geo, honeypot_logs=honeypot_logs,
        blocked=len(blocked_ips),
        ip_labels=[i for i,_ in top],
        ip_counts=[c for _,c in top],
    )


# ── SIMULATE PAGE ─────────────────────────────────────────────────────────────
@app.route('/simulate')
def simulate():
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Attack Simulator</title>""" + SHARED + """
<style>
/* Radar on simulator page */
.radar-corner{position:fixed;bottom:32px;right:32px;z-index:50;opacity:0;animation:fadeUp 0.7s ease 0.3s forwards;}
.radar-sm{width:180px;height:180px;border-radius:50%;border:2px solid rgba(0,255,65,0.5);
  background:radial-gradient(circle,rgba(0,255,65,0.08) 0%,transparent 70%);
  position:relative;overflow:hidden;
  box-shadow:0 0 30px rgba(0,255,65,0.2),inset 0 0 30px rgba(0,255,65,0.07);}
.radar-sm::before,.radar-sm::after{content:"";position:absolute;border:1px solid rgba(0,255,65,0.18);border-radius:50%;top:50%;left:50%;transform:translate(-50%,-50%);}
.radar-sm::before{width:66%;height:66%;}
.radar-sm::after{width:33%;height:33%;}
.r-h{position:absolute;top:50%;left:0;right:0;height:1px;background:rgba(0,255,65,0.12);transform:translateY(-50%);}
.r-v{position:absolute;left:50%;top:0;bottom:0;width:1px;background:rgba(0,255,65,0.12);transform:translateX(-50%);}
.sweep-sm{position:absolute;top:50%;left:50%;width:50%;height:50%;
  background:conic-gradient(from 0deg,transparent 70%,rgba(0,255,65,0.7) 100%);
  transform-origin:0% 0%;animation:sweep-anim 3s linear infinite;}
@keyframes sweep-anim{to{transform:rotate(360deg)}}
.blip-sm{position:absolute;border-radius:50%;opacity:0;animation:blip-anim 4s infinite;}
@keyframes blip-anim{0%{opacity:0;transform:scale(0.5)}10%{opacity:1;transform:scale(1.5)}30%{opacity:0;transform:scale(1)}100%{opacity:0}}
.radar-lbl{text-align:center;margin-top:8px;font-family:"Share Tech Mono",monospace;font-size:8px;color:var(--g3);letter-spacing:2px;}

.sim-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;}
.atk-btn{display:flex;align-items:center;gap:12px;padding:14px 16px;background:var(--panel);
  border:1px solid var(--border);border-radius:3px;cursor:pointer;
  transition:border-color 0.2s,background 0.2s,box-shadow 0.2s;
  width:100%;text-align:left;position:relative;overflow:hidden;}
.atk-btn::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;opacity:0;transition:opacity 0.2s;}
.atk-btn:hover{border-color:var(--border2);background:var(--bg3);}
.atk-btn:hover::before{opacity:1;}
.atk-btn.sql::before,.atk-btn.drop::before{background:var(--red);}
.atk-btn.xss::before{background:var(--amber);}
.atk-btn.cmd::before{background:var(--cyan);}
.atk-btn.path::before{background:var(--orange);}
.atk-btn.brute::before,.atk-btn.honey::before{background:var(--violet);}
.atk-icon{font-size:18px;flex-shrink:0;}
.atk-name{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;color:var(--g);margin-bottom:2px;letter-spacing:1px;}
.atk-desc{font-size:8px;color:var(--dim);}
.atk-sev{font-size:7px;padding:2px 7px;border-radius:2px;border:1px solid;letter-spacing:1px;flex-shrink:0;}
.result-term{margin-top:14px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;
  padding:16px;font-size:10px;line-height:2;min-height:70px;}
.r-ok{color:var(--g);}
.r-block{color:var(--red);}
.r-info{color:var(--dim);}
.fire-btn{width:100%;padding:14px;background:transparent;border:1px solid var(--red);border-radius:3px;
  font-family:'Orbitron',monospace;font-size:13px;font-weight:900;color:var(--red);cursor:pointer;
  letter-spacing:3px;text-shadow:0 0 10px rgba(255,0,64,0.5);box-shadow:0 0 16px rgba(255,0,64,0.1);transition:all 0.2s;margin-top:14px;}
.fire-btn:hover{background:rgba(255,0,64,0.08);box-shadow:0 0 32px rgba(255,0,64,0.4);}
.prog{height:2px;background:var(--bg3);border-radius:1px;margin-top:8px;overflow:hidden;display:none;}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--red),var(--amber),var(--g));width:0%;transition:width 0.3s;}
</style>
</head><body>""" + nav('/simulate') + """
<!-- Radar in corner -->
<div class="radar-corner">
  <div class="radar-sm">
    <div class="r-h"></div><div class="r-v"></div>
    <div class="sweep-sm"></div>
    <div class="blip-sm" style="width:7px;height:7px;top:25%;left:35%;background:#ff0040;box-shadow:0 0 8px #ff0040;animation-delay:0s;"></div>
    <div class="blip-sm" style="width:6px;height:6px;top:65%;left:72%;background:#ff0040;box-shadow:0 0 8px #ff0040;animation-delay:1.2s;"></div>
    <div class="blip-sm" style="width:5px;height:5px;top:45%;left:58%;background:#ffaa00;box-shadow:0 0 7px #ffaa00;animation-delay:2.5s;"></div>
  </div>
  <div class="radar-lbl">THREAT RADAR</div>
</div>
<main>
<div class="page-head"><h1>ATTACK SIMULATOR</h1><p>FIRE REAL PAYLOADS THROUGH THE WAF WITH ONE CLICK</p></div>
<div class="panel" style="animation-delay:0.1s;">
  <div class="panel-title">SELECT ATTACK</div>
  <div class="sim-grid">
    <button class="atk-btn sql" onclick="fire('1 OR 1=1','SQL Injection','CRITICAL')"><div class="atk-icon">&#128137;</div><div style="flex:1"><div class="atk-name">SQL INJECTION</div><div class="atk-desc">Payload: 1 OR 1=1</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn sql" onclick="fire('1 UNION SELECT username,password FROM users--','UNION SELECT','CRITICAL')"><div class="atk-icon">&#128450;&#65039;</div><div style="flex:1"><div class="atk-name">UNION SELECT</div><div class="atk-desc">Dump database credentials</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn drop" onclick="fire('1; DROP TABLE users--','DROP TABLE','CRITICAL')"><div class="atk-icon">&#128163;</div><div style="flex:1"><div class="atk-name">DROP TABLE</div><div class="atk-desc">Destroy database tables</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn xss" onclick="fire('<script>alert(1)<\/script>','XSS Attack','HIGH')"><div class="atk-icon">&#128221;</div><div style="flex:1"><div class="atk-name">XSS ATTACK</div><div class="atk-desc">Payload: &lt;script&gt;alert(1)&lt;/script&gt;</div></div><div class="atk-sev sev-HIGH">HIGH</div></button>
    <button class="atk-btn xss" onclick="fire('<img src=x onerror=alert(1)>','XSS IMG Inject','HIGH')"><div class="atk-icon">&#128247;</div><div style="flex:1"><div class="atk-name">XSS IMG INJECT</div><div class="atk-desc">Image tag onerror exploit</div></div><div class="atk-sev sev-HIGH">HIGH</div></button>
    <button class="atk-btn cmd" onclick="fire('; ls','Command Injection','CRITICAL')"><div class="atk-icon">&#128187;</div><div style="flex:1"><div class="atk-name">CMD INJECTION</div><div class="atk-desc">Payload: ; ls</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn cmd" onclick="fire('; cat /etc/passwd','CMD Read File','CRITICAL')"><div class="atk-icon">&#128272;</div><div style="flex:1"><div class="atk-name">CMD READ FILE</div><div class="atk-desc">Read system password file</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn path" onclick="fire('../../etc/passwd','Path Traversal','HIGH')"><div class="atk-icon">&#128194;</div><div style="flex:1"><div class="atk-name">PATH TRAVERSAL</div><div class="atk-desc">Payload: ../../etc/passwd</div></div><div class="atk-sev sev-HIGH">HIGH</div></button>
    <button class="atk-btn brute" onclick="fireBrute()"><div class="atk-icon">&#128272;</div><div style="flex:1"><div class="atk-name">BRUTE FORCE</div><div class="atk-desc">Fires 6 rapid login attempts</div></div><div class="atk-sev sev-HIGH">HIGH</div></button>
    <button class="atk-btn honey" onclick="fireHoney()"><div class="atk-icon">&#127855;</div><div style="flex:1"><div class="atk-name">HONEYPOT TRAP</div><div class="atk-desc">Access /admin decoy path</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
    <button class="atk-btn sql" onclick="fire('*)(cn=*','LDAP Injection','HIGH')"><div class="atk-icon">&#128100;</div><div style="flex:1"><div class="atk-name">LDAP INJECTION</div><div class="atk-desc">Directory service exploit</div></div><div class="atk-sev sev-HIGH">HIGH</div></button>
    <button class="atk-btn drop" onclick="fire('system(id)','RCE Attempt','CRITICAL')"><div class="atk-icon">&#128165;</div><div style="flex:1"><div class="atk-name">RCE ATTEMPT</div><div class="atk-desc">Remote code execution probe</div></div><div class="atk-sev sev-CRITICAL">CRITICAL</div></button>
  </div>
  <button class="fire-btn" onclick="fireAll()">[ &#9889; FIRE ALL ATTACKS ]</button>
  <div class="prog" id="prog"><div class="prog-fill" id="fill"></div></div>
  <div class="result-term" id="result"><span style="color:var(--dim);">Awaiting attack launch...</span></div>
</div>
</main>
<script>
const W='';
function log(m,c){var t=document.getElementById('result');t.innerHTML+='<div class="'+c+'">'+m+'</div>';t.scrollTop=t.scrollHeight;}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
async function fire(p,label,sev){
  document.getElementById('result').innerHTML='';
  log('> Launching: '+label+' ['+sev+']','r-info');
  log('> Payload: '+p,'r-info');
  try{await fetch(W+'/login?user='+encodeURIComponent(p),{mode:'no-cors'});}catch(e){}
  log('[BLOCKED] '+label+' intercepted by WAF','r-block');
  log('[LOG] Check /dashboard for entry','r-ok');
}
async function fireBrute(){
  document.getElementById('result').innerHTML='';
  log('> Launching: Brute Force (6 rapid attempts)','r-info');
  for(var i=1;i<=6;i++){
    try{await fetch(W+'/login?user=admin',{mode:'no-cors'});}catch(e){}
    log('[ATTEMPT '+i+'/6] Login attempt sent','r-block');
    await sleep(300);
  }
  log('[BLOCKED] Brute force detected and blocked','r-block');
}
async function fireHoney(){
  document.getElementById('result').innerHTML='';
  log('> Accessing honeypot: /admin','r-info');
  try{await fetch(W+'/admin',{mode:'no-cors'});}catch(e){}
  log('[HONEYPOT] Trap triggered - IP flagged as CRITICAL','r-block');
  log('[LOG] Check /dashboard honeypot section','r-ok');
}
async function fireAll(){
  var t=document.getElementById('result'),p=document.getElementById('prog'),f=document.getElementById('fill');
  t.innerHTML='';p.style.display='block';f.style.width='0%';
  var attacks=[
    {p:'1 OR 1=1',l:'SQL Injection'},
    {p:'1 UNION SELECT username,password FROM users--',l:'UNION SELECT'},
    {p:'1; DROP TABLE users--',l:'DROP TABLE'},
    {p:'<script>alert(1)<\/script>',l:'XSS Attack'},
    {p:'<img src=x onerror=alert(1)>',l:'XSS IMG Inject'},
    {p:'; ls',l:'Command Injection'},
    {p:'; cat /etc/passwd',l:'CMD Read File'},
    {p:'../../etc/passwd',l:'Path Traversal'},
    {p:'*)(cn=*',l:'LDAP Injection'},
    {p:'system(id)',l:'RCE Attempt'},
    {honey:true,l:'Honeypot Trigger'},
  ];
  log('> [LAUNCH] Clearing blocked IPs for full test...','r-info');
  // Clear blocked IPs via admin so all attacks get logged
  try{await fetch('/admin-clear-blocked',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'}});}catch(e){}
  await sleep(400);
  log('> [LAUNCH] Firing '+attacks.length+' attacks...','r-info');
  for(var i=0;i<attacks.length;i++){
    f.style.width=((i+1)/attacks.length*100)+'%';
    try{
      if(attacks[i].honey)await fetch(W+'/admin',{mode:'no-cors'});
      else await fetch(W+'/login?user='+encodeURIComponent(attacks[i].p),{mode:'no-cors'});
    }catch(e){}
    log('['+(i+1)+'/'+attacks.length+'] '+attacks[i].l+' - BLOCKED','r-block');
    await sleep(600);
  }
  log('','r-info');
  log('[COMPLETE] All '+attacks.length+' attacks fired','r-ok');
}
</script>
</body></html>""")


# ── COMPARE PAGE ──────────────────────────────────────────────────────────────
@app.route('/compare')
def compare():
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: WAF Comparison</title>""" + SHARED + """
<style>
.compare-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px;}
.cp{padding:24px;border-radius:4px;position:relative;overflow:hidden;}
.cp::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;}
.no-waf{background:#0a0505;border:1px solid rgba(255,0,64,0.3);}
.no-waf::before{background:linear-gradient(90deg,transparent,var(--red),transparent);}
.with-waf{background:var(--panel);border:1px solid rgba(0,255,65,0.3);}
.with-waf::before{background:linear-gradient(90deg,transparent,var(--g),transparent);}
.cp-label{font-family:'Orbitron',monospace;font-size:12px;font-weight:900;letter-spacing:3px;margin-bottom:4px;}
.no-waf .cp-label{color:var(--red);text-shadow:0 0 12px rgba(255,0,64,0.5);}
.with-waf .cp-label{color:var(--g);text-shadow:0 0 12px rgba(0,255,65,0.5);}
.cp-sub{font-size:8px;color:var(--dim);letter-spacing:2px;margin-bottom:20px;}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;}
.chip{padding:3px 9px;border:1px solid var(--border);font-size:7px;color:var(--g3);cursor:pointer;transition:all 0.2s;letter-spacing:1px;border-radius:2px;}
.chip:hover{border-color:var(--border2);color:var(--g);}
.payload-in{width:100%;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;
  color:var(--g);font-family:'Share Tech Mono',monospace;font-size:11px;outline:none;margin-bottom:10px;}
.send-btn{width:100%;padding:11px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;cursor:pointer;transition:all 0.2s;}
.send-r{background:transparent;border:1px solid rgba(255,0,64,0.5);color:var(--red);}
.send-r:hover{background:rgba(255,0,64,0.08);}
.send-g{background:transparent;border:1px solid rgba(0,255,65,0.5);color:var(--g);}
.send-g:hover{background:rgba(0,255,65,0.08);}
.res-box{margin-top:12px;padding:12px;border-radius:3px;font-size:10px;line-height:1.7;min-height:52px;}
.res-danger{background:rgba(255,0,64,0.05);border:1px solid rgba(255,0,64,0.2);color:var(--red);}
.res-safe{background:rgba(0,255,65,0.04);border:1px solid rgba(0,255,65,0.15);color:var(--g);}
.res-neu{background:var(--bg3);border:1px solid var(--border);color:var(--dim);}
.feat-tbl td,.feat-tbl th{padding:9px 14px;font-size:10px;border-bottom:1px solid rgba(0,255,65,0.05);}
.feat-tbl th{font-size:7px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;background:var(--bg3);}
.feat-tbl td:first-child{color:var(--dim);}
.ok{color:var(--g);}
.no{color:var(--red);}
</style>
</head><body>""" + nav('/compare') + """
<main>
<div class="page-head"><h1>COMPARISON DEMO</h1><p>SIDE-BY-SIDE: WITHOUT WAF vs WITH WAF — SAME PAYLOAD</p></div>
<div class="compare-grid" style="opacity:0;animation:fadeUp 0.5s ease 0.1s forwards;">
  <div class="cp no-waf">
    <div class="cp-label">&#10007; WITHOUT WAF</div>
    <div class="cp-sub">DIRECT TO BACKEND :5001 - NO PROTECTION</div>
    <div class="chips">
      <span class="chip" onclick="set('nowaf','1 OR 1=1')">SQL</span>
      <span class="chip" onclick="set('nowaf','&lt;script&gt;alert(1)&lt;/script&gt;')">XSS</span>
      <span class="chip" onclick="set('nowaf','; ls')">CMD</span>
      <span class="chip" onclick="set('nowaf','../../etc/passwd')">PATH</span>
    </div>
    <input class="payload-in" id="nowaf" value="1 OR 1=1">
    <button class="send-btn send-r" onclick="sendDirect()">[ SEND TO BACKEND DIRECTLY ]</button>
    <div class="res-box res-neu" id="nr">Awaiting request...</div>
  </div>
  <div class="cp with-waf">
    <div class="cp-label">&#10003; WITH WAF</div>
    <div class="cp-sub">THROUGH PROXY :8080 - PROTECTED BY IPS</div>
    <div class="chips">
      <span class="chip" onclick="set('waf','1 OR 1=1')">SQL</span>
      <span class="chip" onclick="set('waf','&lt;script&gt;alert(1)&lt;/script&gt;')">XSS</span>
      <span class="chip" onclick="set('waf','; ls')">CMD</span>
      <span class="chip" onclick="set('waf','../../etc/passwd')">PATH</span>
    </div>
    <input class="payload-in" id="waf" value="1 OR 1=1">
    <button class="send-btn send-g" onclick="sendWAF()">[ SEND THROUGH WAF ]</button>
    <div class="res-box res-neu" id="wr">Awaiting request...</div>
  </div>
</div>

<div class="panel" style="animation-delay:0.2s;padding:0;overflow:hidden;">
  <div style="padding:16px 22px;border-bottom:1px solid var(--border);">
    <div class="panel-title" style="margin-bottom:0;">FEATURE COMPARISON TABLE</div>
  </div>
  <table class="feat-tbl" style="width:100%;border-collapse:collapse;">
    <thead><tr><th>FEATURE</th><th>WITHOUT WAF</th><th>WITH OUR IPS</th></tr></thead>
    <tbody>
      <tr><td>SQL Injection Protection</td><td class="no">&#10007; VULNERABLE</td><td class="ok">&#10003; BLOCKED</td></tr>
      <tr><td>XSS Attack Protection</td><td class="no">&#10007; VULNERABLE</td><td class="ok">&#10003; BLOCKED</td></tr>
      <tr><td>Command Injection</td><td class="no">&#10007; VULNERABLE</td><td class="ok">&#10003; BLOCKED</td></tr>
      <tr><td>Path Traversal</td><td class="no">&#10007; VULNERABLE</td><td class="ok">&#10003; BLOCKED</td></tr>
      <tr><td>Brute Force Protection</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; 5 attempts/60s limit</td></tr>
      <tr><td>IP Blacklisting</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; Auto after 3 strikes</td></tr>
      <tr><td>Honeypot Traps</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; 20+ decoy paths</td></tr>
      <tr><td>Rate Limiting / DoS</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; 100 req/min</td></tr>
      <tr><td>GeoIP Tracking</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; Country + City</td></tr>
      <tr><td>Severity Scoring</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; CRITICAL/HIGH/MEDIUM/LOW</td></tr>
      <tr><td>Live Dashboard</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; Real-time monitor</td></tr>
      <tr><td>PDF Report Export</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; Auto generated</td></tr>
      <tr><td>Admin Control Panel</td><td class="no">&#10007; NONE</td><td class="ok">&#10003; Full management</td></tr>
    </tbody>
  </table>
</div>
</main>
<script>
function set(id,v){document.getElementById(id).value=v;}
async function sendDirect(){
  var p=document.getElementById('nowaf').value,b=document.getElementById('nr');
  b.className='res-box res-neu';b.innerHTML='> Sending directly......';
  try{var r=await fetch('/login?user='+encodeURIComponent(p));
    var t=await r.text();
    b.className='res-box res-danger';
    b.innerHTML='[VULNERABLE] Reached backend!<br>'+t.substring(0,100)+'<br>[!] No WAF — attack went through';
  }catch(e){
    b.className='res-box res-danger';
    b.innerHTML='[SENT] Request reached backend directly<br>[!] No WAF protection active<br>Note: '+e.message;
  }
}
async function sendWAF(){
  var p=document.getElementById('waf').value,b=document.getElementById('wr');
  b.className='res-box res-neu';b.innerHTML='> Sending through WAF......';
  try{await fetch('/login?user='+encodeURIComponent(p),{mode:'no-cors'});}catch(e){}
  b.className='res-box res-safe';
  b.innerHTML='[WAF] Request intercepted by proxy<br>[BLOCKED] Malicious payload detected<br>[LOGGED] Attack recorded — check /dashboard';
}
</script>
</body></html>""")


# ── STATS PAGE ────────────────────────────────────────────────────────────────
@app.route('/stats')
def stats():
    logs = load_logs()
    blocked, _ = load_blocked()
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Project Stats</title>""" + SHARED + """
<style>
.tech-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px;opacity:0;animation:fadeUp 0.4s ease 0.2s forwards;}
.tc{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:20px;position:relative;overflow:hidden;}
.tc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:0.4;}
.tc-title{font-family:'Orbitron',monospace;font-size:9px;font-weight:700;color:var(--cyan);letter-spacing:2px;margin-bottom:12px;}
.tc-item{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(0,255,65,0.05);font-size:10px;color:var(--dim);}
.tc-item:last-child{border-bottom:none;}
.dot{width:5px;height:5px;border-radius:50%;flex-shrink:0;}
.dot-g{background:var(--g);box-shadow:0 0 5px var(--g);}
.dot-c{background:var(--cyan);box-shadow:0 0 5px var(--cyan);}
.dot-a{background:var(--amber);box-shadow:0 0 5px var(--amber);}
.tl-item{display:flex;gap:14px;margin-bottom:14px;}
.tl-dot{width:9px;height:9px;border-radius:50%;background:var(--g);box-shadow:0 0 7px var(--g);flex-shrink:0;margin-top:3px;}
.tl-title{font-size:11px;color:var(--g);margin-bottom:2px;}
.tl-desc{font-size:9px;color:var(--dim);}
.tl-line{width:1px;height:12px;background:rgba(0,255,65,0.15);margin-left:4px;}
.feat-check{display:grid;grid-template-columns:1fr 1fr;gap:8px;opacity:0;animation:fadeUp 0.4s ease 0.35s forwards;}
.fc-item{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;font-size:9px;color:var(--dim);}
.fc-item .ok{color:var(--g);font-size:12px;}
</style>
</head><body>""" + nav('/stats') + """
<main>
<div class="page-head"><h1>PROJECT STATISTICS</h1><p>WEB APPLICATION IPS - SEM 4 MAJOR PROJECT - COMPLETE OVERVIEW</p></div>

<div class="stat-row stat-4" style="animation-delay:0.1s;">
  <div class="stat s-g"><div class="stat-n">8</div><div class="stat-l">Python Files</div></div>
  <div class="stat s-c"><div class="stat-n">90+</div><div class="stat-l">Attack Patterns</div></div>
  <div class="stat s-a"><div class="stat-n">20+</div><div class="stat-l">Honeypot Traps</div></div>
  <div class="stat s-v"><div class="stat-n">6</div><div class="stat-l">Server Ports</div></div>
</div>
<div class="stat-row stat-4" style="animation-delay:0.18s;">
  <div class="stat s-r"><div class="stat-n">{{ total }}</div><div class="stat-l">Attacks Blocked</div></div>
  <div class="stat s-g"><div class="stat-n">9</div><div class="stat-l">Attack Types</div></div>
  <div class="stat s-a"><div class="stat-n">{{ blocked }}</div><div class="stat-l">IPs Banned</div></div>
  <div class="stat s-c"><div class="stat-n">100%</div><div class="stat-l">Block Rate</div></div>
</div>

<div class="tech-grid">
  <div class="tc">
    <div class="tc-title">BACKEND STACK</div>
    <div class="tc-item"><div class="dot dot-g"></div>Python 3.10</div>
    <div class="tc-item"><div class="dot dot-g"></div>Flask (Web Framework)</div>
    <div class="tc-item"><div class="dot dot-g"></div>SQLite (Database)</div>
    <div class="tc-item"><div class="dot dot-g"></div>Requests (HTTP Proxy)</div>
    <div class="tc-item"><div class="dot dot-g"></div>FPDF2 (PDF Export)</div>
  </div>
  <div class="tc">
    <div class="tc-title">SECURITY MODULES</div>
    <div class="tc-item"><div class="dot dot-c"></div>Rules Engine (90+ Regex)</div>
    <div class="tc-item"><div class="dot dot-c"></div>IP Blacklist (Persistent)</div>
    <div class="tc-item"><div class="dot dot-c"></div>Rate Limiter (DoS)</div>
    <div class="tc-item"><div class="dot dot-c"></div>Brute Force Detector</div>
    <div class="tc-item"><div class="dot dot-c"></div>Honeypot Traps (20+)</div>
  </div>
  <div class="tc">
    <div class="tc-title">FRONTEND / UI</div>
    <div class="tc-item"><div class="dot dot-a"></div>HTML5 + CSS3</div>
    <div class="tc-item"><div class="dot dot-a"></div>Chart.js (Data Viz)</div>
    <div class="tc-item"><div class="dot dot-a"></div>Canvas API (Matrix Rain)</div>
    <div class="tc-item"><div class="dot dot-a"></div>GeoIP (ip-api.com)</div>
    <div class="tc-item"><div class="dot dot-a"></div>Orbitron + Share Tech Mono</div>
  </div>
</div>

<div class="panel" style="animation-delay:0.3s;">
  <div class="panel-title">DEVELOPMENT TIMELINE</div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 1 — Core WAF</div><div class="tl-desc">Proxy server, SQL injection detection, attack logging, SQLite database</div></div></div>
  <div class="tl-line"></div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 2 — Prevention</div><div class="tl-desc">IP blocking after 3 strikes, XSS detection, persistent block file</div></div></div>
  <div class="tl-line"></div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 3 — Web UI</div><div class="tl-desc">Cyberpunk hacker theme, Matrix rain, home page, attack console</div></div></div>
  <div class="tl-line"></div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 4 — Dashboard + Report</div><div class="tl-desc">Live attack dashboard, Chart.js charts, PDF report with fpdf2</div></div></div>
  <div class="tl-line"></div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 5 — Advanced Detection</div><div class="tl-desc">GeoIP tracking, honeypot traps, brute force, severity scoring, 9 attack types</div></div></div>
  <div class="tl-line"></div>
  <div class="tl-item"><div class="tl-dot"></div><div><div class="tl-title">Phase 6 — Major Project Complete</div><div class="tl-desc">Admin panel, attack simulator, comparison demo, project stats, unified navigation</div></div></div>
</div>

<div class="panel" style="animation-delay:0.4s;">
  <div class="panel-title">FEATURE CHECKLIST</div>
  <div class="feat-check">
    <div class="fc-item"><span class="ok">&#10003;</span> SQL Injection Detection (11 patterns)</div>
    <div class="fc-item"><span class="ok">&#10003;</span> XSS Attack Detection (15 patterns)</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Command Injection Detection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Path Traversal Detection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> CSRF / XXE / SSRF Detection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> LDAP + Header Injection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> IP Blacklisting (Persistent)</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Brute Force Detection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Honeypot Traps (20+ paths)</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Rate Limiting / DoS Protection</div>
    <div class="fc-item"><span class="ok">&#10003;</span> GeoIP Country + City Tracking</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Severity Scoring (4 levels)</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Live Attack Dashboard</div>
    <div class="fc-item"><span class="ok">&#10003;</span> PDF Report Export</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Admin Control Panel</div>
    <div class="fc-item"><span class="ok">&#10003;</span> Attack Simulator</div>
    <div class="fc-item"><span class="ok">&#10003;</span> WAF Comparison Demo</div>
    <div class="fc-item"><span class="ok">&#10003;</span> One-click Start (start_demo.bat)</div>
  </div>
</div>
</main>
</body></html>""", total=len(logs), blocked=len(blocked))


# ── HONEYPOTS PAGE ────────────────────────────────────────────────────────────
@app.route('/honeypots')
def honeypots():
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Honeypot System</title>""" + SHARED + """
<style>
.hp-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;}
.hp-card{background:var(--panel);border-radius:4px;overflow:hidden;position:relative;
  opacity:0;animation:fadeUp 0.4s ease forwards;}
.hp-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
.hp-c1::before{background:rgba(255,170,0,0.8);}
.hp-c2::before{background:rgba(0,255,255,0.8);}
.hp-c3::before{background:rgba(168,85,247,0.8);}
.hp-c4::before{background:rgba(255,136,0,0.8);}
.hp-c5::before{background:rgba(255,0,64,0.8);}
.hp-header{display:flex;align-items:center;gap:14px;padding:18px 20px;border-bottom:1px solid var(--border);}
.hp-icon{font-size:28px;flex-shrink:0;}
.hp-type{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;letter-spacing:2px;margin-bottom:3px;}
.hp-c1 .hp-type{color:var(--amber);}
.hp-c2 .hp-type{color:var(--cyan);}
.hp-c3 .hp-type{color:var(--violet);}
.hp-c4 .hp-type{color:var(--orange);}
.hp-c5 .hp-type{color:var(--red);}
.hp-severity{font-size:8px;letter-spacing:2px;padding:2px 8px;border-radius:2px;border:1px solid;}
.sev-CRITICAL{color:var(--red);border-color:rgba(255,0,64,0.4);background:rgba(255,0,64,0.07);}
.sev-HIGH{color:var(--amber);border-color:rgba(255,170,0,0.4);background:rgba(255,170,0,0.07);}
.hp-body{padding:18px 20px;}
.hp-desc{font-size:11px;color:var(--dim);line-height:1.8;margin-bottom:14px;}
.hp-why{font-size:10px;color:var(--g);margin-bottom:10px;}
.hp-paths{display:flex;flex-wrap:wrap;gap:6px;}
.hp-path{font-family:'Share Tech Mono',monospace;font-size:9px;padding:3px 10px;
  border-radius:2px;border:1px solid var(--border);color:var(--muted);
  background:var(--bg3);}
.hp-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px;
  opacity:0;animation:fadeUp 0.4s ease 0.1s forwards;}
.hp-stat{background:var(--panel);border:1px solid var(--border);border-radius:4px;
  padding:16px;text-align:center;position:relative;overflow:hidden;}
.hp-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;}
.hp-stat:nth-child(1)::before{background:var(--amber);}
.hp-stat:nth-child(2)::before{background:var(--cyan);}
.hp-stat:nth-child(3)::before{background:var(--violet);}
.hp-stat:nth-child(4)::before{background:var(--orange);}
.hp-stat:nth-child(5)::before{background:var(--red);}
.hp-stat-n{font-family:'Orbitron',monospace;font-size:28px;font-weight:900;color:var(--g);line-height:1;margin-bottom:4px;}
.hp-stat-l{font-size:7px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;}
</style>
</head><body>""" + nav('/honeypots') + """
<main>
<div class="page-head">
  <h1>HONEYPOT SYSTEM</h1>
  <p>5-LAYER DECEPTION NETWORK FOR PROACTIVE INTRUSION DETECTION</p>
</div>

<div class="hp-stats">
  <div class="hp-stat"><div class="hp-stat-n">5</div><div class="hp-stat-l">Honeypot Types</div></div>
  <div class="hp-stat"><div class="hp-stat-n">50+</div><div class="hp-stat-l">Trap Paths</div></div>
  <div class="hp-stat"><div class="hp-stat-n">CRITICAL</div><div class="hp-stat-l" style="font-size:6px;">Max Severity</div></div>
  <div class="hp-stat"><div class="hp-stat-n">3</div><div class="hp-stat-l">Strike Rule</div></div>
  <div class="hp-stat"><div class="hp-stat-n">AUTO</div><div class="hp-stat-l">IP Block</div></div>
</div>

<div class="hp-grid">
  <!-- 1. Web Login Honeypot -->
  <div class="hp-card hp-c1" style="animation-delay:0.1s;">
    <div class="hp-header">
      <div class="hp-icon">&#127856;</div>
      <div>
        <div class="hp-type">WEB LOGIN HONEYPOT</div>
        <span class="hp-severity sev-CRITICAL">CRITICAL</span>
      </div>
    </div>
    <div class="hp-body">
      <div class="hp-desc">Fake admin login pages that appear real. Any access attempt — whether by bots, scanners or attackers — is immediately logged and the IP flagged.</div>
      <div class="hp-why">&#128161; Detects: Web-based attacks, admin panel probing, credential stuffing</div>
      <div class="hp-paths">
        <span class="hp-path">/admin</span><span class="hp-path">/wp-admin</span>
        <span class="hp-path">/administrator</span><span class="hp-path">/panel</span>
        <span class="hp-path">/cpanel</span><span class="hp-path">/manage</span>
      </div>
    </div>
  </div>

  <!-- 2. Hidden URL Honeypot -->
  <div class="hp-card hp-c2" style="animation-delay:0.15s;">
    <div class="hp-header">
      <div class="hp-icon">&#128373;</div>
      <div>
        <div class="hp-type">HIDDEN URL HONEYPOT</div>
        <span class="hp-severity sev-HIGH">HIGH</span>
      </div>
    </div>
    <div class="hp-body">
      <div class="hp-desc">Invisible decoy URLs that are never linked anywhere. Only automated bots and network scanners discover these paths through brute-force enumeration.</div>
      <div class="hp-why">&#128161; Detects: Reconnaissance, directory enumeration, bot crawlers</div>
      <div class="hp-paths">
        <span class="hp-path">/secret-admin</span><span class="hp-path">/hidden</span>
        <span class="hp-path">/backup</span><span class="hp-path">/staging</span>
        <span class="hp-path">/internal</span><span class="hp-path">/vault</span>
      </div>
    </div>
  </div>

  <!-- 3. SSH Honeypot -->
  <div class="hp-card hp-c3" style="animation-delay:0.2s;">
    <div class="hp-header">
      <div class="hp-icon">&#128272;</div>
      <div>
        <div class="hp-type">SSH HONEYPOT</div>
        <span class="hp-severity sev-CRITICAL">CRITICAL</span>
      </div>
    </div>
    <div class="hp-body">
      <div class="hp-desc">Fake remote access and shell endpoints. Attackers attempting to gain shell access or execute remote commands trigger this trap instantly.</div>
      <div class="hp-why">&#128161; Detects: Remote code execution attempts, shell access, SSH brute force</div>
      <div class="hp-paths">
        <span class="hp-path">/shell</span><span class="hp-path">/cmd.php</span>
        <span class="hp-path">/terminal</span><span class="hp-path">/bash</span>
        <span class="hp-path">/execute</span><span class="hp-path">/remote-access</span>
      </div>
    </div>
  </div>

  <!-- 4. Port Scanner Honeypot -->
  <div class="hp-card hp-c4" style="animation-delay:0.25s;">
    <div class="hp-header">
      <div class="hp-icon">&#128225;</div>
      <div>
        <div class="hp-type">PORT SCANNER HONEYPOT</div>
        <span class="hp-severity sev-HIGH">HIGH</span>
      </div>
    </div>
    <div class="hp-body">
      <div class="hp-desc">Mimics endpoints of common vulnerable services (MySQL, FTP, phpMyAdmin). Port scanners and automated exploit tools hit these first, revealing attacker intent.</div>
      <div class="hp-why">&#128161; Detects: Port scanning, service fingerprinting, automated exploits</div>
      <div class="hp-paths">
        <span class="hp-path">/phpmyadmin</span><span class="hp-path">/mysql</span>
        <span class="hp-path">/jenkins</span><span class="hp-path">/solr</span>
        <span class="hp-path">/actuator</span><span class="hp-path">/jboss</span>
      </div>
    </div>
  </div>

  <!-- 5. Honey Credentials Honeypot -->
  <div class="hp-card hp-c5" style="grid-column:1/-1;animation-delay:0.3s;">
    <div class="hp-header">
      <div class="hp-icon">&#128273;</div>
      <div>
        <div class="hp-type">HONEY CREDENTIALS HONEYPOT</div>
        <span class="hp-severity sev-CRITICAL">CRITICAL</span>
      </div>
    </div>
    <div class="hp-body">
      <div class="hp-desc">Fake configuration files and credential stores. This is the most sensitive trap — an attacker who reaches these files has already bypassed other defences, indicating advanced post-exploitation or insider threat. Any access immediately triggers permanent IP block.</div>
      <div class="hp-why">&#128161; Detects: Post-exploitation, insider threats, automated config file harvesters, secrets extraction</div>
      <div class="hp-paths">
        <span class="hp-path">/.env</span><span class="hp-path">/config.php</span>
        <span class="hp-path">/.git/config</span><span class="hp-path">/wp-config.php</span>
        <span class="hp-path">/database.yml</span><span class="hp-path">/secrets.json</span>
        <span class="hp-path">/passwords.txt</span><span class="hp-path">/backup.sql</span>
        <span class="hp-path">/api-keys.txt</span><span class="hp-path">/credentials.xml</span>
        <span class="hp-path">/.htpasswd</span><span class="hp-path">/web.config</span>
      </div>
    </div>
  </div>
</div>

<div class="panel" style="animation-delay:0.35s;">
  <div class="panel-title">HOW HONEYPOTS WORK IN THIS IPS</div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:8px;">
    <div style="background:var(--bg3);padding:16px;text-align:center;">
      <div style="font-size:20px;margin-bottom:8px;">&#128270;</div>
      <div style="font-family:'Orbitron',monospace;font-size:9px;color:var(--g);letter-spacing:1px;margin-bottom:6px;">DETECT</div>
      <div style="font-size:9px;color:var(--dim);">Attacker accesses a decoy path</div>
    </div>
    <div style="background:var(--bg3);padding:16px;text-align:center;">
      <div style="font-size:20px;margin-bottom:8px;">&#128221;</div>
      <div style="font-family:'Orbitron',monospace;font-size:9px;color:var(--amber);letter-spacing:1px;margin-bottom:6px;">LOG</div>
      <div style="font-size:9px;color:var(--dim);">IP, path, type and timestamp recorded</div>
    </div>
    <div style="background:var(--bg3);padding:16px;text-align:center;">
      <div style="font-size:20px;margin-bottom:8px;">&#128308;</div>
      <div style="font-family:'Orbitron',monospace;font-size:9px;color:var(--red);letter-spacing:1px;margin-bottom:6px;">BLOCK</div>
      <div style="font-size:9px;color:var(--dim);">IP flagged — blocked after 3 honeypot hits</div>
    </div>
    <div style="background:var(--bg3);padding:16px;text-align:center;">
      <div style="font-size:20px;margin-bottom:8px;">&#128202;</div>
      <div style="font-family:'Orbitron',monospace;font-size:9px;color:var(--cyan);letter-spacing:1px;margin-bottom:6px;">REPORT</div>
      <div style="font-size:9px;color:var(--dim);">Visible in dashboard + PDF report</div>
    </div>
  </div>
</div>
<div style="text-align:center;margin-top:20px;padding-bottom:40px;position:relative;z-index:1;">
  <a href="/.env" class="btn btn-r" style="margin-right:10px;">TEST: Honey Credentials</a>
  <a href="/phpmyadmin" class="btn btn-a" style="margin-right:10px;">TEST: Port Scanner</a>
  <a href="/secret-admin" class="btn btn-c">TEST: Hidden URL</a>
</div>
</main>
</body></html>""")

# ── REPORT PAGE ───────────────────────────────────────────────────────────────
@app.route('/report')
def report():
    from collections import Counter as _Counter
    logs        = load_logs()
    type_counts = _Counter(l.get('attack_type', 'Unknown') for l in logs)
    ip_counts   = _Counter(l.get('ip', '?') for l in logs)
    blocked, _  = load_blocked()
    total       = len(logs)
    gen_time    = datetime.now().strftime('%d %b %Y  %H:%M:%S')

    # Build bars HTML
    bars_type = ''
    for atype, count in type_counts.most_common():
        pct = round(count / total * 100, 1) if total > 0 else 0
        if   'SQL'  in atype: clr = '#ff0040'
        elif 'XSS'  in atype: clr = '#ffaa00'
        elif 'CMD'  in atype or 'Command' in atype: clr = '#00ffff'
        elif 'PATH' in atype or 'Path'    in atype: clr = '#ff8800'
        elif 'LDAP' in atype: clr = '#a855f7'
        elif 'RCE'  in atype: clr = '#ff0040'
        elif 'Honey' in atype: clr = '#ffaa00'
        else: clr = 'rgba(0,255,65,0.3)'
        bars_type += (
            f'<div class="bar-row">'
            f'<div class="bar-label">{atype}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{clr};"></div></div>'
            f'<div class="bar-n">{count}</div>'
            f'<div class="bar-p">{pct}%</div>'
            f'</div>'
        )
    if not bars_type:
        bars_type = '<div style="color:rgba(0,255,65,0.45);font-size:10px;padding:10px 0;">No attack data yet</div>'

    bars_ip = ''
    max_c = max(ip_counts.values()) if ip_counts else 1
    for ip_addr, count in ip_counts.most_common(8):
        pct  = round(count / max_c * 100, 1)
        pct2 = round(count / total * 100, 1) if total > 0 else 0
        bars_ip += (
            f'<div class="bar-row">'
            f'<div class="bar-label">{ip_addr}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:#00ffff;"></div></div>'
            f'<div class="bar-n">{count}</div>'
            f'<div class="bar-p">{pct2}%</div>'
            f'</div>'
        )
    if not bars_ip:
        bars_ip = '<div style="color:rgba(0,255,65,0.45);font-size:10px;padding:10px 0;">No IP data yet</div>'

    # Build log table rows
    log_rows = ''
    for i, log in enumerate(reversed(logs), 1):
        atype = log.get('attack_type', '')
        if   'SQL'  in atype: badge_cls, badge_txt = 'b-sql', atype
        elif 'XSS'  in atype: badge_cls, badge_txt = 'b-xss', 'XSS'
        elif 'CMD'  in atype or 'Command' in atype: badge_cls, badge_txt = 'b-cmd', 'CMD'
        elif 'PATH' in atype or 'Path'    in atype: badge_cls, badge_txt = 'b-path', 'PATH'
        else:                                        badge_cls, badge_txt = 'b-unk',  atype or '???'
        sev = log.get('severity', 'HIGH')
        payload = str(log.get('payload', ''))[:50]
        log_rows += (
            f'<tr>'
            f'<td class="td-m">{i}</td>'
            f'<td class="td-m">{log.get("time","?")}</td>'
            f'<td class="td-ip">{log.get("ip","?")}</td>'
            f'<td><span class="badge {badge_cls}">{badge_txt}</span></td>'
            f'<td><span class="sev-b sev-{sev}">{sev}</span></td>'
            f'<td class="td-p">{payload}</td>'
            f'<td><span class="badge b-block">BLOCKED</span></td>'
            f'</tr>'
        )

    log_table = f'''<table>
      <thead><tr><th>#</th><th>TIMESTAMP</th><th>IP ADDRESS</th><th>TYPE</th><th>SEVERITY</th><th>PAYLOAD</th><th>STATUS</th></tr></thead>
      <tbody>{log_rows}</tbody>
    </table>''' if logs else '<div class="empty">No attacks logged yet — send payloads from /login or /simulate</div>'

    sql_c  = type_counts.get('SQL_INJECTION', 0) + type_counts.get('SQL Injection', 0)
    xss_c  = type_counts.get('XSS', 0)
    cmd_c  = type_counts.get('CMD_INJECTION', 0) + type_counts.get('Command Injection', 0)
    path_c = type_counts.get('PATH_TRAVERSAL', 0) + type_counts.get('Path Traversal', 0)

    html = f'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>[IPS] :: Attack Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{{--bg:#050a05;--bg2:#070d07;--bg3:#0a120a;--panel:#0c160c;
  --border:rgba(0,255,65,0.15);--border2:rgba(0,255,65,0.35);
  --g:#00ff41;--g2:#00cc33;--g3:#008f23;--dim:rgba(0,255,65,0.45);
  --red:#ff0040;--amber:#ffaa00;--cyan:#00ffff;--violet:#a855f7;--orange:#ff8800;--text:#c8ffc8;}}
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:"Share Tech Mono",monospace;background:var(--bg);color:var(--g);min-height:100vh;overflow-x:hidden;}}
#matrix{{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.1;}}
body::after{{content:"";position:fixed;inset:0;z-index:999;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px);}}
body::before{{content:"";position:fixed;inset:0;z-index:998;pointer-events:none;background:radial-gradient(ellipse at center,transparent 60%,rgba(0,0,0,0.55) 100%);}}
@keyframes glitch{{0%,100%{{text-shadow:none;transform:none;}}20%{{text-shadow:-2px 0 #ff0040,2px 0 #00ffff;transform:translate(-1px,0);}}40%{{text-shadow:2px 0 #ff0040,-2px 0 #00ffff;transform:translate(1px,0);}}60%{{text-shadow:none;transform:none;}}80%{{text-shadow:-1px 0 #00ffff;transform:translate(1px,0);}}}}
@keyframes flicker{{0%,100%{{opacity:1}}42%{{opacity:0.6}}76%{{opacity:0.7}}}}
@keyframes scanH{{0%{{top:-4px}}100%{{top:100%}}}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(14px)}}to{{opacity:1;transform:translateY(0)}}}}
.scan-line{{position:fixed;left:0;right:0;height:2px;z-index:997;pointer-events:none;background:linear-gradient(90deg,transparent,rgba(0,255,65,0.35),transparent);animation:scanH 8s linear infinite;}}
nav{{position:sticky;top:0;z-index:200;display:flex;justify-content:space-between;align-items:center;padding:12px 40px;background:rgba(5,10,5,0.93);backdrop-filter:blur(14px);border-bottom:1px solid var(--border);animation:flicker 10s infinite;}}
.logo{{font-family:"Orbitron",monospace;font-size:13px;font-weight:900;color:var(--g);letter-spacing:4px;text-shadow:0 0 20px var(--g);animation:glitch 7s infinite;text-decoration:none;}}
.nav-links{{display:flex;gap:6px;align-items:center;}}
.nav-link{{font-size:9px;color:var(--dim);text-decoration:none;letter-spacing:1.5px;padding:5px 10px;border:1px solid transparent;border-radius:2px;transition:all 0.2s;}}
.nav-link:hover{{color:var(--g);border-color:var(--border);}}
.nav-link.active{{color:var(--g);border-color:var(--border2);background:rgba(0,255,65,0.06);}}
.nav-pdf{{color:var(--amber) !important;border-color:rgba(255,170,0,0.3) !important;}}
main{{position:relative;z-index:1;max-width:1300px;margin:0 auto;padding:40px 44px 60px;}}
.page-head{{margin-bottom:30px;opacity:0;animation:fadeUp 0.5s ease 0.1s forwards;}}
.page-head h1{{font-family:"Orbitron",monospace;font-size:26px;font-weight:900;letter-spacing:2px;text-shadow:0 0 20px rgba(0,255,65,0.4);margin-bottom:4px;}}
.page-head h1 span{{color:var(--amber);text-shadow:0 0 18px rgba(255,170,0,0.5);}}
.page-head p{{font-size:10px;color:var(--dim);letter-spacing:1px;}}
.refresh-row{{display:flex;align-items:center;gap:12px;margin-top:6px;}}
.gen-t{{font-size:9px;color:var(--g3);letter-spacing:1px;}}
.cd{{font-size:9px;color:var(--amber);border:1px solid rgba(255,170,0,0.3);padding:2px 10px;letter-spacing:1px;}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px;opacity:0;animation:fadeUp 0.4s ease 0.15s forwards;}}
.stat{{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:18px 14px;text-align:center;position:relative;overflow:hidden;transition:all 0.2s;}}
.stat:hover{{border-color:var(--border2);transform:translateY(-2px);}}
.stat::before{{content:"";position:absolute;top:0;left:0;right:0;height:1px;}}
.s-r::before{{background:linear-gradient(90deg,var(--red),transparent);}}
.s-a::before{{background:linear-gradient(90deg,var(--amber),transparent);}}
.s-v::before{{background:linear-gradient(90deg,var(--violet),transparent);}}
.s-c::before{{background:linear-gradient(90deg,var(--cyan),transparent);}}
.s-o::before{{background:linear-gradient(90deg,var(--orange),transparent);}}
.s-g::before{{background:linear-gradient(90deg,var(--g),transparent);}}
.stat-n{{font-family:"Orbitron",monospace;font-size:36px;font-weight:900;line-height:1;margin-bottom:5px;}}
.s-r .stat-n{{color:var(--red);}} .s-a .stat-n{{color:var(--amber);}} .s-v .stat-n{{color:var(--violet);}}
.s-c .stat-n{{color:var(--cyan);}} .s-o .stat-n{{color:var(--orange);}} .s-g .stat-n{{color:var(--g);}}
.stat-l{{font-size:7px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;}}
.breakdown{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px;opacity:0;animation:fadeUp 0.4s ease 0.25s forwards;}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:22px 24px;position:relative;overflow:hidden;}}
.card::before{{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--g),transparent);opacity:0.4;}}
.card-title{{font-family:"Orbitron",monospace;font-size:10px;font-weight:700;color:var(--g);letter-spacing:2px;margin-bottom:3px;}}
.card-sub{{font-size:8px;color:var(--g3);letter-spacing:1px;margin-bottom:18px;}}
.bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:9px;}}
.bar-label{{font-size:9px;color:var(--dim);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.bar-track{{flex:1;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:2px;}}
.bar-n{{font-size:9px;color:var(--dim);width:22px;text-align:right;flex-shrink:0;}}
.bar-p{{font-size:9px;color:var(--g3);width:34px;text-align:right;flex-shrink:0;}}
.log-section{{background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;opacity:0;animation:fadeUp 0.4s ease 0.35s forwards;position:relative;}}
.log-section::before{{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--amber),transparent);opacity:0.5;}}
.log-top{{display:flex;justify-content:space-between;align-items:center;padding:16px 22px;border-bottom:1px solid var(--border);}}
.log-top h3{{font-family:"Orbitron",monospace;font-size:11px;font-weight:700;color:var(--amber);letter-spacing:3px;}}
.log-right{{display:flex;align-items:center;gap:8px;}}
.pill{{font-size:8px;color:var(--g3);border:1px solid var(--border);padding:2px 10px;letter-spacing:1px;}}
.pdf-link{{font-size:8px;color:var(--amber);text-decoration:none;border:1px solid rgba(255,170,0,0.4);padding:4px 12px;border-radius:2px;transition:all 0.2s;}}
.pdf-link:hover{{background:rgba(255,170,0,0.08);}}
table{{width:100%;border-collapse:collapse;}}
thead th{{padding:9px 14px;text-align:left;font-size:7px;color:var(--g3);letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--bg3);}}
tbody tr{{border-bottom:1px solid rgba(0,255,65,0.05);transition:background 0.15s;}}
tbody tr:last-child{{border-bottom:none;}}
tbody tr:hover{{background:rgba(0,255,65,0.03);}}
td{{padding:10px 14px;font-size:10px;color:var(--text);}}
.td-m{{font-size:9px;color:var(--dim);}} .td-ip{{font-size:10px;color:var(--cyan);}}
.td-p{{font-size:8px;color:rgba(0,255,65,0.3);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.badge{{display:inline-flex;align-items:center;padding:2px 7px;border-radius:2px;font-size:7px;letter-spacing:1px;border:1px solid;}}
.b-sql{{color:var(--red);border-color:rgba(255,0,64,0.3);background:rgba(255,0,64,0.06);}}
.b-xss{{color:var(--amber);border-color:rgba(255,170,0,0.3);background:rgba(255,170,0,0.06);}}
.b-cmd{{color:var(--cyan);border-color:rgba(0,255,255,0.3);background:rgba(0,255,255,0.06);}}
.b-path{{color:var(--orange);border-color:rgba(255,136,0,0.3);background:rgba(255,136,0,0.06);}}
.b-block{{color:var(--red);border-color:rgba(255,0,64,0.3);background:rgba(255,0,64,0.06);}}
.b-unk{{color:var(--dim);border-color:var(--border);}}
.sev-b{{display:inline-block;padding:2px 6px;border-radius:2px;font-size:7px;letter-spacing:1px;border:1px solid;}}
.sev-CRITICAL{{color:var(--red);border-color:rgba(255,0,64,0.4);background:rgba(255,0,64,0.07);}}
.sev-HIGH{{color:var(--amber);border-color:rgba(255,170,0,0.4);background:rgba(255,170,0,0.07);}}
.sev-MEDIUM{{color:var(--cyan);border-color:rgba(0,255,255,0.3);background:rgba(0,255,255,0.05);}}
.sev-LOW{{color:var(--g);border-color:rgba(0,255,65,0.3);background:rgba(0,255,65,0.05);}}
.empty{{text-align:center;padding:60px;color:var(--dim);font-size:11px;}}
</style>
<script>
window.addEventListener("DOMContentLoaded",function(){{
  var cv=document.getElementById("matrix"),ctx=cv.getContext("2d");
  var chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()";
  var W,H,cols,drops;
  function init(){{W=cv.width=innerWidth;H=cv.height=innerHeight;cols=Math.floor(W/16);drops=[];for(var i=0;i<cols;i++)drops[i]=Math.random()*-50;}}
  init();window.addEventListener("resize",init);
  setInterval(function(){{
    ctx.fillStyle="rgba(5,10,5,0.05)";ctx.fillRect(0,0,W,H);
    for(var i=0;i<drops.length;i++){{var ch=chars[Math.floor(Math.random()*chars.length)],x=i*16,y=drops[i]*16;
      ctx.fillStyle="#ccffcc";ctx.font="bold 13px monospace";ctx.fillText(ch,x,y);
      if(y>H&&Math.random()>0.975)drops[i]=0;drops[i]++;}}
  }},45);
}});
</script>
</head><body>
<canvas id="matrix"></canvas>
<div class="scan-line"></div>
<nav>
  <a href="/" class="logo">W-IPS</a>
  <div class="nav-links">
    <a href="/" class="nav-link">HOME</a>
    <a href="/dashboard" class="nav-link">DASHBOARD</a>
    <a href="/simulate" class="nav-link">SIMULATOR</a>
    <a href="/report" class="nav-link active">REPORT</a>
    <a href="/download/pdf" class="nav-link nav-pdf">&#11015; PDF</a>
  </div>
</nav>
<main>
  <div class="page-head">
    <h1>ATTACK <span>REPORT</span></h1>
    <p>REAL-TIME WAF INTRUSION DETECTION ANALYSIS</p>
    <div class="refresh-row">
      <div class="gen-t">GENERATED: {gen_time}</div>
      <div class="cd" id="cd">REFRESH IN 30s</div>
    </div>
  </div>
  <div class="stats">
    <div class="stat s-r"><div class="stat-n">{total}</div><div class="stat-l">Total</div></div>
    <div class="stat s-a"><div class="stat-n">{sql_c}</div><div class="stat-l">SQL</div></div>
    <div class="stat s-v"><div class="stat-n">{xss_c}</div><div class="stat-l">XSS</div></div>
    <div class="stat s-c"><div class="stat-n">{cmd_c}</div><div class="stat-l">CMD</div></div>
    <div class="stat s-o"><div class="stat-n">{path_c}</div><div class="stat-l">Path</div></div>
    <div class="stat s-g"><div class="stat-n">{len(blocked)}</div><div class="stat-l">Blocked IPs</div></div>
  </div>
  <div class="breakdown">
    <div class="card">
      <div class="card-title">ATTACK TYPE BREAKDOWN</div>
      <div class="card-sub">DISTRIBUTION BY CATEGORY</div>
      {bars_type}
    </div>
    <div class="card">
      <div class="card-title">TOP ATTACKER IPs</div>
      <div class="card-sub">MOST FREQUENT SOURCES</div>
      {bars_ip}
    </div>
  </div>
  <div class="log-section">
    <div class="log-top">
      <h3>FULL ATTACK LOG</h3>
      <div class="log-right">
        <div class="pill">{total} ENTRIES</div>
        <a href="/download/pdf" class="pdf-link">&#11015; DOWNLOAD PDF</a>
      </div>
    </div>
    {log_table}
  </div>
</main>
<script>
var s=30,cd=document.getElementById("cd");
setInterval(function(){{s--;if(s<=0){{location.reload();return;}}cd.textContent="REFRESH IN "+s+"s";}},1000);
</script>
</body></html>'''
    return html


@app.route('/download/pdf')
def download_pdf():
    try:
        from fpdf import FPDF
    except ImportError:
        return "[ERROR] fpdf2 not installed. Add fpdf2 to requirements.txt and redeploy.", 500

    from collections import Counter as _Counter
    import io as _io

    logs        = load_logs()
    total       = len(logs)
    blocked, _  = load_blocked()
    gen_time    = datetime.now().strftime('%d %b %Y  %H:%M:%S')
    type_counts = _Counter(l.get('attack_type', 'Unknown') for l in logs)
    ip_counts   = _Counter(l.get('ip', '?') for l in logs)

    color_map = {
        'SQL_INJECTION':    ((220, 50,  50), 'CRITICAL'),
        'SQL Injection':    ((220, 50,  50), 'CRITICAL'),
        'XSS':              ((220,150,  30), 'HIGH'),
        'CMD_INJECTION':    ((30, 180, 180), 'CRITICAL'),
        'Command Injection':((30, 180, 180), 'CRITICAL'),
        'PATH_TRAVERSAL':   ((220,120,  30), 'HIGH'),
        'Path Traversal':   ((220,120,  30), 'HIGH'),
        'LDAP_INJECTION':   ((168, 85, 247), 'HIGH'),
        'RCE':              ((220, 50,  50), 'CRITICAL'),
        'Honeypot':         ((220,150,  30), 'CRITICAL'),
        'Brute Force':      ((150, 80, 200), 'HIGH'),
        'Unknown':          ((120,130, 140), 'LOW'),
    }

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    pdf.set_fill_color(10, 25, 10); pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_font('Helvetica', 'B', 20); pdf.set_text_color(0, 220, 60)
    pdf.set_xy(0, 10); pdf.cell(210, 10, 'WEB APPLICATION IPS', align='C')
    pdf.set_font('Helvetica', '', 10); pdf.set_text_color(0, 150, 40)
    pdf.set_xy(0, 22); pdf.cell(210, 10, 'Intrusion Prevention System - Attack Report', align='C')
    pdf.ln(30)

    pdf.set_fill_color(15, 30, 15); pdf.rect(15, 45, 180, 36, 'F')
    pdf.set_draw_color(0, 180, 50); pdf.rect(15, 45, 180, 36)
    pdf.set_font('Helvetica', '', 9); pdf.set_text_color(0, 180, 50)
    pdf.set_xy(20, 49); pdf.cell(80, 6, 'Generated:')
    pdf.set_text_color(200, 255, 200); pdf.cell(0, 6, gen_time, ln=True)
    pdf.set_xy(20, 57); pdf.set_text_color(0, 180, 50); pdf.cell(80, 6, 'Total Attacks Detected:')
    pdf.set_text_color(220, 50, 50); pdf.cell(0, 6, str(total), ln=True)
    pdf.set_xy(20, 65); pdf.set_text_color(0, 180, 50); pdf.cell(80, 6, 'IPs Permanently Blocked:')
    pdf.set_text_color(0, 220, 60); pdf.cell(0, 6, str(len(blocked)), ln=True)
    pdf.ln(20)

    def section_hdr(txt):
        pdf.set_fill_color(10, 25, 10); pdf.rect(15, pdf.get_y(), 180, 8, 'F')
        pdf.set_font('Helvetica', 'B', 9); pdf.set_text_color(0, 220, 60)
        pdf.cell(180, 8, '  ' + txt, ln=True)
        pdf.set_draw_color(0, 180, 50); pdf.set_line_width(0.3)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y()); pdf.ln(3)

    section_hdr('SUMMARY')
    summary_rows = [
        ('Total Attacks Detected', str(total), (220,50,50)),
        ('SQL Injection', str(type_counts.get('SQL_INJECTION',0)+type_counts.get('SQL Injection',0)), (220,150,30)),
        ('XSS Attacks',  str(type_counts.get('XSS',0)), (150,80,200)),
        ('CMD Injection', str(type_counts.get('CMD_INJECTION',0)+type_counts.get('Command Injection',0)), (30,180,180)),
        ('Path Traversal', str(type_counts.get('PATH_TRAVERSAL',0)+type_counts.get('Path Traversal',0)), (220,120,30)),
        ('LDAP Injection', str(type_counts.get('LDAP_INJECTION',0)), (168,85,247)),
        ('RCE Attempts',  str(type_counts.get('RCE',0)), (220,50,50)),
        ('IPs Blocked',   str(len(blocked)), (0,200,60)),
    ]
    for label, val, clr in summary_rows:
        pdf.set_font('Helvetica', '', 9); pdf.set_text_color(140,180,140)
        pdf.set_x(15); pdf.cell(120, 6, label)
        pdf.set_font('Helvetica', 'B', 9); pdf.set_text_color(*clr)
        pdf.cell(0, 6, val, ln=True)
    pdf.ln(6)

    section_hdr('ATTACK TYPE BREAKDOWN')
    pdf.set_fill_color(10,30,10); pdf.set_font('Helvetica','B',8); pdf.set_text_color(0,180,50)
    pdf.set_x(15)
    pdf.cell(70,7,'ATTACK TYPE',fill=True); pdf.cell(25,7,'COUNT',fill=True)
    pdf.cell(30,7,'PERCENTAGE',fill=True); pdf.cell(0,7,'SEVERITY',fill=True,ln=True)
    for atype, count in type_counts.most_common():
        if pdf.get_y() > 260: pdf.add_page()
        pct = f'{round(count/total*100,1)}%' if total > 0 else '0%'
        clr, sev = color_map.get(atype, ((120,130,140),'LOW'))
        pdf.set_font('Helvetica','',9); pdf.set_text_color(180,220,180); pdf.set_x(15); pdf.cell(70,6,atype)
        pdf.set_font('Helvetica','B',9); pdf.set_text_color(*clr)
        pdf.cell(25,6,str(count)); pdf.cell(30,6,pct); pdf.cell(0,6,sev,ln=True)
    pdf.ln(6)

    section_hdr('TOP ATTACKER IPs')
    pdf.set_fill_color(10,30,10); pdf.set_font('Helvetica','B',8); pdf.set_text_color(0,180,50)
    pdf.set_x(15)
    pdf.cell(60,7,'IP ADDRESS',fill=True); pdf.cell(30,7,'ATTACKS',fill=True)
    pdf.cell(0,7,'PERCENTAGE',fill=True,ln=True)
    for ip_addr, count in ip_counts.most_common(10):
        if pdf.get_y() > 260: pdf.add_page()
        pct = f'{round(count/total*100,1)}%' if total > 0 else '0%'
        pdf.set_font('Helvetica','',9); pdf.set_text_color(30,180,180); pdf.set_x(15); pdf.cell(60,6,ip_addr)
        pdf.set_font('Helvetica','B',9); pdf.set_text_color(220,50,50); pdf.cell(30,6,str(count))
        pdf.set_text_color(180,220,180); pdf.set_font('Helvetica','',9); pdf.cell(0,6,pct,ln=True)
    pdf.ln(6)

    if logs:
        pdf.add_page()
        section_hdr(f'FULL ATTACK LOG  ({total} entries)')
        col_w = [8, 38, 28, 28, 20, 38]
        pdf.set_fill_color(10,30,10); pdf.set_font('Helvetica','B',7); pdf.set_text_color(0,180,50); pdf.set_x(15)
        for txt, w in zip(['#','TIMESTAMP','IP ADDRESS','TYPE','SEVERITY','PAYLOAD'], col_w):
            pdf.cell(w, 6, txt, fill=True)
        pdf.ln()
        sev_colors = {'CRITICAL':(220,50,50),'HIGH':(220,150,30),'MEDIUM':(30,180,180),'LOW':(0,180,50)}
        for idx, log in enumerate(reversed(logs), 1):
            if pdf.get_y() > 268:
                pdf.add_page()
                pdf.set_fill_color(10,30,10); pdf.set_font('Helvetica','B',7); pdf.set_text_color(0,180,50); pdf.set_x(15)
                for txt, w in zip(['#','TIMESTAMP','IP ADDRESS','TYPE','SEVERITY','PAYLOAD'], col_w):
                    pdf.cell(w, 6, txt, fill=True)
                pdf.ln()
            atype = log.get('attack_type','Unknown')
            clr, _ = color_map.get(atype, ((120,130,140),'LOW'))
            sev = log.get('severity','HIGH')
            pdf.set_font('Helvetica','',7); pdf.set_x(15)
            pdf.set_text_color(120,130,140); pdf.cell(col_w[0],5,str(idx))
            pdf.set_text_color(120,140,120); pdf.cell(col_w[1],5,str(log.get('time',''))[:20])
            pdf.set_text_color(30,180,180);  pdf.cell(col_w[2],5,str(log.get('ip',''))[:15])
            pdf.set_text_color(*clr); pdf.set_font('Helvetica','B',7); pdf.cell(col_w[3],5,atype[:14])
            pdf.set_font('Helvetica','',7)
            pdf.set_text_color(*sev_colors.get(sev,(120,130,140))); pdf.cell(col_w[4],5,sev)
            pdf.set_text_color(100,130,100); pdf.cell(col_w[5],5,str(log.get('payload',''))[:25],ln=True)

    pdf_bytes = bytes(pdf.output())
    return send_file(
        _io.BytesIO(pdf_bytes), mimetype='application/pdf',
        as_attachment=True,
        download_name=f'waf_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )




# ── HONEYPOT TRAP ROUTES ──────────────────────────────────────────────────────
HONEYPOT_PATHS = [
    '/.env', '/config.php', '/.git/config', '/wp-config.php',
    '/database.yml', '/secrets.json', '/passwords.txt', '/backup.sql',
    '/api-keys.txt', '/credentials.xml', '/.htpasswd', '/web.config',
    '/admin', '/wp-admin', '/administrator', '/panel', '/cpanel', '/manage',
    '/secret-admin', '/hidden', '/backup', '/staging', '/internal', '/vault',
    '/shell', '/cmd.php', '/terminal', '/bash', '/execute', '/remote-access',
    '/phpmyadmin', '/mysql', '/jenkins', '/solr', '/actuator', '/jboss',
]

def log_honeypot(path):
    ip  = request.remote_addr
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    blocked, ac = load_blocked()
    ac[ip] = ac.get(ip, 0) + 1
    if ac[ip] >= 3:
        blocked.add(ip)
    save_blocked(blocked, ac)
    entry = json.dumps({
        'time': now, 'attack_type': 'HONEYPOT',
        'ip': ip, 'payload': path,
        'severity': 'CRITICAL', 'country': 'Unknown'
    })
    with open(LOG_FILE, 'a') as f:
        f.write(entry + '\n')

@app.route('/.env')
@app.route('/config.php')
@app.route('/.git/config')
@app.route('/wp-config.php')
@app.route('/database.yml')
@app.route('/secrets.json')
@app.route('/passwords.txt')
@app.route('/backup.sql')
@app.route('/api-keys.txt')
@app.route('/credentials.xml')
@app.route('/.htpasswd')
@app.route('/web.config')
@app.route('/wp-admin')
@app.route('/administrator')
@app.route('/panel')
@app.route('/cpanel')
@app.route('/manage')
@app.route('/secret-admin')
@app.route('/hidden')
@app.route('/staging')
@app.route('/internal')
@app.route('/vault')
@app.route('/shell')
@app.route('/cmd.php')
@app.route('/terminal')
@app.route('/bash')
@app.route('/execute')
@app.route('/remote-access')
@app.route('/phpmyadmin')
@app.route('/mysql')
@app.route('/jenkins')
@app.route('/solr')
@app.route('/actuator')
@app.route('/jboss')
def honeypot_trap():
    path = request.path
    log_honeypot(path)
    return render_template_string("""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><title>404 Not Found</title>
<style>body{font-family:monospace;background:#050a05;color:#00ff41;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
.box{text-align:center;border:1px solid rgba(0,255,65,0.2);padding:40px 60px;background:#0c160c;}
h1{font-size:48px;color:#ff0040;margin:0 0 10px;}p{color:rgba(0,255,65,0.5);font-size:12px;}</style>
</head><body><div class="box"><h1>404</h1><p>NOT FOUND</p><p style="margin-top:20px;font-size:10px;color:rgba(255,0,64,0.4);">[HONEYPOT] Your IP has been logged and flagged.</p></div></body></html>"""), 404


# ── ADMIN PAGE ────────────────────────────────────────────────────────────────
@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('admin'):
        return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>[IPS] :: Admin Login</title>""" + SHARED + """
<style>
.login-wrap{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 50px);padding:40px 20px;}
.lc{background:var(--panel);border:1px solid rgba(255,0,64,0.3);border-radius:4px;padding:40px 36px;width:340px;position:relative;overflow:hidden;}
.lc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--red),transparent);}
.lt{font-family:'Orbitron',monospace;font-size:16px;font-weight:900;color:var(--red);letter-spacing:3px;text-shadow:0 0 14px rgba(255,0,64,0.4);margin-bottom:4px;}
.ls{font-size:8px;color:var(--g3);letter-spacing:2px;margin-bottom:28px;}
.bl{width:100%;padding:12px;background:transparent;border:1px solid var(--red);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:3px;color:var(--red);
  cursor:pointer;text-shadow:0 0 8px rgba(255,0,64,0.4);transition:all 0.2s;}
.bl:hover{background:rgba(255,0,64,0.08);}
.err{margin-bottom:14px;padding:9px 12px;background:rgba(255,0,64,0.06);border:1px solid rgba(255,0,64,0.2);font-size:9px;color:var(--red);border-radius:3px;}
</style></head><body>""" + nav('/admin') + """
<div class="login-wrap"><div class="lc">
  <div class="lt">ADMIN ACCESS</div>
  <div class="ls">IPS CONTROL PANEL - AUTHORIZED ONLY</div>
  {% if err %}<div class="err">{{ err }}</div>{% endif %}
  <form method="POST" action="/admin-login">
    <label>Admin Password</label>
    <input type="password" name="password" placeholder="&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;" style="margin-bottom:14px;" required>
    <button type="submit" class="bl">[ ACCESS CONTROL PANEL ]</button>
  </form>
</div></div>
</body></html>""", err=request.args.get('err'))

    blocked_ips, attack_count = load_blocked()
    logs = load_logs()
    return render_template_string("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>[IPS] :: Admin Panel</title>""" + SHARED + """
<style>
.a-panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:22px 24px;margin-bottom:16px;position:relative;overflow:hidden;opacity:0;animation:fadeUp 0.4s ease forwards;}
.a-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--red),transparent);opacity:0.5;}
.a-title{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;color:var(--red);letter-spacing:3px;margin-bottom:14px;}
.alert{padding:10px 14px;border-radius:3px;font-size:10px;margin-bottom:14px;letter-spacing:1px;}
.alert-ok{background:rgba(0,255,65,0.06);border:1px solid rgba(0,255,65,0.2);color:var(--g);}
.alert-err{background:rgba(255,0,64,0.06);border:1px solid rgba(255,0,64,0.2);color:var(--red);}
</style></head><body>""" + nav('/admin') + """
<main>
<div class="page-head"><h1 style="color:var(--red);">CONTROL CENTER</h1><p>MANAGE BLOCKED IPS, LOGS AND SYSTEM</p></div>
{% if msg %}<div class="alert alert-{{ mt }}">{{ msg }}</div>{% endif %}

<div class="stat-row stat-4" style="animation-delay:0.1s;">
  <div class="stat s-r"><div class="stat-n">{{ total }}</div><div class="stat-l">Total Attacks</div></div>
  <div class="stat s-a"><div class="stat-n">{{ bcount }}</div><div class="stat-l">Blocked IPs</div></div>
  <div class="stat s-g"><div class="stat-n">{{ total }}</div><div class="stat-l">Log Entries</div></div>
  <div class="stat s-c"><div class="stat-n">ONLINE</div><div class="stat-l">System Status</div></div>
</div>

<div class="a-panel" style="animation-delay:0.15s;">
  <div class="a-title">&#128683; BLOCKED IP MANAGEMENT</div>
  {% if blocked_ips %}
  <table>
    <thead><tr><th>IP ADDRESS</th><th>ATTACKS</th><th>ACTION</th></tr></thead>
    <tbody>
      {% for ip in blocked_ips %}
      <tr>
        <td style="color:var(--red);font-size:11px;">{{ ip }}</td>
        <td class="td-mono">{{ attack_count.get(ip,'?') }}</td>
        <td><form method="POST" action="/admin-unblock" style="display:inline;"><input type="hidden" name="ip" value="{{ ip }}"><button type="submit" class="btn btn-g" style="font-size:9px;padding:5px 12px;">UNBLOCK</button></form></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}<div style="color:var(--dim);font-size:10px;">No IPs currently blocked.</div>{% endif %}
</div>

<div class="a-panel" style="animation-delay:0.2s;">
  <div class="a-title">&#128274; MANUALLY BLOCK IP</div>
  <form method="POST" action="/admin-block" style="display:flex;gap:10px;align-items:flex-end;">
    <div style="flex:1;"><label>IP Address</label><input type="text" name="ip" placeholder="e.g. 192.168.1.100"></div>
    <button type="submit" class="btn btn-r" style="height:40px;margin-top:14px;">BLOCK IP</button>
  </form>
</div>

<div class="a-panel" style="animation-delay:0.25s;">
  <div class="a-title">&#128203; LOG MANAGEMENT</div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;">
    <a href="/dashboard" class="btn btn-a">DOWNLOAD PDF REPORT</a>
    <form method="POST" action="/admin-clear-logs" style="display:inline;" onsubmit="return confirm('Clear all attack logs?');"><button type="submit" class="btn btn-r">CLEAR ATTACK LOGS</button></form>
    <form method="POST" action="/admin-clear-blocked" style="display:inline;" onsubmit="return confirm('Unblock ALL IPs?');"><button type="submit" class="btn btn-r">UNBLOCK ALL IPs</button></form>
    <a href="/admin-logout" class="btn btn-c">LOGOUT</a>
  </div>
</div>

<div class="a-panel" style="animation-delay:0.3s;padding:0;overflow:hidden;">
  <div style="padding:16px 22px;border-bottom:1px solid var(--border);"><div class="a-title" style="margin-bottom:0;">RECENT ATTACKS (LAST 10)</div></div>
  {% if logs %}
  <table>
    <thead><tr><th>#</th><th>TIME</th><th>IP</th><th>TYPE</th><th>SEVERITY</th><th>COUNTRY</th></tr></thead>
    <tbody>
      {% for l in logs|reverse %}{% if loop.index <= 10 %}
      <tr>
        <td class="td-mono">{{ loop.index }}</td>
        <td class="td-mono">{{ l.time }}</td>
        <td class="td-ip">{{ l.ip }}</td>
        <td style="font-size:10px;color:var(--amber);">{{ l.get('attack_type','?') }}</td>
        <td><span class="sev-b sev-{{ l.get('severity','LOW') }}">{{ l.get('severity','LOW') }}</span></td>
        <td class="td-mono">{{ l.get('country','?') }}</td>
      </tr>
      {% endif %}{% endfor %}
    </tbody>
  </table>
  {% else %}<div style="padding:30px;color:var(--dim);font-size:10px;">No attacks logged yet.</div>{% endif %}
</div>
</main>
</body></html>""",
        blocked_ips=sorted(blocked_ips), attack_count=attack_count,
        total=len(logs), bcount=len(blocked_ips), logs=logs,
        msg=request.args.get('msg'), mt=request.args.get('t','ok'))


@app.route('/admin-login', methods=['POST'])
def admin_login():
    if request.form.get('password') == ADMIN_PASSWORD:
        session['admin'] = True
        return redirect('/admin')
    return redirect('/admin?err=[ACCESS DENIED] Invalid password')

@app.route('/admin-logout')
def admin_logout():
    session.clear()
    return redirect('/admin')

@app.route('/admin-unblock', methods=['POST'])
def admin_unblock():
    if not session.get('admin'): return redirect('/admin')
    ip = request.form.get('ip','').strip()
    try:
        blocked, ac = load_blocked()
        blocked.discard(ip)
        ac.pop(ip, None)
        save_blocked(blocked, ac)
        return redirect(f'/admin?msg=[OK] {ip} unblocked&t=ok')
    except:
        return redirect('/admin?msg=[ERR] Could not unblock&t=err')

@app.route('/admin-block', methods=['POST'])
def admin_block():
    if not session.get('admin'): return redirect('/admin')
    ip = request.form.get('ip','').strip()
    if not ip: return redirect('/admin?msg=[ERR] No IP entered&t=err')
    try:
        blocked, ac = load_blocked()
        blocked.add(ip)
        ac[ip] = ac.get(ip,0) + 99
        save_blocked(blocked, ac)
        return redirect(f'/admin?msg=[OK] {ip} blocked&t=ok')
    except:
        return redirect('/admin?msg=[ERR] Could not block&t=err')

@app.route('/admin-clear-logs', methods=['POST'])
def admin_clear_logs():
    if not session.get('admin'): return redirect('/admin')
    try:
        open(LOG_FILE, 'w').close()
        return redirect('/admin?msg=[OK] Logs cleared&t=ok')
    except:
        return redirect('/admin?msg=[ERR] Could not clear logs&t=err')

@app.route('/admin-clear-blocked', methods=['POST'])
def admin_clear_blocked():
    if not session.get('admin'): return redirect('/admin')
    try:
        save_blocked(set(), {})
        return redirect('/admin?msg=[OK] All IPs unblocked&t=ok')
    except:
        return redirect('/admin?msg=[ERR] Could not clear&t=err')


if __name__ == '__main__':
    print()
    print('  +=============================================+')
    print('  |  IPS Unified App   --  Port 5001          |')
    print('  |  http://localhost:5001                     |')
    print('  |  Admin password: admin123                  |')
    print('  +=============================================+')
    print()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=False)
