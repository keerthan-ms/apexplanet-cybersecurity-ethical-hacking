<?php /** Training app layout. Included by render_page() in bootstrap.php. */ ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title) ?> · ApexPlanet Web Security Lab</title>
<style>
:root{
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --line:#30363d;
  --text:#e6edf3; --muted:#9da7b3; --red:#f85149; --redbg:#3d1418;
  --green:#3fb950; --greenbg:#12261a; --amber:#d29922; --blue:#58a6ff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--blue);text-decoration:none} a:hover{text-decoration:underline}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 48px}
.warning{background:#4a1d1d;border-bottom:2px solid var(--red);color:#ffdcd9;padding:10px 20px;text-align:center;font-weight:600;letter-spacing:.3px}
.warning span{background:var(--red);color:#0d1117;border-radius:3px;padding:2px 7px;margin-right:8px;font-size:12px;vertical-align:1px}
header{padding:22px 0 8px;border-bottom:1px solid var(--line);margin-bottom:22px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:18px;margin:26px 0 10px} h3{font-size:15px;margin:0 0 8px}
.sub{color:var(--muted);font-size:13px}
nav{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
nav a{padding:6px 11px;border:1px solid var(--line);border-radius:6px;color:var(--muted);font-size:13px}
nav a:hover{border-color:var(--blue);color:var(--text);text-decoration:none}
nav a.active{background:#1f6feb22;border-color:var(--blue);color:var(--text)}
.mode{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.6px;padding:2px 8px;border-radius:20px;text-transform:uppercase}
.mode.vuln{background:var(--redbg);color:#ff9d96;border:1px solid #6e2a2a}
.mode.secure{background:var(--greenbg);color:#7ee787;border:1px solid #2a5c36}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
@media(max-width:820px){.grid,.grid3{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:18px}
.card.vuln{border-top:3px solid var(--red)} .card.secure{border-top:3px solid var(--green)}
.card p{color:var(--muted);font-size:13px;margin:6px 0}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px;text-transform:uppercase;letter-spacing:.5px}
input[type=text],input[type=email],input[type=password],textarea{width:100%;background:#0b0f14;border:1px solid var(--line);border-radius:6px;color:var(--text);padding:9px 11px;font:inherit}
input:focus,textarea:focus{outline:2px solid #1f6feb66;border-color:var(--blue)}
button{margin-top:12px;background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#388bfd}
button.secondary{background:#21262d;border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
code,pre{font-family:Consolas,"SF Mono",monospace}
code{background:#0b0f14;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:12.5px}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:7px;padding:12px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.note{border-left:3px solid var(--amber);background:#2a210d;padding:10px 14px;border-radius:0 6px 6px 0;font-size:13px;margin:14px 0}
.note.good{border-color:var(--green);background:var(--greenbg)}
.note.bad{border-color:var(--red);background:var(--redbg)}
.hint{font-size:13px;color:var(--muted)}
.hint code{display:inline-block;margin:2px 0}
.pill{font-size:11px;padding:2px 7px;border-radius:20px;background:#21262d;border:1px solid var(--line);color:var(--muted)}
.kv{display:flex;gap:8px;font-size:13px;color:var(--muted);margin:4px 0}
.kv b{color:var(--text);font-weight:600}
.result{margin-top:14px}
footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--line);color:#6e7681;font-size:12px}
ul{padding-left:20px} li{margin:4px 0}
.badge-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
</style>
</head>
<body>
<div class="warning"><span>TRAINING ONLY</span>Deliberately vulnerable code. Localhost, fake data, no real credentials. Never deploy this version.</div>
<div class="wrap">
  <header>
    <div class="badge-row">
      <h1 style="margin:0">ApexPlanet · Web Security Lab</h1>
      <span class="pill">127.0.0.1 only</span>
      <span class="pill">Task 3</span>
    </div>
    <div class="sub">Four vulnerabilities, each with a deliberately vulnerable route and a hardened counterpart. Events are written to <code>task-3/vulnerable/data/security.jsonl</code> for Task 5's SIEM.</div>
    <nav>
      <a href="/" class="<?= $active === 'home' ? 'active' : '' ?>">Overview</a>
      <a href="/vuln/sqli" class="<?= $active === 'vuln-sqli' ? 'active' : '' ?>">SQLi · vulnerable</a>
      <a href="/secure/sqli" class="<?= $active === 'secure-sqli' ? 'active' : '' ?>">SQLi · hardened</a>
      <a href="/vuln/xss" class="<?= $active === 'vuln-xss' ? 'active' : '' ?>">XSS · vulnerable</a>
      <a href="/secure/xss" class="<?= $active === 'secure-xss' ? 'active' : '' ?>">XSS · hardened</a>
      <a href="/vuln/csrf" class="<?= $active === 'vuln-csrf' ? 'active' : '' ?>">CSRF · vulnerable</a>
      <a href="/secure/csrf" class="<?= $active === 'secure-csrf' ? 'active' : '' ?>">CSRF · hardened</a>
      <a href="/vuln/lfi" class="<?= $active === 'vuln-lfi' ? 'active' : '' ?>">LFI · vulnerable</a>
      <a href="/secure/lfi" class="<?= $active === 'secure-lfi' ? 'active' : '' ?>">LFI · hardened</a>
    </nav>
  </header>
  <?= $body ?>
  <footer>ApexPlanet Cybersecurity &amp; Ethical Hacking · Task 3 demo · All records are synthetic. Events follow <code>docs/LOG-CONTRACT.md</code>.</footer>
</div>
</body>
</html>
