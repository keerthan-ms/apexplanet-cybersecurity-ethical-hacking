<?php
/** Task 3 landing page. */
declare(strict_types=1);

ob_start();
?>
<div class="note bad">
  <strong>This is a training target, not production software.</strong>
  It binds to <code>127.0.0.1</code> only and uses a synthetic SQLite database.
  The vulnerable routes below intentionally contain SQL injection, cross-site
  scripting, CSRF and local file inclusion flaws. Run them locally, on this
  machine, and never expose this server to a network.
</div>

<div class="grid">
  <div class="card vuln">
    <div class="mode vuln">Vulnerable routes</div>
    <h2 style="margin-top:10px">Break it</h2>
    <p>Direct string concatenation, raw HTML output, no CSRF token, and a
       traversal-prone file read. Each action writes a security event.</p>
    <ul>
      <li><a href="/vuln/sqli">SQL injection</a> — auth bypass + UNION extraction</li>
      <li><a href="/vuln/xss">Cross-site scripting</a> — reflected + stored</li>
      <li><a href="/vuln/csrf">CSRF</a> — state change without a token</li>
      <li><a href="/vuln/lfi">LFI / path traversal</a> — read outside the public fixture dir</li>
    </ul>
  </div>
  <div class="card secure">
    <div class="mode secure">Hardened routes</div>
    <h2 style="margin-top:10px">Fix it</h2>
    <p>Prepared statements, context-aware output encoding, a session-bound
       CSRF token, and a realpath allowlist. Same fake data, same UI shape.</p>
    <ul>
      <li><a href="/secure/sqli">SQL injection</a> — parameterised queries</li>
      <li><a href="/secure/xss">Cross-site scripting</a> — HTML encoding on output</li>
      <li><a href="/secure/csrf">CSRF</a> — token validation, 403 on failure</li>
      <li><a href="/secure/lfi">LFI / path traversal</a> — fixture-directory allowlist</li>
    </ul>
  </div>
</div>

<h2>The four weaknesses</h2>
<table>
  <tr><th>Weakness</th><th>Vulnerable behaviour</th><th>Hardened control</th><th>SIEM event</th></tr>
  <tr>
    <td><strong>SQL injection</strong></td>
    <td>Login and search interpolate raw input into SQL.</td>
    <td><code>PDO::prepare()</code> with bound parameters; input never becomes SQL.</td>
    <td><code>sqli_attempt</code> / <code>sqli_blocked</code></td>
  </tr>
  <tr>
    <td><strong>XSS</strong></td>
    <td>Query string and guestbook rows echoed as raw HTML.</td>
    <td><code>htmlspecialchars()</code> at every output point.</td>
    <td><code>xss_reflected</code> / <code>xss_stored</code> / <code>xss_blocked</code></td>
  </tr>
  <tr>
    <td><strong>CSRF</strong></td>
    <td>Email change accepts any cross-origin POST.</td>
    <td>Random token in the session, compared with <code>hash_equals()</code>.</td>
    <td><code>csrf_missing</code> / <code>csrf_blocked</code></td>
  </tr>
  <tr>
    <td><strong>LFI</strong></td>
    <td><code>fixtures/public/</code> plus <code>../private/flag.txt</code> is read.</td>
    <td><code>realpath()</code> must stay inside the public fixture directory.</td>
    <td><code>lfi_attempt</code> (blocked attempts carry <code>blocked=1</code>)</td>
  </tr>
</table>

<h2>Generate events for the SIEM</h2>
<div class="card">
  <p>While this server is running, execute the scripted proof-of-concept requests:</p>
  <pre>python task-3/scripts/demo_attacks.py --base-url http://127.0.0.1:8091</pre>
  <p>It sends the same harmless payloads against both modes, prints the result,
     and appends to:</p>
  <pre>task-3/vulnerable/data/security.jsonl
task-3/vulnerable/data/access.log</pre>
  <p>Then run the Task 5 detector over those real events:</p>
  <pre>python task-5/siem/detect.py --events task-3/vulnerable/data/security.jsonl</pre>
</div>

<div class="note good">
  <strong>What is fake here:</strong> users, password digests, emails, guestbook
  messages, fixture files and every log line. No external system is contacted.
  The only file reads are inside <code>task-3/</code>.
</div>
<?php
render_page('Overview', (string) ob_get_clean(), $ACTIVE);
