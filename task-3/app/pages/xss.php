<?php
/**
 * Cross-site scripting demo: one reflected sink, one stored sink.
 * Vulnerable mode echoes raw HTML; hardened mode encodes at the output point.
 */
declare(strict_types=1);

$mode = $MODE;
$isVuln = $mode === 'vuln';
$action = $isVuln ? '/vuln/xss' : '/secure/xss';
$name = trim((string) ($_GET['name'] ?? ''));
$posted = false;
$error = null;

if ($METHOD === 'POST' && (string) ($_POST['action'] ?? '') === 'guestbook') {
    $author = trim((string) ($_POST['author'] ?? 'anon'));
    $message = trim((string) ($_POST['message'] ?? ''));
    if ($author === '') {
        $author = 'anon';
    }
    if ($message !== '') {
        $payload = looks_like_xss($author) || looks_like_xss($message);
        $stmt = db()->prepare(
            'INSERT INTO guestbook (author, message, created_at) VALUES (?, ?, ?)'
        );
        // Both modes store the text as-is. The difference is where and how it
        // is encoded: never at input time, always at the output sink.
        $stmt->execute([$author, $message, date('c')]);

        if ($payload) {
            log_event($isVuln ? 'xss_stored' : 'xss_blocked', $message, $author);
        }
        $posted = true;
    }
}

if ($name !== '') {
    if (looks_like_xss($name)) {
        log_event($isVuln ? 'xss_reflected' : 'xss_blocked', $name);
    }
}

$entries = db()->query(
    'SELECT author, message, created_at FROM guestbook ORDER BY id DESC LIMIT 25'
)->fetchAll();

ob_start();
?>
<div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
  <div class="mode <?= $isVuln ? 'vuln' : 'secure' ?>"><?= $isVuln ? 'Vulnerable' : 'Hardened' ?> · Cross-site scripting</div>
  <h2 style="margin-top:10px"><?= $isVuln ? 'Raw HTML sinks' : 'Output encoding at every sink' ?></h2>
  <p>
    <?php if ($isVuln): ?>
      The greeting and guestbook rows are concatenated into the HTML document.
      The payload below is treated as markup, so a browser would execute it.
    <?php else: ?>
      The same strings are stored unchanged, but every output passes through
      <code>htmlspecialchars()</code> with <code>ENT_QUOTES</code>. The browser
      displays the payload as text.
    <?php endif; ?>
  </p>
</div>

<div class="grid">
  <div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
    <h3>Reflected greeting</h3>
    <form method="get" action="<?= e($action) ?>">
      <label for="name">Your name</label>
      <input id="name" name="name" type="text" value="<?= e($name) ?>" autocomplete="off">
      <button type="submit">Greet me</button>
    </form>

    <?php if ($name !== ''): ?>
      <div class="result">
        <label>Rendered output</label>
        <?php if ($isVuln): ?>
          <div class="note">Hello, <strong><?= $name ?></strong> — welcome to the lab.</div>
          <pre><?= e('Hello, <strong>' . $name . '</strong>') ?></pre>
        <?php else: ?>
          <div class="note good">Hello, <strong><?= e($name) ?></strong> — welcome to the lab.</div>
          <pre><?= e('Hello, <strong>' . e($name) . '</strong>') ?></pre>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <h3 style="margin-top:22px">Guestbook (stored)</h3>
    <form method="post" action="<?= e($action) ?>">
      <input type="hidden" name="action" value="guestbook">
      <label for="author">Name</label>
      <input id="author" name="author" type="text" placeholder="intern" autocomplete="off">
      <label for="message">Message</label>
      <textarea id="message" name="message" rows="3" placeholder="Hello!"></textarea>
      <button type="submit">Post message</button>
    </form>
    <?php if ($posted): ?>
      <div class="note <?= $isVuln ? 'bad' : 'good' ?>">Message stored. It is rendered below.</div>
    <?php endif; ?>

    <h3 style="margin-top:20px">Latest entries</h3>
    <table>
      <tr><th>Author</th><th>Message</th><th>Stored at</th></tr>
      <?php foreach ($entries as $entry): ?>
        <tr>
          <?php if ($isVuln): ?>
            <td><?= $entry['author'] ?></td>
            <td><?= $entry['message'] ?></td>
          <?php else: ?>
            <td><?= e((string) $entry['author']) ?></td>
            <td><?= e((string) $entry['message']) ?></td>
          <?php endif; ?>
          <td><?= e((string) $entry['created_at']) ?></td>
        </tr>
      <?php endforeach; ?>
    </table>
    <?php if ($entries === []): ?>
      <p class="hint">No entries yet.</p>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3>Harmless proof-of-concept payloads</h3>
    <ul class="hint">
      <li>Name: <code>&lt;script&gt;window.__xss=1&lt;/script&gt;</code></li>
      <li>Name: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
      <li>Guestbook message: <code>&lt;svg onload=alert('stored')&gt;</code></li>
    </ul>
    <?php if ($isVuln): ?>
      <div class="note bad">Open the page source: the payload is present as raw
      markup. In a browser it runs in this origin. That is why the vulnerable
      build must never be deployed.</div>
    <?php else: ?>
      <div class="note good">Open the page source: the payload appears as
      <code>&amp;lt;script&amp;gt;</code>. It is inert text, and the SIEM gets an
      <code>xss_blocked</code> event.</div>
    <?php endif; ?>
    <h3 style="margin-top:18px">Why encode on output?</h3>
    <p class="hint">Input filtering is bypassable and breaks legitimate text.
    Context-aware encoding at the sink is the reliable control: HTML body,
    attribute values, URLs and JavaScript each need their own encoding.</p>
  </div>
</div>

<div class="note">
  <strong>Note:</strong> the hardened page renders entries created by the
  vulnerable page as encoded text as well. Storage is shared; safety comes from
  the sink, not from having cleaned the input on the way in.
</div>
<?php
render_page('XSS · ' . ($isVuln ? 'vulnerable' : 'hardened'), (string) ob_get_clean(), $ACTIVE);
