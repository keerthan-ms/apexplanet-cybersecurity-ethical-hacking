<?php
/**
 * Local file inclusion / path traversal demo.
 *
 * Safety rail: even the vulnerable route resolves every path with realpath()
 * and refuses anything outside task-3/fixtures/. The demonstration escapes the
 * public fixture directory into task-3/fixtures/private/, never into host files
 * such as C:\Windows\win.ini or /etc/passwd.
 */
declare(strict_types=1);

$mode = $MODE;
$isVuln = $mode === 'vuln';
$action = $isVuln ? '/vuln/lfi' : '/secure/lfi';
$requested = trim((string) ($_GET['file'] ?? ''));
$didRead = $requested !== '';
$file = $didRead ? $requested : 'welcome.txt';
$content = null;
$error = null;
$resolvedPath = null;
$blocked = false;
$attemptLogged = false;

if ($didRead) {
    if ($isVuln) {
        if (looks_like_lfi($file)) {
            log_event('lfi_attempt', $file);
            $attemptLogged = true;
        }

        $target = FIXTURE_PUBLIC . '/' . $file;
        $resolved = realpath($target);
        $fixtureRoot = realpath(APP_ROOT . '/fixtures');

        if ($resolved === false) {
            $error = 'Fixture not found: ' . $file;
        } elseif ($fixtureRoot === false || !str_starts_with($resolved, $fixtureRoot . DIRECTORY_SEPARATOR)) {
            // Deliberate safety rail: the vulnerable code is confined to the
            // fixture tree so an accidental request cannot read app source or
            // arbitrary host files.
            http_response_code(403);
            $blocked = true;
            $error = 'Refused by the lab sandbox: the resolved path is outside task-3/fixtures/. '
                   . 'This rail exists so the demo can never read arbitrary host files.';
            if (!$attemptLogged) {
                log_event('lfi_attempt', 'sandbox-refused: ' . $file);
            }
        } else {
            $resolvedPath = $resolved;
            $content = (string) file_get_contents($resolved);
        }
    } else {
        $allowed = ['welcome.txt', 'readme.txt'];
        if (looks_like_lfi($file)) {
            log_event('lfi_attempt', 'blocked=1; input=' . $file);
        }

        if (!in_array($file, $allowed, true)) {
            http_response_code(403);
            $blocked = true;
            $error = 'Rejected: only these fixture files are readable: ' . implode(', ', $allowed) . '.';
            if (!looks_like_lfi($file)) {
                log_event('lfi_attempt', 'blocked=1; input=' . $file);
            }
        } else {
            $resolved = realpath(FIXTURE_PUBLIC . '/' . $file);
            if ($resolved === false || !str_starts_with($resolved, (string) realpath(FIXTURE_PUBLIC) . DIRECTORY_SEPARATOR)) {
                http_response_code(403);
                $blocked = true;
                $error = 'Rejected: resolved path left the public fixture directory.';
            } else {
                $resolvedPath = $resolved;
                $content = (string) file_get_contents($resolved);
            }
        }
    }
}

ob_start();
?>
<div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
  <div class="mode <?= $isVuln ? 'vuln' : 'secure' ?>"><?= $isVuln ? 'Vulnerable' : 'Hardened' ?> · LFI / path traversal</div>
  <h2 style="margin-top:10px"><?= $isVuln ? 'Public path concatenation' : 'Allowlist inside a resolved directory' ?></h2>
  <p>
    <?php if ($isVuln): ?>
      The filename is appended to <code>fixtures/public/</code> without
      normalisation. <code>../private/flag.txt</code> resolves to a sibling
      directory and is read.
    <?php else: ?>
      Only two exact filenames are accepted, and the resolved path must remain
      inside the public fixture directory. Traversal is refused with 403.
    <?php endif; ?>
  </p>
</div>

<div class="grid">
  <div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
    <h3>Read a fixture</h3>
    <form method="get" action="<?= e($action) ?>">
      <label for="file">File name</label>
      <input id="file" name="file" type="text" value="<?= e($file) ?>" autocomplete="off">
      <button type="submit">Open file</button>
    </form>

    <?php if ($error !== null): ?>
      <div class="result note bad"><?= e($error) ?></div>
    <?php endif; ?>
    <?php if ($resolvedPath !== null): ?>
      <div class="result">
        <div class="kv"><span>Resolved path:</span><b><?= e($resolvedPath) ?></b></div>
        <label>File contents</label>
        <pre><?= e($content ?? '') ?></pre>
      </div>
    <?php endif; ?>

    <h3 style="margin-top:20px">Available public fixtures</h3>
    <ul class="hint">
      <li><a href="<?= e($action) ?>?file=welcome.txt">welcome.txt</a></li>
      <li><a href="<?= e($action) ?>?file=readme.txt">readme.txt</a></li>
    </ul>
    <?php if ($isVuln): ?>
      <div class="note bad">
        <strong>Try:</strong> <code>../private/flag.txt</code> or
        <code>../private/internal-memo.txt</code>. The former is the training
        "secret"; the latter shows that sibling directories are reachable.
      </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3>Harmless proof-of-concept input</h3>
    <pre>../private/flag.txt</pre>
    <?php if ($isVuln): ?>
      <div class="note bad">The traversal succeeds because the code trusts the
      concatenated path. It is still sandboxed to
      <code>task-3/fixtures/</code>: attempts such as
      <code>../../../README.md</code>, app source or
      <code>C:\Windows\win.ini</code> are refused by a realpath rail and logged.</div>
    <?php else: ?>
      <div class="note good">The request is rejected before the filesystem is
      read. <code>lfi_attempt</code> with <code>blocked=1</code> is logged for
      the SIEM.</div>
    <?php endif; ?>

    <h3 style="margin-top:18px">The fix in one sentence</h3>
    <p class="hint">Never build a path from user input. Map an identifier to a
    fixed server-side filename, then verify <code>realpath()</code> is inside
    the intended base directory.</p>
  </div>
</div>
<?php
render_page('LFI · ' . ($isVuln ? 'vulnerable' : 'hardened'), (string) ob_get_clean(), $ACTIVE);
