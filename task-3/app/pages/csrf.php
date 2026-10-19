<?php
/**
 * CSRF demo: change a fake profile email.
 *
 * Vulnerable mode accepts any POST and never checks a token.
 * Hardened mode requires a random, session-bound token compared with
 * hash_equals(); a missing or forged token is rejected with HTTP 403 and
 * nothing is written.
 */
declare(strict_types=1);

$mode = $MODE;
$isVuln = $mode === 'vuln';
$action = $isVuln ? '/vuln/csrf' : '/secure/csrf';
$user = current_user();
$message = null;
$messageKind = 'good';
$submittedToken = isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null;

if ($METHOD === 'POST' && (string) ($_POST['action'] ?? '') === 'update_email') {
    $email = trim((string) ($_POST['email'] ?? ''));

    if ($isVuln) {
        // Deliberate flaw: the token is neither required nor validated.
        log_event(
            'csrf_missing',
            'form=update_email; token=' . ($submittedToken === null ? 'absent' : 'unchecked'),
            $user['username']
        );
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $stmt = db()->prepare('UPDATE users SET email = ? WHERE username = ?');
            $stmt->execute([$email, $user['username']]);
            log_event('admin_action', 'email changed to ' . $email, $user['username']);
            $message = 'Email changed to ' . $email . ' — no CSRF token was verified.';
            $messageKind = 'bad';
        } else {
            $message = 'Enter a valid email address.';
            $messageKind = 'bad';
        }
    } elseif (!csrf_valid($submittedToken)) {
        // Hardened: reject before any state change.
        http_response_code(403);
        log_event('csrf_blocked', 'form=update_email', $user['username']);
        $message = '403 — CSRF token missing or invalid. The profile was not changed.';
        $messageKind = 'bad';
    } elseif ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Enter a valid email address.';
        $messageKind = 'bad';
    } else {
        $stmt = db()->prepare('UPDATE users SET email = ? WHERE username = ?');
        $stmt->execute([$email, $user['username']]);
        log_event('admin_action', 'email changed to ' . $email, $user['username']);
        $message = 'Email changed to ' . $email . ' — token verified.';
        $messageKind = 'good';
    }

    $user = current_user();
}

ob_start();
?>
<div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
  <div class="mode <?= $isVuln ? 'vuln' : 'secure' ?>"><?= $isVuln ? 'Vulnerable' : 'Hardened' ?> · CSRF</div>
  <h2 style="margin-top:10px"><?= $isVuln ? 'State change without a token' : 'Session-bound token validation' ?></h2>
  <p>
    <?php if ($isVuln): ?>
      The email form accepts any POST. A page on another origin can submit it
      with the victim's cookies, changing the profile without consent.
    <?php else: ?>
      The form carries a 128-bit token generated per session. A request without
      that exact token is refused with 403 before the database is touched.
    <?php endif; ?>
  </p>
</div>

<div class="grid">
  <div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
    <div class="kv"><span>Signed in as</span><b><?= e((string) $user['username']) ?></b><span>(fake account)</span></div>
    <div class="kv"><span>Role</span><b><?= e((string) $user['role']) ?></b></div>
    <div class="kv"><span>Current email</span><b><?= e((string) $user['email']) ?></b></div>

    <h3 style="margin-top:18px">Change email</h3>
    <form method="post" action="<?= e($action) ?>">
      <input type="hidden" name="action" value="update_email">
      <?php if (!$isVuln): ?>
        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
      <?php endif; ?>
      <label for="email">New email</label>
      <input id="email" name="email" type="email" value="<?= e((string) $user['email']) ?>">
      <button type="submit">Update profile</button>
    </form>

    <?php if ($message !== null): ?>
      <div class="result note <?= e($messageKind) ?>"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($isVuln): ?>
      <div class="note bad" style="margin-top:18px">No token input exists in this
      form. Any POST to <code>/vuln/csrf</code> with <code>action=update_email</code>
      changes the profile.</div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3>Forge the request</h3>
    <p class="hint">With the server running, this sends the state-changing POST
    without a token. The vulnerable route applies it; the hardened route returns
    403 and logs <code>csrf_blocked</code>.</p>
    <pre>python task-3/scripts/demo_attacks.py --base-url http://127.0.0.1:8091 --only csrf</pre>

    <h3 style="margin-top:18px">What good validation looks like</h3>
    <ul class="hint">
      <li>Token generated with <code>random_bytes(16)</code> and stored server-side in the session.</li>
      <li>Compared with <code>hash_equals()</code> to avoid timing leaks.</li>
      <li>Rejected with 403 <em>before</em> any write.</li>
      <li>Session cookie is <code>HttpOnly</code> and <code>SameSite=Lax</code>; in production it would also be <code>Secure</code>.</li>
    </ul>
    <div class="note">
      <strong>Why a token if SameSite exists?</strong> SameSite is a useful
      defence-in-depth control but has browser and deployment edge cases. A
      synchroniser token is server-enforced and also covers same-site subdomain
      attacks. Use both.
    </div>
  </div>
</div>
<?php
render_page('CSRF · ' . ($isVuln ? 'vulnerable' : 'hardened'), (string) ob_get_clean(), $ACTIVE);
