<?php
/**
 * SQL injection demo.
 *
 * Vulnerable mode concatenates the submitted values into the SQL string.
 * Hardened mode uses PDO prepared statements with bound parameters. Both modes
 * read the same fake users table and emit events from the shared log contract.
 */
declare(strict_types=1);

$mode = $MODE;
$isVuln = $mode === 'vuln';
$action = $isVuln ? '/vuln/sqli' : '/secure/sqli';
$login = null;
$rows = null;
$sqlShown = null;
$error = null;

$u = trim((string) ($_POST['username'] ?? ''));
$p = (string) ($_POST['password'] ?? '');
$q = trim((string) ($_GET['q'] ?? ''));
$didLogin = $METHOD === 'POST' && (string) ($_POST['action'] ?? '') === 'login';
$didSearch = $METHOD === 'GET' && isset($_GET['q']);

if ($didLogin) {
    $digest = hash('sha256', $p);
    $injected = looks_like_sqli($u) || looks_like_sqli($p);

    if ($isVuln) {
        if ($injected) {
            log_event('sqli_attempt', 'login username=' . $u . ($p !== '' ? ' [password submitted]' : ''), $u);
        }
        $sqlShown = "SELECT id, username, role FROM users WHERE username = '{$u}' AND password_hash = '{$digest}'";
        try {
            $row = db()->query($sqlShown)->fetch();
            if (is_array($row)) {
                $_SESSION['user'] = (string) $row['username'];
                log_event('auth_success', 'user=' . $row['username'], (string) $row['username']);
                $login = ['ok' => true, 'username' => $row['username'], 'role' => $row['role']];
            } else {
                log_event('auth_fail', 'user=' . $u, $u);
                $login = ['ok' => false, 'username' => $u];
            }
        } catch (PDOException $ex) {
            log_event('auth_fail', 'user=' . $u . ' (SQL error)', $u);
            $error = $ex->getMessage();
            $login = ['ok' => false, 'username' => $u];
        }
    } else {
        if ($injected) {
            log_event('sqli_blocked', 'login username=' . $u . ($p !== '' ? ' [password submitted]' : ''), $u);
        }
        $stmt = db()->prepare('SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?');
        $stmt->execute([$u, $digest]);
        $row = $stmt->fetch();
        if (is_array($row)) {
            $_SESSION['user'] = (string) $row['username'];
            log_event('auth_success', 'user=' . $row['username'], (string) $row['username']);
            $login = ['ok' => true, 'username' => $row['username'], 'role' => $row['role']];
        } else {
            log_event('auth_fail', 'user=' . $u, $u);
            $login = ['ok' => false, 'username' => $u];
        }
    }
}

if ($didSearch) {
    $injected = looks_like_sqli($q);
    if ($isVuln) {
        if ($injected) {
            log_event('sqli_attempt', $q);
        }
        $sqlShown = "SELECT id, username, email, role FROM users WHERE username LIKE '%{$q}%' OR email LIKE '%{$q}%'";
        try {
            $rows = db()->query($sqlShown)->fetchAll();
        } catch (PDOException $ex) {
            $error = $ex->getMessage();
            $rows = [];
        }
    } else {
        if ($injected) {
            log_event('sqli_blocked', $q);
        }
        $stmt = db()->prepare(
            'SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?'
        );
        $stmt->execute(['%' . $q . '%', '%' . $q . '%']);
        $rows = $stmt->fetchAll();
    }
}

ob_start();
?>
<div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
  <div class="mode <?= $isVuln ? 'vuln' : 'secure' ?>"><?= $isVuln ? 'Vulnerable' : 'Hardened' ?> · SQL injection</div>
  <h2 style="margin-top:10px"><?= $isVuln ? 'String-concatenated login and search' : 'Parameterised login and search' ?></h2>
  <p>
    <?php if ($isVuln): ?>
      Input is pasted straight into the SQL text, so a quote can end the string
      literal and add a <code>UNION SELECT</code> or a comment that removes the
      password check. Every action is real SQL against the fake database.
    <?php else: ?>
      Input is bound as data. The quote in a payload is never parsed as SQL,
      so the same payload returns no rows instead of an administrator session.
    <?php endif; ?>
  </p>
</div>

<div class="grid">
  <div class="card <?= $isVuln ? 'vuln' : 'secure' ?>">
    <h3>Login</h3>
    <form method="post" action="<?= e($action) ?>">
      <input type="hidden" name="action" value="login">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" value="<?= e($u) ?>" autocomplete="off">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="off">
      <button type="submit">Sign in</button>
    </form>
    <?php if ($login !== null): ?>
      <div class="result note <?= $login['ok'] ? 'good' : 'bad' ?>">
        <?php if ($login['ok']): ?>
          Signed in as <strong><?= e($login['username']) ?></strong>
          with role <strong><?= e($login['role']) ?></strong>.
        <?php else: ?>
          Login failed for <strong><?= e($login['username']) ?></strong>.
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <h3 style="margin-top:22px">Search users</h3>
    <form method="get" action="<?= e($action) ?>">
      <label for="q">Username or email contains</label>
      <input id="q" name="q" type="text" value="<?= e($q) ?>" autocomplete="off">
      <button type="submit">Search</button>
    </form>

    <?php if ($rows !== null): ?>
      <div class="result">
        <div class="kv"><span>Rows returned:</span><b><?= count($rows) ?></b></div>
        <table>
          <tr><th>ID</th><th>User</th><th>Email / injected column</th><th>Role</th></tr>
          <?php foreach ($rows as $row): ?>
            <tr>
              <td><?= e((string) $row['id']) ?></td>
              <td><?= e((string) $row['username']) ?></td>
              <td><?= e((string) $row['email']) ?></td>
              <td><?= e((string) $row['role']) ?></td>
            </tr>
          <?php endforeach; ?>
          <?php if ($rows === []): ?>
            <tr><td colspan="4">No rows.</td></tr>
          <?php endif; ?>
        </table>
      </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3>What the code did</h3>
    <?php if ($sqlShown !== null): ?>
      <label>SQL actually executed</label>
      <pre><?= e($sqlShown) ?></pre>
    <?php else: ?>
      <p class="hint">Submit the form to see the exact SQL. The hardened mode
      never displays a query because the input is not part of it.</p>
    <?php endif; ?>
    <?php if ($error !== null): ?>
      <div class="note bad"><strong>Database error:</strong> <?= e($error) ?></div>
    <?php endif; ?>

    <h3 style="margin-top:18px">Harmless proof-of-concept inputs</h3>
    <ul class="hint">
      <li>Login username: <code>admin' -- </code> (any password)</li>
      <li>Search: <code>' UNION SELECT 999, username, password_hash, 'leaked' FROM users -- </code></li>
    </ul>
    <?php if ($isVuln): ?>
      <div class="note bad">The login payload removes the password check, and the
      search payload adds a synthetic row marked <code>leaked</code> whose email
      column contains the fake password digest.</div>
    <?php else: ?>
      <div class="note good">Both payloads are neutralised: the login fails, the
      search returns no rows, and <code>sqli_blocked</code> is written to the
      security log.</div>
    <?php endif; ?>
  </div>
</div>
<?php
render_page('SQL injection · ' . ($isVuln ? 'vulnerable' : 'hardened'), (string) ob_get_clean(), $ACTIVE);
