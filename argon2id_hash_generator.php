<?php
// argon2id_hash_generator.php
// Standalone script for generating strong Argon2ID hashes for username and password
function validate_strong($str, &$errorMsg = "") {
    // At least 28 chars, at least 7 lowercase, 7 uppercase, 7 numbers, 7 special, max 3 of same in a row
    if (strlen($str) < 28) {
        $errorMsg = "Must be at least 28 characters.";
        return false;
    }
    if (preg_match('/(.)\1\1\1/', $str)) {
        $errorMsg = "No more than three identical characters in a row are allowed.";
        return false;
    }
    if (preg_match_all('/[a-z]/', $str, $m) < 7) {
        $errorMsg = "Must contain at least 7 lowercase letters.";
        return false;
    }
    if (preg_match_all('/[A-Z]/', $str, $m) < 7) {
        $errorMsg = "Must contain at least 7 uppercase letters.";
        return false;
    }
    if (preg_match_all('/[0-9]/', $str, $m) < 7) {
        $errorMsg = "Must contain at least 7 numbers.";
        return false;
    }
    if (preg_match_all('/[^A-Za-z0-9]/', $str, $m) < 7) {
        $errorMsg = "Must contain at least 7 special characters.";
        return false;
    }
    return true;
}

// Example generator: returns a string that matches the requirements
function generate_strong_hex2bin_example() {
    // 7 lowercase, 7 uppercase, 7 digits, 7 special, none more than 3 in a row, total 28 chars
    $lower = str_split('abcdefghijklmnopqrstuvwxyz');
    $upper = str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    $digit = str_split('0123456789');
    $special = str_split('!@#$%^&*()-_=+,.?;:[]{}~');
    shuffle($lower); shuffle($upper); shuffle($digit); shuffle($special);

    $pool = [
        array_slice($lower, 0, 7),
        array_slice($upper, 0, 7),
        array_slice($digit, 0, 7),
        array_slice($special, 0, 7)
    ];
    $result = [];
    // Interleave chars to avoid >3 in a row and shuffle later
    for ($i = 0; $i < 7; $i++) {
        foreach ($pool as $set) $result[] = $set[$i];
    }
    // Shuffle but avoid >3 repeats
    do {
        shuffle($result);
        $str = implode('', $result);
    } while (preg_match('/(.)\1\1\1/', $str));
    // Use hex2bin with random 56-hex-digit string to show another example
    $hex = bin2hex(random_bytes(14)); // 28 hex chars, will be 14 bytes after hex2bin
    $bin = hex2bin($hex);
    // To make bin printable, base64-encode it for display
    return [
        'strong' => $str,
        'hex'    => $hex,
        'base64' => base64_encode($bin)
    ];
}

$output = '';
$errors = [];
$example = generate_strong_hex2bin_example();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $userErr = $passErr = "";
    if (!validate_strong($username, $userErr)) {
        $errors[] = "Username: $userErr";
    }
    if (!validate_strong($password, $passErr)) {
        $errors[] = "Password: $passErr";
    }
    if (!$errors) {
        $username_hash = password_hash($username, PASSWORD_ARGON2ID);
        $password_hash = password_hash($password, PASSWORD_ARGON2ID);
        $output = "Copy and paste the following for your config file:<br><br>";
        $output .= "<pre>return [\n    'username_hash' => '" . htmlspecialchars($username_hash, ENT_QUOTES) . "',\n    'password_hash' => '" . htmlspecialchars($password_hash, ENT_QUOTES) . "',\n];</pre>";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Argon2ID Hash Generator</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    :root {
        --padding: clamp(1em, 4vw, 2.5em);
        --max-width: clamp(350px, 80vw, 600px);
        --input-font: clamp(1em, 2.5vw, 1.1em);
        --container-radius: clamp(6px, 1vw, 16px);
    }
    html { box-sizing: border-box; }
    *,*:before,*:after{ box-sizing:inherit; }
    body {
        font-family: system-ui, sans-serif;
        background: #f7f7f7;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: var(--max-width);
        margin: clamp(1em, 5vw, 40px) auto;
        background: #fff;
        border-radius: var(--container-radius);
        padding: var(--padding);
        box-shadow: 0 2px 16px rgba(0,0,0,0.07);
        min-width: 0;
    }
    label {
        display: block;
        margin-top: 1em;
        font-size: 1em;
    }
    input[type="password"], input[type="text"] {
        width: 100%;
        padding: .5em;
        font-size: var(--input-font);
        border-radius: 4px;
        border: 1px solid #ccc;
        margin-top: .3em;
        margin-bottom: .7em;
    }
    .btn {
        margin-top: 1.3em;
        background: #2d82ef;
        color: #fff;
        border: none;
        padding: .7em 1.8em;
        border-radius: 4px;
        font-size: var(--input-font);
        cursor: pointer;
        transition: background .2s;
    }
    .btn:disabled { background: #aaa; }
    .errors {
        color: #a00;
        margin-bottom: 1em;
        font-size: clamp(.98em, 1.7vw, 1.05em);
    }
    pre, code {
        background: #222;
        color: #5ffba0;
        padding: .8em .7em;
        border-radius: 7px;
        display: block;
        font-size: clamp(.97em,1.85vw,1.09em);
        white-space: pre-wrap;
        word-break: break-all;
        margin-bottom: .7em;
    }
    .example-block {
        background: #23272e;
        color: #b8e1ff;
        border-radius: 8px;
        padding: clamp(1em, 3vw, 2em);
        margin-bottom: clamp(1em, 4vw, 2em);
        font-size: clamp(.96em, 1.7vw, 1.14em);
        overflow-x: auto;
    }
    .output { margin-top: 1.2em; }
    @media (max-width: 600px) {
        .container { padding: 1em;}
        pre, code, .example-block { font-size: .96em; }
    }
    </style>
</head>
<body>
<div class="container">
    <h2>Argon2ID Username/Password Hash Generator</h2>
    <div class="example-block">
        <strong>Example strong string:</strong>
        <pre><code><?= htmlspecialchars($example['strong']) ?></code></pre>
        <strong>Example hex2bin string (base64-encoded output):</strong>
        <pre><code>hex: <?= htmlspecialchars($example['hex']) ?>

base64: <?= htmlspecialchars($example['base64']) ?></code></pre>
        <small>(These examples are randomly generated and just for reference.)</small>
    </div>
    <?php if ($errors): ?>
        <div class="errors">
            <ul>
                <?php foreach ($errors as $e): ?><li><?= htmlspecialchars($e) ?></li><?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
    <?php if ($output): ?>
        <div class="output"><?= $output ?></div>
    <?php else: ?>
    <form method="post" autocomplete="off" spellcheck="false">
        <label>
            Username (min 28 chars, at least 7 lowercase, 7 uppercase, 7 numbers, 7 special, max 3 identical in a row):
            <input type="text" name="username" minlength="28" maxlength="128" required pattern="^(?=(?:[^a-z]*[a-z]){7,})(?=(?:[^A-Z]*[A-Z]){7,})(?=(?:[^0-9]*[0-9]){7,})(?=(?:[^A-Za-z0-9]*[^A-Za-z0-9]){7,})(?!.*(.)\1\1\1).{28,}$">
        </label>
        <label>
            Password (min 28 chars, at least 7 lowercase, 7 uppercase, 7 numbers, 7 special, max 3 identical in a row):
            <input type="password" name="password" minlength="28" maxlength="128" required pattern="^(?=(?:[^a-z]*[a-z]){7,})(?=(?:[^A-Z]*[A-Z]){7,})(?=(?:[^0-9]*[0-9]){7,})(?=(?:[^A-Za-z0-9]*[^A-Za-z0-9]){7,})(?!.*(.)\1\1\1).{28,}$">
        </label>
        <button class="btn" type="submit">Generate Argon2ID Hashes</button>
    </form>
    <?php endif; ?>
</div>
</body>
</html>
