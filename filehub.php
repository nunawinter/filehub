<?php
/**
 * FileHub — دانلود ریموت + مدیریت فایل (تک‌فایل، سازگار با PHP 7.4+)
 *
 * نصب: این فایل را در public_html (یا هر پوشه دلخواه) آپلود کنید و در مرورگر باز کنید.
 * بار اول از شما رمز عبور می‌خواهد. نیاز: افزونه cURL (در اکثر هاست‌ها فعال است).
 */
error_reporting(E_ALL);
@ini_set('display_errors', '0');
@ini_set('zlib.output_compression', '0');

const CONFIG_FILE      = __DIR__ . '/fm_config.php';
const BLOCK_PRIVATE_IPS = true;   // جلوگیری از دانلود از آدرس‌های داخلی/لوکال (امنیت)
const VERIFY_SSL        = true;   // اگر هاست گواهی SSL ندارد و خطا می‌دهد، false کنید

session_name('fh_sess');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'httponly' => true,
    'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS']),
]);
session_start();

/* ───────────────────────── ابزارها ───────────────────────── */

function cfg()
{
    static $c = false;
    if ($c === false) {
        $c = is_file(CONFIG_FILE) ? include CONFIG_FILE : null;
        if (!is_array($c) || empty($c['hash']) || empty($c['dir'])) $c = null;
    }
    return $c;
}
function store_dir(): string
{
    $d = __DIR__ . '/' . cfg()['dir'];
    if (!is_dir($d)) { @mkdir($d, 0755, true); write_htaccess($d); }
    return $d;
}
function tmp_dir(): string
{
    $d = store_dir() . '/.tmp';
    if (!is_dir($d)) @mkdir($d, 0755, true);
    return $d;
}
function write_htaccess(string $d): void
{
    @file_put_contents($d . '/.htaccess',
        "Options -Indexes\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" .
        "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n");
}
function json_out($data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function fail(string $msg, int $code = 400): void { json_out(['ok' => false, 'error' => $msg], $code); }

function clean_name(string $n): string
{
    $n = str_replace('\\', '/', $n);
    $n = basename($n);
    $n = preg_replace('/[\x00-\x1f\x7f<>:"|?*\/\\\\]/', '_', (string)$n);
    $n = trim((string)$n, " .");
    if ($n === '') $n = 'file';
    if (function_exists('mb_strcut')) $n = mb_strcut($n, 0, 200, 'UTF-8'); else $n = substr($n, 0, 200);
    // جلوگیری از اجرای اسکریپت‌های خطرناک
    if (preg_match('/\.(php\d?|phtml|phar|pht|phps|shtml|cgi|pl|py|sh|htaccess)$/i', $n)) $n .= '.txt';
    return $n;
}
function unique_path(string $dir, string $name): array
{
    $p = $dir . '/' . $name;
    if (!file_exists($p)) return [$name, $p];
    $info = pathinfo($name);
    $base = $info['filename'];
    $ext  = isset($info['extension']) ? '.' . $info['extension'] : '';
    for ($i = 1; $i < 10000; $i++) {
        $n = "$base ($i)$ext";
        if (!file_exists("$dir/$n")) return [$n, "$dir/$n"];
    }
    $n = $base . '-' . bin2hex(random_bytes(3)) . $ext;
    return [$n, "$dir/$n"];
}
function existing_file(string $n): ?string
{
    if ($n === '' || $n[0] === '.' || $n !== basename($n) || strpbrk($n, "/\\\0") !== false) return null;
    $p = store_dir() . '/' . $n;
    return is_file($p) ? $p : null;
}
function ini_bytes($v): int
{
    $v = trim((string)$v);
    if ($v === '') return 0;
    $u = strtolower(substr($v, -1));
    $n = (float)$v;
    switch ($u) { case 'g': $n *= 1024; case 'm': $n *= 1024; case 'k': $n *= 1024; }
    return (int)$n;
}
function host_allowed(string $url): bool
{
    $h = parse_url($url, PHP_URL_HOST);
    if (!$h) return false;
    if (!BLOCK_PRIVATE_IPS) return true;
    $h = trim($h, '[]');
    $ips = filter_var($h, FILTER_VALIDATE_IP) ? [$h] : (@gethostbynamel($h) ?: []);
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;
    }
    return true;
}
function job_write(string $f, array $d): void
{
    $d['updated'] = time();
    @file_put_contents($f, json_encode($d, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
}
function detach(array $payload): void
{
    ignore_user_abort(true);
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($body));
    header('Connection: close');
    echo $body;
    while (ob_get_level() > 0) @ob_end_flush();
    flush();
    if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();
    elseif (function_exists('litespeed_finish_request')) litespeed_finish_request();
}
function curl_msg(int $no, string $raw, int $http): string
{
    $map = [
        6  => 'آدرس سایت پیدا نشد (DNS)',
        7  => 'اتصال به سرور برقرار نشد',
        28 => 'زمان اتصال به پایان رسید',
        35 => 'خطای SSL در اتصال امن',
        60 => 'گواهی SSL سایت معتبر نیست',
        23 => 'خطا در نوشتن فایل (شاید فضای هاست پر شده)',
        18 => 'دانلود ناقص ماند',
        56 => 'ارتباط در میانه دانلود قطع شد',
    ];
    if ($no === 22) return 'سرور مبدأ خطا داد (کد HTTP ' . $http . ')';
    return ($map[$no] ?? 'خطا') . ($no && !isset($map[$no]) ? ' — ' . $raw : '');
}

function stream_file(string $path, string $name): void
{
    @set_time_limit(0);
    $size = filesize($path);
    $start = 0; $end = $size - 1; $code = 200;
    if ($size > 0 && isset($_SERVER['HTTP_RANGE']) &&
        preg_match('/^bytes=(\d*)-(\d*)$/', trim($_SERVER['HTTP_RANGE']), $m) && ($m[1] !== '' || $m[2] !== '')) {
        if ($m[1] === '') { $start = max(0, $size - (int)$m[2]); }
        else { $start = (int)$m[1]; if ($m[2] !== '') $end = min($end, (int)$m[2]); }
        if ($start > $end || $start >= $size) {
            http_response_code(416); header("Content-Range: bytes */$size"); exit;
        }
        $code = 206;
    }
    while (ob_get_level() > 0) @ob_end_clean();
    http_response_code($code);
    $ascii = str_replace(['"', '\\'], '_', preg_replace('/[^\x20-\x7e]/', '_', $name));
    header('Content-Type: application/octet-stream');
    header('X-Content-Type-Options: nosniff');
    header('Accept-Ranges: bytes');
    header('Content-Disposition: attachment; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Content-Length: ' . max(0, $end - $start + 1));
    if ($code === 206) header("Content-Range: bytes $start-$end/$size");
    $fp = fopen($path, 'rb');
    fseek($fp, $start);
    $left = $end - $start + 1;
    while ($left > 0 && !feof($fp) && !connection_aborted()) {
        $buf = fread($fp, (int)min(1048576, $left));
        if ($buf === false || $buf === '') break;
        echo $buf; $left -= strlen($buf); flush();
    }
    fclose($fp);
    exit;
}

function run_download(string $id, string $url, string $custom): void
{
    @set_time_limit(0);
    ignore_user_abort(true);
    $tmp   = tmp_dir();
    $jobF  = "$tmp/job_$id.json";
    $part  = "$tmp/job_$id.part";
    $cancel = "$tmp/job_$id.cancel";

    $urlPath = parse_url($url, PHP_URL_PATH);
    $urlName = $urlPath ? rawurldecode(basename($urlPath)) : '';
    $display = $custom !== '' ? $custom : ($urlName !== '' ? clean_name($urlName) : 'download');

    job_write($jobF, ['state' => 'running', 'name' => $display, 'done' => 0, 'total' => 0]);
    detach(['ok' => true, 'id' => $id]);

    $finished = false;
    register_shutdown_function(function () use (&$finished, $jobF, $part) {
        if (!$finished) {
            @unlink($part);
            job_write($jobF, ['state' => 'error', 'error' => 'اجرای اسکریپت توسط هاست متوقف شد (محدودیت زمان/حافظه)']);
        }
    });

    $cdName = null;
    $last = 0.0;
    $fp = fopen($part, 'wb');
    if (!$fp) { $finished = true; job_write($jobF, ['state' => 'error', 'error' => 'امکان ایجاد فایل موقت نیست']); return; }

    $hf = function ($ch, $h) use (&$cdName) {
        if (stripos($h, 'HTTP/') === 0) $cdName = null;
        elseif (stripos($h, 'content-disposition:') === 0) {
            if (preg_match("/filename\*\s*=\s*UTF-8''([^;\r\n]+)/i", $h, $m)) $cdName = rawurldecode(trim($m[1], " \"'"));
            elseif (preg_match('/filename\s*=\s*"?([^";\r\n]+)"?/i', $h, $m)) $cdName = trim($m[1]);
        }
        return strlen($h);
    };
    $cb = function ($ch, $dlT, $dlN) use (&$last, $jobF, $cancel, $custom, $display, &$cdName) {
        $now = microtime(true);
        if ($now - $last < 0.4) return 0;
        $last = $now;
        if (is_file($cancel)) return 1;
        $nm = $custom !== '' ? $custom : ($cdName ? clean_name($cdName) : $display);
        job_write($jobF, ['state' => 'running', 'name' => $nm, 'done' => (int)$dlN, 'total' => (int)$dlT]);
        return 0;
    };

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FILE            => $fp,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 10,
        CURLOPT_CONNECTTIMEOUT  => 20,
        CURLOPT_TIMEOUT         => 0,
        CURLOPT_LOW_SPEED_LIMIT => 1,
        CURLOPT_LOW_SPEED_TIME  => 120,
        CURLOPT_FAILONERROR     => true,
        CURLOPT_USERAGENT       => 'Mozilla/5.0 (compatible; FileHub/1.0)',
        CURLOPT_SSL_VERIFYPEER  => VERIFY_SSL,
        CURLOPT_SSL_VERIFYHOST  => VERIFY_SSL ? 2 : 0,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HEADERFUNCTION  => $hf,
        CURLOPT_NOPROGRESS      => false,
        CURLOPT_PROGRESSFUNCTION => $cb,
    ]);
    $ok   = curl_exec($ch);
    $errn = curl_errno($ch);
    $errm = curl_error($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    fclose($fp);

    if (is_file($cancel)) {
        @unlink($part); @unlink($cancel);
        $finished = true;
        job_write($jobF, ['state' => 'cancelled']);
        return;
    }
    if (!$ok) {
        @unlink($part);
        $finished = true;
        job_write($jobF, ['state' => 'error', 'error' => curl_msg($errn, $errm, $http)]);
        return;
    }
    $final = $custom !== '' ? $custom : ($cdName ? clean_name($cdName) : $display);
    [$finalName, $finalPath] = unique_path(store_dir(), clean_name($final));
    if (!@rename($part, $finalPath)) {
        @unlink($part);
        $finished = true;
        job_write($jobF, ['state' => 'error', 'error' => 'انتقال فایل نهایی ناموفق بود']);
        return;
    }
    $finished = true;
    job_write($jobF, ['state' => 'done', 'name' => $finalName, 'size' => filesize($finalPath)]);
}

/* ───────────────────────── ظاهر مشترک ───────────────────────── */

function base_css(): string
{
    return <<<'CSS'
:root{--bg:#f4f5fb;--card:#fff;--text:#1d2033;--muted:#6b7090;--line:#e6e8f2;--p1:#6d5dfc;--p2:#b06bff;--ok:#16a34a;--err:#e11d48;--shadow:0 12px 32px -14px rgba(60,50,160,.3)}
@media(prefers-color-scheme:dark){:root{--bg:#0e1120;--card:#171b30;--text:#e8eaf6;--muted:#98a0c6;--line:#262b47;--shadow:0 12px 32px -14px rgba(0,0,0,.7)}}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.8 Vazirmatn,Tahoma,"Segoe UI",system-ui,sans-serif}
input,textarea,button{font:inherit;color:inherit}
.btn{border:0;cursor:pointer;border-radius:12px;padding:10px 18px;font-weight:600;background:linear-gradient(135deg,var(--p1),var(--p2));color:#fff;transition:.2s;box-shadow:0 8px 18px -8px var(--p1)}
.btn:hover{transform:translateY(-1px);filter:brightness(1.07)}.btn:disabled{opacity:.55;cursor:not-allowed;transform:none}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line);box-shadow:none}
.btn.danger{background:linear-gradient(135deg,#f43f5e,#e11d48);box-shadow:0 8px 18px -8px #e11d48}
.btn.sm{padding:4px 12px;font-size:13px;border-radius:9px}
.field{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:var(--bg);outline:none;transition:.2s}
.field:focus{border-color:var(--p1);box-shadow:0 0 0 4px rgba(109,93,252,.15)}
CSS;
}
function shell(string $title, string $body, string $extraCss = ''): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('X-Robots-Tag: noindex, nofollow');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">',
         '<title>', htmlspecialchars($title), '</title><style>', base_css(), $extraCss, '</style></head><body>', $body, '</body></html>';
}
function auth_page(string $title, string $sub, string $fields, string $btn, string $csrf, string $err = ''): void
{
    $css = '.wrap{min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(900px 500px at 80% -10%,rgba(176,107,255,.35),transparent),radial-gradient(800px 500px at 0% 110%,rgba(109,93,252,.3),transparent)}'
         . '.box{width:100%;max-width:400px;background:var(--card);border-radius:24px;padding:34px 28px;box-shadow:var(--shadow);border:1px solid var(--line)}'
         . '.logo{width:64px;height:64px;border-radius:20px;background:linear-gradient(135deg,var(--p1),var(--p2));display:grid;place-items:center;font-size:30px;margin:0 auto 14px;box-shadow:0 14px 26px -10px var(--p1)}'
         . 'h1{margin:0;text-align:center;font-size:22px}p.s{margin:4px 0 22px;text-align:center;color:var(--muted);font-size:14px}'
         . '.box .field{margin-bottom:12px}.box .btn{width:100%;padding:12px}.e{background:rgba(225,29,72,.1);color:var(--err);padding:10px 14px;border-radius:12px;margin-bottom:14px;font-size:14px}';
    $body = '<div class="wrap"><form class="box" method="post"><div class="logo">📦</div><h1>' . htmlspecialchars($title) . '</h1><p class="s">' . htmlspecialchars($sub) . '</p>'
          . ($err ? '<div class="e">' . htmlspecialchars($err) . '</div>' : '')
          . '<input type="hidden" name="csrf" value="' . htmlspecialchars($csrf) . '">' . $fields
          . '<button class="btn">' . htmlspecialchars($btn) . '</button></form></div>';
    shell($title, $body, $css);
}

/* ───────────────────────── نصب اولیه / ورود ───────────────────────── */

$a = $_GET['a'] ?? '';

if (!cfg()) {
    $err = '';
    if (empty($_SESSION['scsrf'])) $_SESSION['scsrf'] = bin2hex(random_bytes(16));
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && hash_equals($_SESSION['scsrf'], $_POST['csrf'] ?? '')) {
        $p1 = (string)($_POST['p1'] ?? ''); $p2 = (string)($_POST['p2'] ?? '');
        if (strlen($p1) < 8) $err = 'رمز عبور باید حداقل ۸ کاراکتر باشد.';
        elseif ($p1 !== $p2) $err = 'تکرار رمز عبور مطابقت ندارد.';
        else {
            $dir = 'files_' . bin2hex(random_bytes(5));
            $c = ['hash' => password_hash($p1, PASSWORD_DEFAULT), 'dir' => $dir];
            if (!@mkdir(__DIR__ . '/' . $dir, 0755, true)) $err = 'ساخت پوشه ذخیره‌سازی ممکن نیست؛ دسترسی نوشتن پوشه را بررسی کنید.';
            else {
                write_htaccess(__DIR__ . '/' . $dir);
                if (@file_put_contents(CONFIG_FILE, "<?php\nreturn " . var_export($c, true) . ";\n") === false) $err = 'نوشتن فایل تنظیمات ممکن نیست؛ دسترسی نوشتن پوشه را بررسی کنید.';
                else { header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit; }
            }
        }
    }
    auth_page('نصب اولیه', 'یک رمز عبور برای ورود تعیین کنید',
        '<input class="field" type="password" name="p1" placeholder="رمز عبور (حداقل ۸ کاراکتر)" required autofocus>' .
        '<input class="field" type="password" name="p2" placeholder="تکرار رمز عبور" required>',
        'ذخیره و شروع', $_SESSION['scsrf'], $err);
    exit;
}

if (empty($_SESSION['auth'])) {
    if ($a !== '') json_out(['ok' => false, 'error' => 'نشست منقضی شده؛ دوباره وارد شوید.', 'auth' => false], 401);
    $err = '';
    if (empty($_SESSION['lcsrf'])) $_SESSION['lcsrf'] = bin2hex(random_bytes(16));
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (hash_equals($_SESSION['lcsrf'], $_POST['csrf'] ?? '') && password_verify((string)($_POST['pw'] ?? ''), cfg()['hash'])) {
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        sleep(2);
        $err = 'رمز عبور اشتباه است.';
    }
    auth_page('ورود', 'برای ادامه رمز عبور را وارد کنید',
        '<input class="field" type="password" name="pw" placeholder="رمز عبور" required autofocus>',
        'ورود', $_SESSION['lcsrf'], $err);
    exit;
}

/* ───────────────────────── API (پس از ورود) ───────────────────────── */

$csrf = $_SESSION['csrf'];
if (isset($_GET['logout']) && hash_equals($csrf, $_GET['t'] ?? '')) {
    $_SESSION = []; session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit;
}
session_write_close(); // جلوگیری از قفل شدن درخواست‌های هم‌زمان

if ($a !== '') {
    $dir = store_dir();
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    if (in_array($a, ['start', 'cancel', 'upload', 'upload_abort', 'delete'], true)) {
        if (!$post) fail('روش درخواست نامعتبر است.', 405);
        if (!hash_equals($csrf, $_SERVER['HTTP_X_CSRF'] ?? '')) fail('توکن امنیتی نامعتبر است؛ صفحه را رفرش کنید.', 403);
    }
    $isId = function ($v) { return is_string($v) && preg_match('/^[a-f0-9]{16}$/', $v); };

    switch ($a) {
        case 'list':
            $items = [];
            foreach (scandir($dir) ?: [] as $f) {
                if ($f[0] === '.') continue;
                $p = "$dir/$f";
                if (!is_file($p)) continue;
                $items[] = ['name' => $f, 'size' => filesize($p), 'mtime' => filemtime($p)];
            }
            usort($items, function ($x, $y) { return $y['mtime'] <=> $x['mtime']; });
            // پاکسازی فایل‌های موقت قدیمی
            foreach (glob(tmp_dir() . '/*') ?: [] as $t) if (is_file($t) && filemtime($t) < time() - 172800) @unlink($t);
            json_out(['ok' => true, 'files' => $items, 'free' => @disk_free_space($dir), 'total' => @disk_total_space($dir)]);

        case 'get':
            $p = existing_file((string)($_GET['name'] ?? ''));
            if (!$p) { http_response_code(404); echo 'File not found'; exit; }
            stream_file($p, basename($p));
            break;

        case 'progress':
            $id = $_GET['id'] ?? '';
            if (!$isId($id)) fail('شناسه نامعتبر');
            $f = tmp_dir() . "/job_$id.json";
            $d = is_file($f) ? json_decode((string)file_get_contents($f), true) : null;
            if (!is_array($d)) $d = ['state' => 'waiting'];
            $d['ok'] = true; $d['now'] = time();
            json_out($d);

        case 'start':
            $id = $_POST['id'] ?? '';
            if (!$isId($id)) fail('شناسه نامعتبر');
            $url = trim((string)($_POST['url'] ?? ''));
            if (!preg_match('#^https?://[^\s]+$#i', $url) || !parse_url($url, PHP_URL_HOST)) fail('آدرس واردشده معتبر نیست (باید با http:// یا https:// شروع شود).');
            if (!host_allowed($url)) fail('این آدرس مجاز نیست (آدرس داخلی یا محلی).');
            if (!function_exists('curl_init')) fail('افزونه cURL روی این هاست فعال نیست.');
            $custom = trim((string)($_POST['name'] ?? ''));
            run_download($id, $url, $custom !== '' ? clean_name($custom) : '');
            exit;

        case 'cancel':
            $id = $_POST['id'] ?? '';
            if (!$isId($id)) fail('شناسه نامعتبر');
            @touch(tmp_dir() . "/job_$id.cancel");
            json_out(['ok' => true]);

        case 'upload':
            $uid = $_POST['uid'] ?? '';
            if (!$isId($uid)) fail('شناسه نامعتبر');
            if (!isset($_FILES['chunk']) || $_FILES['chunk']['error'] !== UPLOAD_ERR_OK) {
                $e = $_FILES['chunk']['error'] ?? -1;
                fail($e === UPLOAD_ERR_INI_SIZE || $e === UPLOAD_ERR_FORM_SIZE ? 'اندازه تکه آپلود از حد مجاز هاست بیشتر است.' : 'دریافت فایل ناموفق بود (کد ' . $e . ').');
            }
            $offset = max(0, (int)($_POST['offset'] ?? 0));
            $last = ($_POST['last'] ?? '0') === '1';
            $tmp = tmp_dir() . "/up_$uid.part";
            $fh = fopen($tmp, 'c+b');
            if (!$fh) fail('امکان نوشتن فایل موقت نیست.', 500);
            flock($fh, LOCK_EX);
            $cur = (int)(fstat($fh)['size'] ?? 0);
            if ($offset > $cur) { flock($fh, LOCK_UN); fclose($fh); fail('ترتیب تکه‌ها نامعتبر است.'); }
            ftruncate($fh, $offset);
            fseek($fh, $offset);
            $in = fopen($_FILES['chunk']['tmp_name'], 'rb');
            stream_copy_to_stream($in, $fh);
            fclose($in);
            fflush($fh); flock($fh, LOCK_UN); fclose($fh);
            if ($last) {
                [$n, $p] = unique_path($dir, clean_name((string)($_POST['name'] ?? 'file')));
                if (!@rename($tmp, $p)) fail('ذخیره فایل نهایی ناموفق بود.', 500);
                json_out(['ok' => true, 'name' => $n, 'size' => filesize($p)]);
            }
            json_out(['ok' => true]);

        case 'upload_abort':
            $uid = $_POST['uid'] ?? '';
            if ($isId($uid)) @unlink(tmp_dir() . "/up_$uid.part");
            json_out(['ok' => true]);

        case 'delete':
            $names = $_POST['names'] ?? [];
            if (!is_array($names)) $names = [];
            $n = 0;
            foreach ($names as $nm) {
                $p = existing_file((string)$nm);
                if ($p && @unlink($p)) $n++;
            }
            json_out(['ok' => true, 'deleted' => $n]);

        default:
            fail('درخواست نامعتبر', 404);
    }
    exit;
}

/* ───────────────────────── رابط کاربری ───────────────────────── */

$m = min(ini_bytes(ini_get('upload_max_filesize')) ?: 8388608, ini_bytes(ini_get('post_max_size')) ?: 8388608);
$chunk = max(65536, min(8388608, $m - 131072));
$boot = json_encode(['csrf' => $csrf, 'chunk' => $chunk], JSON_UNESCAPED_UNICODE);

$css = <<<'CSS'
.hero{background:linear-gradient(135deg,var(--p1),var(--p2));color:#fff;padding:26px 0 90px}
.c{max-width:980px;margin:0 auto;padding:0 16px}
.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.top .logo{width:50px;height:50px;border-radius:16px;background:rgba(255,255,255,.2);display:grid;place-items:center;font-size:26px;backdrop-filter:blur(6px)}
.top h1{margin:0;font-size:22px;line-height:1.3}.top small{opacity:.85}
.top .sp{flex:1}
.hero .btn.ghost{color:#fff;border-color:rgba(255,255,255,.4)}
.disk{margin-top:18px;max-width:420px}.disk .bar{background:rgba(255,255,255,.25)}.disk .bar>i{background:#fff!important}
.disk span{font-size:13px;opacity:.9}
main{margin-top:-60px;display:grid;gap:18px;padding-bottom:50px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:760px){.grid2{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:22px;box-shadow:var(--shadow)}
.card h2{margin:0 0 4px;font-size:17px;display:flex;align-items:center;gap:8px}
.card p.h{margin:0 0 14px;color:var(--muted);font-size:13px}
textarea.field{resize:vertical;min-height:84px;direction:ltr;text-align:left}
.row2{display:flex;gap:10px;margin-top:10px;flex-wrap:wrap}.row2 .field{flex:1;min-width:140px}
.drop{border:2px dashed var(--line);border-radius:18px;padding:30px 14px;text-align:center;cursor:pointer;transition:.2s;color:var(--muted);background:var(--bg)}
.drop:hover,.drop.on{border-color:var(--p1);background:rgba(109,93,252,.07);color:var(--text)}
.drop .big{font-size:34px;display:block;margin-bottom:4px}
.task{border:1px solid var(--line);border-radius:16px;padding:12px 14px;margin-top:10px;background:var(--bg)}
.t-top{display:flex;align-items:center;gap:10px}.t-name{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
.bar{height:11px;background:var(--line);border-radius:99px;overflow:hidden;margin:10px 0 6px}
.bar>i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--p1),var(--p2));transition:width .35s ease}
.bar.run>i{background-image:repeating-linear-gradient(135deg,rgba(255,255,255,.28) 0 10px,transparent 10px 20px),linear-gradient(90deg,var(--p1),var(--p2));background-size:28px 28px,100% 100%;animation:mv 1s linear infinite}
@keyframes mv{to{background-position:28px 0,0 0}}
.bar.indet>i{width:35%!important;animation:ind 1.2s ease-in-out infinite}
@keyframes ind{0%{margin-inline-start:-35%}100%{margin-inline-start:100%}}
.t-meta{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--muted)}.t-meta b{color:var(--text)}
.t-msg{font-size:13px;margin-top:4px}.task.ok .t-msg{color:var(--ok)}.task.err .t-msg{color:var(--err)}
.bar.ok>i{background:var(--ok)}.bar.err>i{background:var(--err)}
.fh{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.fh h2{margin:0;flex:1}.fh .field{max-width:220px;padding:8px 12px}
.frow{display:grid;grid-template-columns:26px 34px 1fr auto auto;gap:12px;align-items:center;padding:11px 8px;border-bottom:1px solid var(--line);border-radius:10px}
.frow:hover{background:var(--bg)}.frow:last-child{border-bottom:0}
.fic{font-size:24px;text-align:center}.fn{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.fn small{display:block;color:var(--muted);font-weight:400;font-size:12px}
.fsz{color:var(--muted);font-size:13px;white-space:nowrap}
.act{display:flex;gap:6px}
.act a{text-decoration:none;display:inline-block}
.empty{text-align:center;color:var(--muted);padding:34px 0}
input[type=checkbox]{width:18px;height:18px;accent-color:var(--p1)}
.toast{position:fixed;bottom:22px;inset-inline:0;margin:auto;width:max-content;max-width:90%;background:#1d2033;color:#fff;padding:11px 20px;border-radius:14px;box-shadow:0 14px 30px -10px #000;opacity:0;transform:translateY(20px);transition:.3s;pointer-events:none;z-index:9}
.toast.on{opacity:1;transform:none}
@media(max-width:560px){.frow{grid-template-columns:24px 28px 1fr auto}.fsz.d{display:none}}
CSS;

$html = <<<'HTML'
<div class="hero"><div class="c">
  <div class="top"><div class="logo">📦</div><div><h1>مرکز دانلود و مدیریت فایل</h1><small>دانلود مستقیم روی هاست · آپلود · مدیریت</small></div><div class="sp"></div>
  <a class="btn ghost sm" id="logout" href="#">خروج</a></div>
  <div class="disk" id="disk" hidden><div class="bar"><i></i></div><span></span></div>
</div></div>
<div class="c"><main>
  <div class="grid2">
    <section class="card">
      <h2>⬇️ دانلود از لینک</h2><p class="h">لینک را وارد کنید؛ فایل مستقیم روی هاست شما دانلود می‌شود. هر خط یک لینک.</p>
      <textarea class="field" id="urls" placeholder="https://example.com/file.zip" spellcheck="false"></textarea>
      <div class="row2"><input class="field" id="rname" placeholder="نام دلخواه فایل (اختیاری)"><button class="btn" id="go">شروع دانلود</button></div>
    </section>
    <section class="card">
      <h2>⬆️ آپلود فایل</h2><p class="h">فایل‌ها را بکشید و رها کنید یا کلیک کنید. فایل‌های بزرگ تکه‌تکه و بدون محدودیت هاست آپلود می‌شوند.</p>
      <div class="drop" id="drop"><span class="big">📁</span>فایل‌ها را اینجا رها کنید یا کلیک کنید</div>
      <input type="file" id="pick" multiple hidden>
    </section>
  </div>
  <section class="card" id="tasksCard" hidden><h2>⏳ عملیات جاری</h2><div id="tasks"></div></section>
  <section class="card">
    <div class="fh"><h2>🗂️ فایل‌ها <small id="cnt" style="color:var(--muted);font-weight:400"></small></h2>
      <input class="field" id="q" placeholder="جستجو…">
      <button class="btn danger sm" id="bulk" hidden>حذف انتخاب‌شده‌ها</button>
      <button class="btn ghost sm" id="refresh">↻ بازخوانی</button></div>
    <label class="fsz" style="display:flex;gap:8px;align-items:center;padding:0 8px 6px"><input type="checkbox" id="all"> انتخاب همه</label>
    <div id="list"></div>
  </section>
</main></div>
<div class="toast" id="toast"></div>
HTML;

$js = <<<'JS'
const FH=window.FH,$=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const rid=()=>Array.from(crypto.getRandomValues(new Uint8Array(8)),b=>b.toString(16).padStart(2,'0')).join('');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const nf=new Intl.NumberFormat('fa-IR',{maximumFractionDigits:1}),nf0=new Intl.NumberFormat('fa-IR',{maximumFractionDigits:0});
const df=new Intl.DateTimeFormat('fa-IR',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});
function fmtBytes(b){if(!b||b<1)return nf.format(0)+' بایت';const u=['بایت','کیلوبایت','مگابایت','گیگابایت','ترابایت'];const i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);return nf.format(b/Math.pow(1024,i))+' '+u[i]}
function fmtDur(s){s=Math.max(0,Math.round(s));if(s<60)return nf0.format(s)+' ثانیه';const m=Math.floor(s/60);if(m<60)return nf0.format(m)+' دقیقه و '+nf0.format(s%60)+' ثانیه';const h=Math.floor(m/60);return nf0.format(h)+' ساعت و '+nf0.format(m%60)+' دقیقه'}
const ICONS={zip:'🗜️',rar:'🗜️','7z':'🗜️',gz:'🗜️',tar:'🗜️',pdf:'📕',doc:'📘',docx:'📘',xls:'📗',xlsx:'📗',csv:'📗',ppt:'📙',pptx:'📙',txt:'📄',jpg:'🖼️',jpeg:'🖼️',png:'🖼️',gif:'🖼️',webp:'🖼️',svg:'🖼️',mp3:'🎵',wav:'🎵',flac:'🎵',mp4:'🎬',mkv:'🎬',avi:'🎬',mov:'🎬',iso:'💿',exe:'⚙️',apk:'📱',sql:'🗄️',json:'🧩',html:'🌐'};
const icon=n=>ICONS[(n.split('.').pop()||'').toLowerCase()]||'📄';
let tt;function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('on');clearTimeout(tt);tt=setTimeout(()=>t.classList.remove('on'),3200)}

async function api(a,{method='GET',data=null,params={}}={}){
  const q=new URLSearchParams(Object.assign({a},params));
  const o={method,headers:{'X-CSRF':FH.csrf},credentials:'same-origin'};
  if(data)o.body=data instanceof FormData?data:new URLSearchParams(data);
  const r=await fetch('?'+q,o);let j;
  try{j=await r.json()}catch(e){throw new Error('پاسخ نامعتبر از سرور ('+r.status+')')}
  if(j.auth===false)location.reload();
  return j;
}

/* ── کارت عملیات ── */
function makeTask(ic,title){
  const el=document.createElement('div');el.className='task';
  el.innerHTML='<div class="t-top"><span>'+ic+'</span><div class="t-name" dir="auto"></div><button class="btn ghost sm">لغو</button></div><div class="bar run indet"><i></i></div><div class="t-meta"><b class="pct"></b><span class="sz"></span><span class="spd"></span><span class="eta"></span></div><div class="t-msg"></div>';
  el.querySelector('.t-name').textContent=title;
  $('#tasks').prepend(el);$('#tasksCard').hidden=false;
  const bar=el.querySelector('.bar'),fill=bar.firstElementChild,btn=el.querySelector('button');
  const q=c=>el.querySelector(c);
  const t={el,btn,ended:false,cancelled:false,
    title(s){q('.t-name').textContent=s},
    note(s){q('.sz').textContent=s},
    set(done,total,sp){
      if(total>0){bar.classList.remove('indet');fill.style.width=Math.min(100,done/total*100)+'%';q('.pct').textContent=nf0.format(Math.min(100,done/total*100))+'٪';q('.sz').textContent=fmtBytes(done)+' از '+fmtBytes(total);
        q('.eta').textContent=sp>0?'· باقی‌مانده: '+fmtDur((total-done)/sp):''}
      else{bar.classList.add('indet');q('.pct').textContent='';q('.sz').textContent=fmtBytes(done);q('.eta').textContent=''}
      q('.spd').textContent=sp>0?'· '+fmtBytes(sp)+' در ثانیه':'';
    },
    finish(msg,ok){t.ended=true;bar.classList.remove('run','indet');bar.classList.add(ok?'ok':'err');el.classList.add(ok?'ok':'err');if(ok){fill.style.width='100%';q('.pct').textContent=nf0.format(100)+'٪';q('.eta').textContent='';q('.spd').textContent=''}
      q('.t-msg').textContent=msg;btn.disabled=false;btn.textContent='بستن';btn.onclick=()=>t.close()},
    close(){el.remove();if(!$('#tasks').children.length)$('#tasksCard').hidden=true}};
  return t;
}

/* ── دانلود ریموت ── */
function startRemote(url,name){
  const id=rid(),t=makeTask('⬇️',name||url);
  let stopped=false,timer,prev=null,sp=0,waitSince=Date.now();
  const stop=()=>{stopped=true;clearTimeout(timer)};
  t.btn.onclick=async()=>{t.btn.disabled=true;t.btn.textContent='در حال لغو…';try{await api('cancel',{method:'POST',data:{id}})}catch(e){}};
  const tick=async()=>{
    try{
      const j=await api('progress',{params:{id}});
      if(stopped)return;
      if(j.state==='waiting'){if(Date.now()-waitSince>30000){stop();t.finish('پاسخی از سرور دریافت نشد.',false);return}}
      else if(j.state==='running'){
        if(j.name)t.title(j.name);
        const now=performance.now();
        if(prev){const dt=(now-prev.t)/1000;if(dt>0){const inst=Math.max(0,(j.done-prev.d)/dt);sp=sp?sp*.6+inst*.4:inst}}
        prev={d:j.done,t:now};t.set(j.done,j.total,sp);
        if(j.now-j.updated>90){stop();t.finish('ارتباط قطع شد یا دانلود متوقف ماند.',false);return}
      }else if(j.state==='done'){stop();t.set(j.size,j.size,0);t.title(j.name);t.finish('✔ دانلود کامل شد',true);toast('دانلود شد: '+j.name);loadList();return}
      else if(j.state==='error'){stop();t.finish(j.error||'خطا',false);return}
      else if(j.state==='cancelled'){stop();t.finish('دانلود لغو شد.',false);return}
    }catch(e){}
    if(!stopped)timer=setTimeout(tick,800);
  };
  api('start',{method:'POST',data:{id,url,name}}).then(j=>{if(!j.ok&&!stopped){stop();t.finish(j.error||'خطا',false)}}).catch(()=>{});
  setTimeout(tick,500);
}
function submitUrls(){
  const lines=$('#urls').value.split('\n').map(s=>s.trim()).filter(Boolean);
  if(!lines.length){toast('لینک را وارد کنید');return}
  const nm=lines.length===1?$('#rname').value.trim():'';
  lines.forEach(u=>startRemote(u,nm));
  $('#urls').value='';$('#rname').value='';
}
$('#go').onclick=submitUrls;
$('#urls').addEventListener('keydown',e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey))submitUrls()});
$('#urls').addEventListener('input',()=>{const n=$('#urls').value.split('\n').filter(s=>s.trim()).length;$('#rname').disabled=n>1;$('#rname').placeholder=n>1?'نام دلخواه فقط برای یک لینک':'نام دلخواه فایل (اختیاری)'});

/* ── آپلود تکه‌ای ── */
function xhrPost(fd,onProg,t){
  return new Promise((res,rej)=>{
    const x=new XMLHttpRequest();x.open('POST','?a=upload');x.setRequestHeader('X-CSRF',FH.csrf);
    x.upload.onprogress=e=>onProg(e.loaded);
    x.onload=()=>{try{const j=JSON.parse(x.responseText);j.ok?res(j):rej(new Error(j.error||'خطا'))}catch(e){rej(new Error('پاسخ نامعتبر از سرور ('+x.status+')'))}};
    x.onerror=()=>rej(new Error('خطای شبکه'));x.onabort=()=>rej(new Error('لغو شد'));
    t.xhr=x;x.send(fd);
  });
}
async function uploadFile(file,t){
  const uid=rid(),total=file.size,cs=FH.chunk,n=Math.max(1,Math.ceil(total/cs));
  t.uid=uid;let off=0,sp=0,pb=0,pt=performance.now(),lastUi=0,res;
  for(let i=0;i<n;i++){
    const blob=file.slice(off,Math.min(off+cs,total));let tries=0;
    for(;;){
      if(t.cancelled)throw new Error('لغو شد');
      const fd=new FormData();fd.append('uid',uid);fd.append('name',file.name);fd.append('offset',off);fd.append('last',i===n-1?'1':'0');fd.append('chunk',blob,'chunk');
      try{
        res=await xhrPost(fd,loaded=>{
          const done=off+Math.min(loaded,blob.size),now=performance.now();
          if(now-lastUi<250)return;
          const dt=(now-pt)/1000;if(dt>0){const inst=Math.max(0,(done-pb)/dt);sp=sp?sp*.6+inst*.4:inst}
          pb=done;pt=now;lastUi=now;t.set(done,total,sp);
        },t);break;
      }catch(e){if(t.cancelled)throw new Error('لغو شد');if(++tries>=3)throw e;await sleep(1200*tries)}
    }
    off+=blob.size;t.set(off,total,sp);
  }
  return res;
}
let upQ=Promise.resolve();
function enqueue(file){
  const t=makeTask('⬆️',file.name);t.note('در صف انتظار…');
  t.btn.onclick=()=>{t.cancelled=true;t.btn.disabled=true;if(t.xhr)t.xhr.abort();if(t.uid)api('upload_abort',{method:'POST',data:{uid:t.uid}}).catch(()=>{})};
  upQ=upQ.then(async()=>{
    if(t.cancelled){t.finish('آپلود لغو شد.',false);return}
    try{const r=await uploadFile(file,t);t.title(r.name);t.finish('✔ آپلود کامل شد',true);toast('آپلود شد: '+r.name);loadList()}
    catch(e){t.finish(t.cancelled?'آپلود لغو شد.':'خطا: '+e.message,false)}
  });
}
const drop=$('#drop'),pick=$('#pick');
drop.onclick=()=>pick.click();
pick.onchange=()=>{[...pick.files].forEach(enqueue);pick.value=''};
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('on')}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('on')}));
drop.addEventListener('drop',e=>{[...e.dataTransfer.files].forEach(enqueue)});

/* ── لیست فایل‌ها ── */
let FILES=[],SEL=new Set();
function render(){
  const q=$('#q').value.trim().toLowerCase();
  const list=FILES.filter(f=>!q||f.name.toLowerCase().includes(q));
  $('#cnt').textContent='('+nf0.format(FILES.length)+' فایل · '+fmtBytes(FILES.reduce((s,f)=>s+f.size,0))+')';
  const box=$('#list');
  if(!list.length){box.innerHTML='<div class="empty">'+(FILES.length?'موردی پیدا نشد.':'هنوز فایلی وجود ندارد. از بالا دانلود یا آپلود کنید.')+'</div>'}
  else box.innerHTML=list.map(f=>'<div class="frow"><input type="checkbox" data-n="'+esc(f.name)+'"'+(SEL.has(f.name)?' checked':'')+'><span class="fic">'+icon(f.name)+'</span><div class="fn" dir="auto" title="'+esc(f.name)+'">'+esc(f.name)+'<small>'+df.format(new Date(f.mtime*1000))+'</small></div><span class="fsz d">'+fmtBytes(f.size)+'</span><div class="act"><a class="btn sm" href="?a=get&name='+encodeURIComponent(f.name)+'">دانلود</a><button class="btn danger sm" data-del="'+esc(f.name)+'">حذف</button></div></div>').join('');
  $('#bulk').hidden=!SEL.size;$('#bulk').textContent='حذف '+nf0.format(SEL.size)+' مورد';
  $('#all').checked=list.length>0&&list.every(f=>SEL.has(f.name));
}
async function loadList(){
  try{
    const j=await api('list');if(!j.ok)return;FILES=j.files;
    SEL=new Set([...SEL].filter(n=>FILES.some(f=>f.name===n)));render();
    if(j.total>0){const used=j.total-j.free,d=$('#disk');d.hidden=false;d.querySelector('i').style.width=Math.min(100,used/j.total*100)+'%';d.querySelector('span').textContent='فضای آزاد هاست: '+fmtBytes(j.free)+' از '+fmtBytes(j.total)}
  }catch(e){toast(e.message)}
}
async function del(names){
  if(!names.length)return;
  if(!confirm(names.length===1?'«'+names[0]+'» حذف شود؟':nf0.format(names.length)+' فایل حذف شوند؟'))return;
  const fd=new FormData();names.forEach(n=>fd.append('names[]',n));
  try{const j=await api('delete',{method:'POST',data:fd});toast(j.ok?nf0.format(j.deleted)+' فایل حذف شد':j.error);names.forEach(n=>SEL.delete(n));loadList()}catch(e){toast(e.message)}
}
$('#list').addEventListener('click',e=>{const b=e.target.closest('[data-del]');if(b)del([b.dataset.del])});
$('#list').addEventListener('change',e=>{const c=e.target.closest('[data-n]');if(!c)return;c.checked?SEL.add(c.dataset.n):SEL.delete(c.dataset.n);render()});
$('#all').onchange=e=>{const q=$('#q').value.trim().toLowerCase();FILES.filter(f=>!q||f.name.toLowerCase().includes(q)).forEach(f=>e.target.checked?SEL.add(f.name):SEL.delete(f.name));render()};
$('#bulk').onclick=()=>del([...SEL]);
$('#q').oninput=render;$('#refresh').onclick=loadList;
$('#logout').href='?logout=1&t='+encodeURIComponent(FH.csrf);
loadList();
JS;

shell('مرکز دانلود و مدیریت فایل',
    $html . '<script>window.FH=' . $boot . ';</script><script>' . $js . '</script>',
    $css);
