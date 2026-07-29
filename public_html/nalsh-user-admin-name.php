<?php
// ========================================================================
// ملف الاتصال وإعدادات البيئة (النسخة المتطورة لدعم TiDB و Env files)
// ========================================================================

if (basename($_SERVER['PHP_SELF']) === basename(__FILE__)) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(403);
    die(json_encode(['status' => 'error', 'message' => 'Access Denied']));
}

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) {
        ini_set('session.cookie_secure', 1);
    }
    session_start();
}

// ========================================================================
// 1. قارئ ملفات ENV
// ========================================================================
$env_files = [__DIR__ . '/.env', __DIR__ . '/api.env.txt'];
foreach ($env_files as $file) {
    if (file_exists($file)) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (strpos($line, '=') !== false) {
                list($name, $value) = explode('=', $line, 2);
                $name = trim($name);
                $value = trim($value, " \t\n\r\0\x0B\"'"); 
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value;
            }
        }
    }
}

function get_env_value($key, $default = '') {
    $val = getenv($key);
    if ($val === false) $val = $_ENV[$key] ?? $_SERVER[$key] ?? false;
    return $val !== false ? $val : $default;
}

// ========================================================================
// 2. تعريف الثوابت
// ========================================================================
define('DB_HOST', get_env_value('DB_HOST'));
define('DB_NAME', get_env_value('DB_NAME'));
define('DB_USER', get_env_value('DB_USER'));
define('DB_PASS', get_env_value('DB_PASS'));
define('DB_PORT', get_env_value('DB_PORT', '4000')); 

define('APP_SECRET_KEY', get_env_value('APP_SECRET_KEY', 'nalsh_fallback_secret_9988'));
define('FIREBASE_URL', get_env_value('FIREBASE_URL'));
define('FIREBASE_SECRET', get_env_value('FIREBASE_SECRET'));
define('GITHUB_OWNER', get_env_value('GITHUB_OWNER'));
define('GITHUB_REPO', get_env_value('GITHUB_REPO'));
define('GITHUB_TOKEN', get_env_value('GITHUB_TOKEN'));

global $MACRO_DEVICE_ID, $MACRO_WEBHOOK_NAME;
$MACRO_DEVICE_ID = get_env_value('MACRO_DEVICE_ID');
$MACRO_WEBHOOK_NAME = get_env_value('MACRO_WEBHOOK_NAME');

$imgbb_string = get_env_value('IMGBB_KEYS');
$imgbb_array = array_filter(array_map('trim', explode(',', $imgbb_string)));
if (empty($imgbb_array)) $imgbb_array = ['dummy_key'];
define('IMGBB_KEYS', $imgbb_array);

// ========================================================================
// 3. الاتصال بقاعدة بيانات TiDB Cloud (تشفير SSL إجباري)
// ========================================================================
global $pdo;

try {
    $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    
    // مسار شهادات الأمان الافتراضي في سيرفرات Render و Linux
    $ca_path = '/etc/ssl/certs/ca-certificates.crt';
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        // ⭐ إضافة إعدادات التشفير الإجبارية لـ TiDB ⭐
        PDO::MYSQL_ATTR_SSL_CA       => $ca_path,
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (PDOException $e) {
    error_log("TiDB Connection Error: " . $e->getMessage());
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
    die(json_encode([
        'status' => 'error', 
        'message' => 'DB Error: ' . $e->getMessage()
    ]));
}
?>
