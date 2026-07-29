<?php
error_log("DEPLOY_MARKER_v2026_07_22_SYNC_FIX action=" . ($_POST['action'] ?? ($_GET['action'] ?? (json_decode(file_get_contents('php://input'), true)['action'] ?? 'unknown'))));
// =======================================================
// ملف API الشامل (النسخة المتطورة أمنياً - الجدار الأمني 12.0)
// ⭐ تم التحديث لدعم نظام المتاجر المتعددة (Multi-Vendor) ⭐
// ⭐ التحديث الجديد: 
// 1. دعم المزامنة اللحظية للمنتجات بدون تحديث الصفحة.
// 2. إجبار المندوب والتاجر على إكمال الإعدادات الأساسية (موقع، نوع المحل).
// 3. منع تجهيز الطلبات حتى يتم قبولها من قبل مندوب.
// 4. حماية كاملة ومطلقة ضد ثغرات SQL Injection باستخدام الاستعلامات المجهزة.
// 5. تم إلغاء الاعتماد على Cloudflare D1 بالكامل وتحويل كافة العمليات إلى TiDB Cloud (PDO).
// 6. ⭐ تم إلغاء Cloudflare KV بالكامل - جميع ملفات JSON تُرفع مباشرة إلى GitHub API.
//    ✅ كل ملف يُرفع بتوقيع HMAC-SHA256 في رسالة الـ Commit للتحقق من سلامة البيانات.
//    ✅ بنية المسارات منظمة: stores/{username}/manifest.json, search_index.json, ...
//    ✅ لا اعتماد على أي خدمة وسيطة - GitHub هو المصدر الوحيد للحقيقة (Single Source of Truth).
// المسار: htdocs/public_html/api.php
// =======================================================

// 1. منع أي مخرجات عشوائية لضمان سلامة استجابة JSON
ob_start();
function measure_performance($element_name, $callable) {
    $start_memory = memory_get_usage();
    $start_time = microtime(true);
    
    $result = $callable();
    
    $end_memory = memory_get_usage();
    $end_time = microtime(true);
    
    $memory_used = round(($end_memory - $start_memory) / 1024, 2); // بالكيلوبايت
    $execution_time = round(($end_time - $start_time) * 1000, 2); // بالملي ثانية
    
    // إنشاء رسالة واضحة مع الوقت والتاريخ
    $time_now = date('Y-m-d H:i:s');
    $log_message = "[$time_now] 📊 [$element_name] -> الرام: {$memory_used} KB | وقت المعالج: {$execution_time} ms\n";
    
    // حفظ الرسالة في ملف نصي داخل نفس المجلد
    $log_file = __DIR__ . '/performance_log.txt';
    file_put_contents($log_file, $log_message, FILE_APPEND | LOCK_EX);

    return $result;
}

// تنظيف دفتر اليومية إذا كبر حجمه (أكثر من 100 كيلوبايت)
$log_file = __DIR__ . '/updates_log.txt';
if (file_exists($log_file) && filesize($log_file) > 100000) {
    file_put_contents($log_file, ""); // مسح الملف للبدء من جديد
}

// إعدادات إظهار الأخطاء (للإنتاج: أوقف العرض وسجل في ملف)
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

// =======================================================
// ⭐ الترويسات الأمنية (Security Headers & CORS & HTTPS)
// =======================================================
header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

// 1. الجدار الناري الصارم: تحديد النطاقات المسموحة فقط
$allowed_origins = [
    'https://appi.dpdns.org',
];

$request_origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// استخراج النطاق من الـ Referer إذا كان الـ Origin فارغاً
if (empty($request_origin) && isset($_SERVER['HTTP_REFERER'])) {
    $parsed = parse_url($_SERVER['HTTP_REFERER']);
    if (isset($parsed['scheme']) && isset($parsed['host'])) {
        $request_origin = $parsed['scheme'] . '://' . $parsed['host'];
    }
}

$matched_origin = '';

if (!empty($request_origin)) {
    // ⭐ إصلاح أمني: مطابقة تامة للنطاق بدلاً من مطابقة "البداية فقط"
    // (المطابقة القديمة كانت تسمح لمواقع مثل https://nalsh.vercel.app.attacker.com بالمرور)
    foreach ($allowed_origins as $origin) {
        if (strcasecmp($request_origin, $origin) === 0) {
            $matched_origin = $request_origin;
            break;
        }
    }
} else {
    // إذا كان الوصول مباشراً عبر المتصفح
    $matched_origin = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . ($_SERVER['HTTP_HOST'] ?? '');
}

if (empty($matched_origin)) {
    http_response_code(403);
    die(json_encode(['status' => 'error', 'message' => 'Access Denied: Request from an unauthorized source.']));
}

// 2. السماح للطلبات الموثوقة فقط (ديناميكياً)
header("Access-Control-Allow-Origin: $matched_origin");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CSRF-TOKEN");
header("Access-Control-Allow-Credentials: true");

// التعامل مع طلبات OPTIONS (Preflight)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

$_app_secret = getenv("APP_SECRET_KEY") ?: ($_ENV["APP_SECRET_KEY"] ?? "");
if (empty($_app_secret)) {
    http_response_code(500);
    die(json_encode(["status" => "error", "message" => "خطأ في إعدادات السيرفر: APP_SECRET_KEY مفقود من متغيرات البيئة."]));
}
if (!defined("APP_SECRET_KEY")) define("APP_SECRET_KEY", $_app_secret);

// ⭐ إعدادات MacroDroid (بوابة إرسال SMS عبر جهاز أندرويد)
// ⚠️ كانت هذه المتغيرات "global" بدون أي تعريف فعلي في أي مكان بالملف،
// لذلك كان شرط !empty() يفشل دائماً ولا يُرسل أي طلب فعلياً لـ MacroDroid.
$MACRO_DEVICE_ID    = getenv('MACRO_DEVICE_ID') ?: ($_ENV['MACRO_DEVICE_ID'] ?? '');
$MACRO_WEBHOOK_NAME = getenv('MACRO_WEBHOOK_NAME') ?: ($_ENV['MACRO_WEBHOOK_NAME'] ?? '');

// =======================================================
// 2. إجبار استخدام HTTPS (تفعيل التشفير)
// =======================================================
$protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? '';

// تم إضافة rf.gd للسماح للاستضافة المجانية بالعمل مؤقتاً بدون HTTPS
if ($protocol !== 'https' && strpos($host, 'localhost') === false && strpos($host, '127.0.0.1') === false && strpos($host, 'rf.gd') === false) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'يتطلب هذا الـ API اتصالاً آمناً (HTTPS).']);
    exit();
}

header("X-Frame-Options: DENY"); 
header("X-XSS-Protection: 1; mode=block"); 
header("X-Content-Type-Options: nosniff"); 
header("Strict-Transport-Security: max-age=31536000; includeSubDomains"); 
header("Content-Security-Policy: default-src 'none';"); 
header("Referrer-Policy: strict-origin-when-cross-origin");

// =======================================================
// 2. الدوال المساعدة والإعدادات
// =======================================================

define('CACHE_DIR', __DIR__ . '/../cache/');
define('CACHE_FILE', CACHE_DIR . 'products.json');
define('CACHE_TTL', 300); 

define('OTP_COOLDOWN_SECONDS', 120); 

define('DELIVERY_AGENT_MAX_ORDERS', 5);
define('ORDER_ACCEPT_TIMEOUT_SECONDS', 1800); 

define('ALLOWED_DELIVERY_CENTER_LAT', 15.3694); 
define('ALLOWED_DELIVERY_CENTER_LNG', 44.1910);
define('MAX_ALLOWED_DELIVERY_RADIUS_KM', 30); 

define('MIN_ALLOWED_LAT', 12.0000);
define('MAX_ALLOWED_LAT', 19.0000);
define('MIN_ALLOWED_LNG', 41.0000);
define('MAX_ALLOWED_LNG', 54.0000);

define('MAX_PRICE_INCREASE_PERCENTAGE', 20); // 20%

// دالة مساعدة لجلب اسم المستخدم بأمان تام
function get_username_by_id($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetchColumn() ?: '';
}

// دالة مساعدة لجلب اسم المتجر بأمان تام
function get_store_name_by_id($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT store_name FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetchColumn() ?: '';
}
// دالة فحص اشتراك التاجر (النسخة الآمنة والمضادة للانهيار)
// =======================================================
// 🚀 نظام المزامنة الفائقة مع Firebase (محمي بمتغيرات البيئة)
// =======================================================

$fb_url = getenv('FIREBASE_DB_URL') ?: $_ENV['FIREBASE_DB_URL'] ?: 'https://shiban-a2757-default-rtdb.europe-west1.firebasedatabase.app/';
if (substr($fb_url, -1) !== '/') {
    $fb_url .= '/';
}
$fb_secret = getenv('FIREBASE_DB_SECRET') ?: $_ENV['FIREBASE_DB_SECRET'] ?: '';

// =======================================================
// 🚀 دالة المزامنة الشاملة مع Firebase (محمية ومطورة)
// =======================================================
function sync_to_firebase($merchant_username, $node, $item_id, $data, $method = 'PUT') {
    $fb_url = rtrim(getenv('FIREBASE_DB_URL') ?: $_ENV['FIREBASE_DB_URL'] ?: 'https://shiban-a2757-default-rtdb.europe-west1.firebasedatabase.app', '/');
    $fb_secret = getenv('FIREBASE_DB_SECRET') ?: $_ENV['FIREBASE_DB_SECRET'] ?: '';

    if (empty($fb_secret)) {
        error_log("Firebase Error: Secret is empty");
        return;
    }

    $safe_username = preg_replace('/[^a-zA-Z0-9_]/', '_', $merchant_username);
    $path = $item_id ? "/$node/$item_id.json" : "/$node.json";
    $url = $fb_url . "/stores/" . $safe_username . $path . "?auth=" . $fb_secret;

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    
    if ($method !== 'DELETE') {
        $json_data = json_encode($data, JSON_UNESCAPED_UNICODE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
    }
    
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code >= 400) {
        error_log("FIREBASE WRITE FAILED: URL=$url | HTTP_CODE=$http_code | RESPONSE=$response");
    }
}
// دالة لتسجيل علم إعادة بناء الكاش بصمت لمنع توقف النظام
function flag_cache_for_rebuild($merchant_id = null) {
    global $pdo;
    if (!$pdo) return;
    try {
        $stmt = $pdo->prepare("INSERT INTO settings (setting_key, setting_value) VALUES ('cache_rebuild_pending', '1') ON DUPLICATE KEY UPDATE setting_value = '1'");
        $stmt->execute();
    } catch (Exception $e) {
        // التجاوز بصمت لضمان عدم تأثر تجربة المستخدم
    }
}

function generate_signed_token($payload, $expiry_minutes = 5) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload['exp'] = time() + ($expiry_minutes * 60);
    $base64UrlHeader = str_replace(['+', '/', '='],['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='],['-', '_', ''], base64_encode(json_encode($payload)));
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, APP_SECRET_KEY, true);
    $base64UrlSignature = str_replace(['+', '/', '='],['-', '_', ''], base64_encode($signature));
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// دالة أساسية للتعامل مع Firebase عبر REST API داخل PHP
function fb_request($path, $method = 'GET', $data = null) {
    $fb_url = getenv('FIREBASE_DB_URL') ?: $_ENV['FIREBASE_DB_URL'] ?: 'https://shiban-a2757-default-rtdb.europe-west1.firebasedatabase.app/';
    if (substr($fb_url, -1) !== '/') $fb_url .= '/';
    $fb_secret = getenv('FIREBASE_DB_SECRET') ?: $_ENV['FIREBASE_DB_SECRET'] ?: '';
    
    $url = $fb_url . ltrim($path, '/') . "?auth=" . $fb_secret;
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
    }
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}

// =======================================================
// 🚀 نظام المزامنة الآمنة والمباشرة مع GitHub API
// ✅ بديل Cloudflare KV - جميع العمليات تمر عبر GitHub فقط
// ✅ كل commit يحمل توقيع HMAC-SHA256 للتحقق من سلامة البيانات
// ✅ GET يجلب الملف من raw.githubusercontent.com (سريع + مجاني)
// ✅ PUT/DELETE يستخدم GitHub Contents API (مصادقة Bearer Token)
// =======================================================
function gh_get_credentials() {
    $token = getenv('GITHUB_TOKEN') ?: ($_ENV['GITHUB_TOKEN'] ?? '');
    $owner = getenv('GITHUB_REPO_OWNER') ?: ($_ENV['GITHUB_REPO_OWNER'] ?? '');
    $repo  = getenv('GITHUB_REPO_NAME')  ?: ($_ENV['GITHUB_REPO_NAME']  ?? '');
    return [$token, $owner, $repo];
}

/**
 * kv_request — واجهة متوافقة مع الكود القديم لكنها تعمل على GitHub مباشرة.
 * 
 * GET  → يجلب الملف من raw.githubusercontent.com (أسرع + لا تحتاج token للقراءة)
 * PUT  → يرفع/يحدّث الملف عبر GitHub Contents API مع توقيع HMAC في رسالة الـ Commit
 * DELETE → يحذف الملف عبر GitHub Contents API
 *
 * @param string $path   المسار النسبي مثل: stores/username/products_page_1
 * @param string $method GET | PUT | DELETE
 * @param mixed  $data   البيانات للرفع (مصفوفة أو null)
 * @return array|null    البيانات عند GET، أو null عند PUT/DELETE
 */
function kv_request($path, $method = 'GET', $data = null) {
    [$gh_token, $gh_owner, $gh_repo] = gh_get_credentials();

    if (empty($gh_owner) || empty($gh_repo)) {
        error_log("GitHub KV: GITHUB_REPO_OWNER أو GITHUB_REPO_NAME مفقود.");
        return null;
    }

    // ✅ تنظيف المسار: إزالة .json إذا أُضيفت عن طريق الخطأ
    $clean_path = ltrim(str_replace('.json', '', $path), '/') . '.json';
    $api_url    = "https://api.github.com/repos/{$gh_owner}/{$gh_repo}/contents/{$clean_path}";

    $base_headers = [
        "Authorization: Bearer {$gh_token}",
        "Accept: application/vnd.github+json",
        "User-Agent: Nalsh-Ecom-System/2.0",
        "X-GitHub-Api-Version: 2022-11-28",
        "Content-Type: application/json",
    ];

    // ──────────────────────────────────────────────
    // GET: جلب الملف من raw.githubusercontent.com (أسرع وبدون token)
    // ──────────────────────────────────────────────
    if ($method === 'GET') {
        $raw_url = "https://raw.githubusercontent.com/{$gh_owner}/{$gh_repo}/main/{$clean_path}";
        $ch = curl_init($raw_url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HTTPHEADER     => ["User-Agent: Nalsh-Ecom-System/2.0"],
        ]);
        $response  = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code === 200 && $response) {
            return json_decode($response, true);
        }
        return null;
    }

    // ──────────────────────────────────────────────
    // PUT / DELETE: يحتاج GitHub Token
    // ──────────────────────────────────────────────
    if (empty($gh_token)) {
        error_log("GitHub KV: GITHUB_TOKEN مفقود - تعذّر تنفيذ {$method} على {$clean_path}");
        return null;
    }

    // 1. جلب SHA الملف الحالي (مطلوب لأي تحديث أو حذف)
    $ch = curl_init($api_url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $base_headers,
        CURLOPT_TIMEOUT        => 4,
    ]);
    $info_resp = curl_exec($ch);
    $info_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $sha = null;
    if ($info_code === 200) {
        $file_meta = json_decode($info_resp, true);
        $sha = $file_meta['sha'] ?? null;
    }

    // DELETE: نحتاج SHA لأي عملية حذف
    if ($method === 'DELETE') {
        if (!$sha) return null; // الملف غير موجود أصلاً
        $payload = [
            "message" => "🗑️ Auto-delete: {$clean_path}",
            "sha"     => $sha,
        ];
        $ch2 = curl_init($api_url);
        curl_setopt_array($ch2, [
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_POSTFIELDS    => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER    => $base_headers,
            CURLOPT_TIMEOUT       => 8,
        ]);
        curl_exec($ch2);
        curl_close($ch2);
        return null;
    }

    // PUT: رفع/تحديث الملف مع توقيع HMAC لضمان سلامة البيانات
    $json_content  = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    $secret_key    = getenv('APP_SECRET_KEY') ?: ($_ENV['APP_SECRET_KEY'] ?? 'default_key');
    $data_signature = hash_hmac('sha256', $json_content, $secret_key);
    $timestamp      = date('Y-m-d H:i:s T');

    $payload = [
        "message" => "⚡ Auto-sync [{$clean_path}] | sig:{$data_signature} | {$timestamp}",
        "content" => base64_encode($json_content),
    ];
    if ($sha) $payload["sha"] = $sha;

    $ch2 = curl_init($api_url);
    curl_setopt_array($ch2, [
        CURLOPT_CUSTOMREQUEST  => 'PUT',
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $base_headers,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $put_resp = curl_exec($ch2);
    $put_code = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
    curl_close($ch2);

    if ($put_code >= 400) {
        error_log("GitHub KV PUT فشل [{$put_code}] على {$clean_path}: {$put_resp}");
    }

    return null; // PUT لا يُعيد بيانات
}

// =======================================================
// 🚀 دالة مساعدة داخلية: تنفيذ طلب HTTP إلى GitHub Git Database API
// (تُستخدم فقط داخل gh_upload_multiple_files لتفادي تكرار كود cURL)
// =======================================================
function _gh_git_api_request($url, $method, $headers, $payload = null, $timeout = 15) {
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
    ];
    if ($payload !== null) {
        $opts[CURLOPT_POSTFIELDS] = json_encode($payload);
    }
    curl_setopt_array($ch, $opts);
    $response  = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err  = curl_error($ch);
    curl_close($ch);

    return [
        'code'  => $http_code,
        'body'  => $response ? json_decode($response, true) : null,
        'raw'   => $response,
        'error' => $curl_err,
    ];
}

/**
 * =======================================================
 * 🚀 gh_upload_multiple_files — رفع مجمّع (Batch Upload) لعدة ملفات
 * في Commit واحد فقط باستخدام GitHub Git Database API (Trees & Commits)
 * =======================================================
 * ✅ الهدف: بدلاً من عمل N طلب PUT متتالي عبر kv_request (Contents API)،
 *    نقوم بعملية واحدة تشمل: قراءة آخر Commit -> إنشاء Tree جديد يحوي
 *    كل الملفات -> إنشاء Commit واحد -> تحديث مرجع الفرع (ref) ليشير إليه.
 *    هذا يقلل عدد طلبات HTTP من N إلى ~4 طلبات ثابتة بغض النظر عن عدد
 *    الملفات، ويقلل أيضاً عدد الـ commits المسجّلة في المستودع (يمنع مشكلة Abuse من GitHub).
 *
 * @param string $merchant_username    اسم التاجر (يُستخدم لبناء المسار stores/{username}/{file}.json)
 * @param array  $files_array          مصفوفة associative: ['filename' => $data_array_or_string, ...]
 *                                     مثال: ['search_index' => [...], 'categories' => [...], 'products_page_1' => [...]]
 * @return bool  true عند نجاح كامل العملية، false عند أي فشل
 */
function gh_upload_multiple_files($merchant_username, $files_array) {
    if (empty($files_array) || !is_array($files_array)) {
        return false;
    }

    [$gh_token, $gh_owner, $gh_repo] = gh_get_credentials();

    if (empty($gh_token) || empty($gh_owner) || empty($gh_repo)) {
        error_log("GitHub Batch Upload: بيانات الاعتماد (Token/Owner/Repo) مفقودة.");
        return false;
    }

    $api_base = "https://api.github.com/repos/{$gh_owner}/{$gh_repo}";
    $branch   = "main";

    $headers = [
        "Authorization: Bearer {$gh_token}",
        "Accept: application/vnd.github+json",
        "User-Agent: Nalsh-Ecom-System/2.0",
        "X-GitHub-Api-Version: 2022-11-28",
        "Content-Type: application/json",
    ];

    try {
        // ──────────────────────────────────────────────
        // أ) جلب الـ SHA الخاص بآخر Commit في فرع main
        // ──────────────────────────────────────────────
        $ref_res = _gh_git_api_request(
            "{$api_base}/git/ref/heads/{$branch}",
            'GET',
            $headers
        );

        if ($ref_res['code'] !== 200 || empty($ref_res['body']['object']['sha'])) {
            error_log("GitHub Batch Upload: فشل جلب SHA لآخر Commit [{$ref_res['code']}]: " . $ref_res['raw']);
            return false;
        }
        $latest_commit_sha = $ref_res['body']['object']['sha'];

        // نحتاج SHA الخاص بالـ Tree الأساسي (base tree) المرتبط بآخر Commit
        // لبناء الشجرة الجديدة فوقه (بدون الحاجة لإعادة رفع كل ملفات المستودع كاملة)
        $commit_res = _gh_git_api_request(
            "{$api_base}/git/commits/{$latest_commit_sha}",
            'GET',
            $headers
        );

        if ($commit_res['code'] !== 200 || empty($commit_res['body']['tree']['sha'])) {
            error_log("GitHub Batch Upload: فشل جلب Base Tree [{$commit_res['code']}]: " . $commit_res['raw']);
            return false;
        }
        $base_tree_sha = $commit_res['body']['tree']['sha'];

        // ──────────────────────────────────────────────
        // ب) إنشاء Git Tree جديد يحتوي على كل الملفات الممرّرة في $files_array
        // المسار لكل ملف: stores/{merchant_username}/{filename}.json
        // ──────────────────────────────────────────────
        $tree_items = [];

        foreach ($files_array as $filename => $data) {
            // تنظيف اسم الملف من امتداد .json إن وُجد لتوحيد الشكل، ثم إضافته يدوياً
            $clean_filename = str_replace('.json', '', $filename);
            $file_path = "stores/{$merchant_username}/{$clean_filename}.json";

            // دعم تمرير بيانات جاهزة كسلسلة نصية أو كمصفوفة (يتم تحويلها JSON تلقائياً)
            $json_content = is_string($data)
                ? $data
                : json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

            $tree_items[] = [
                "path"    => $file_path,
                "mode"    => "100644", // ملف عادي (blob)
                "type"    => "blob",
                "content" => $json_content,
            ];
        }

        $tree_res = _gh_git_api_request(
            "{$api_base}/git/trees",
            'POST',
            $headers,
            [
                "base_tree" => $base_tree_sha,
                "tree"      => $tree_items,
            ]
        );

        if ($tree_res['code'] !== 201 || empty($tree_res['body']['sha'])) {
            error_log("GitHub Batch Upload: فشل إنشاء Tree [{$tree_res['code']}]: " . $tree_res['raw']);
            return false;
        }
        $new_tree_sha = $tree_res['body']['sha'];

        // ──────────────────────────────────────────────
        // ج) إنشاء Commit واحد جديد يشمل هذه الشجرة الجديدة كاملة
        // ──────────────────────────────────────────────
        $timestamp  = date('Y-m-d H:i:s T');
        $file_count = count($tree_items);
        $commit_message = "⚡ Batch-sync [{$merchant_username}] | {$file_count} files | {$timestamp}";

        $new_commit_res = _gh_git_api_request(
            "{$api_base}/git/commits",
            'POST',
            $headers,
            [
                "message" => $commit_message,
                "tree"    => $new_tree_sha,
                "parents" => [$latest_commit_sha],
            ]
        );

        if ($new_commit_res['code'] !== 201 || empty($new_commit_res['body']['sha'])) {
            error_log("GitHub Batch Upload: فشل إنشاء Commit [{$new_commit_res['code']}]: " . $new_commit_res['raw']);
            return false;
        }
        $new_commit_sha = $new_commit_res['body']['sha'];

        // ──────────────────────────────────────────────
        // د) تحديث مرجع الفرع (Branch Reference) ليشير إلى الـ Commit الجديد
        // ──────────────────────────────────────────────
        $update_ref_res = _gh_git_api_request(
            "{$api_base}/git/refs/heads/{$branch}",
            'PATCH',
            $headers,
            [
                "sha"   => $new_commit_sha,
                "force" => false, // نرفض الـ force update لتفادي فقدان أي commits أخرى حدثت بالتوازي
            ]
        );

        if ($update_ref_res['code'] !== 200) {
            error_log("GitHub Batch Upload: فشل تحديث مرجع الفرع [{$update_ref_res['code']}]: " . $update_ref_res['raw']);
            return false;
        }

        return true;

    } catch (Exception $e) {
        error_log("GitHub Batch Upload: استثناء غير متوقع: " . $e->getMessage());
        return false;
    }
}

// =======================================================
// 🚀 sync_to_github — wrapper للتوافق العكسي مع الكود القديم
// ✅ يُحوِّل كل استدعاء قديم إلى kv_request الموحّدة (GitHub مباشرة)
// =======================================================
function sync_to_github($path, $data, $method = 'PUT', $commit_message = "Auto-update from system") {
    // kv_request تتولى SHA + Base64 + HMAC signature + رفع GitHub داخلياً
    $clean_path = str_replace('.json', '', $path);
    kv_request($clean_path, $method, $method !== 'DELETE' ? $data : null);
}
// =======================================================
// ⭐ نظام كود التحقق (OTP) الآمن
// - random_int بدل rand (مولّد عشوائي آمن تشفيرياً)
// - الكود لا يُخزَّن أبداً كنص صريح، فقط hash
// - المقارنة بـ hash_equals لمنع ثغرات التوقيت (timing attacks)
// =======================================================
function generate_secure_otp() {
    return (string) random_int(100000, 999999);
}
function hash_otp($otp) {
    return hash_hmac('sha256', (string) $otp, APP_SECRET_KEY);
}
function verify_otp_hash($otp_input, $stored_hash) {
    if (empty($stored_hash) || empty($otp_input)) return false;
    return hash_equals((string) $stored_hash, hash_otp($otp_input));
}

// إرسال SMS عبر MacroDroid بأمان:
// - بيانات الرسالة تُرسل عبر POST body بدل query string (كانت الرسالة والكود يظهران كاملين
//   داخل الـ URL نفسه، وهذا يعرّضهما لأي سجل/لوق يحتفظ بروابط GET الكاملة).
// - device_id / webhook_name تُقرأ من متغيرات البيئة فقط، ولا تُطبع أو تُرسل للعميل أبداً.
function send_via_macrodroid($phone, $message) {
    global $MACRO_DEVICE_ID, $MACRO_WEBHOOK_NAME;
    if (empty($MACRO_DEVICE_ID) || empty($MACRO_WEBHOOK_NAME)) {
        error_log("MacroDroid: لم يتم إرسال SMS - متغيرات البيئة MACRO_DEVICE_ID/MACRO_WEBHOOK_NAME غير مُعرَّفة.");
        return false;
    }
    $url = "https://trigger.macrodroid.com/" . rawurlencode($MACRO_DEVICE_ID) . "/" . rawurlencode($MACRO_WEBHOOK_NAME);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['phone' => $phone, 'msg' => $message]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 6);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $result = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($httpcode != 200 || $result === false) {
        error_log("MacroDroid: فشل إرسال SMS (http=$httpcode, err=$err)");
        return false;
    }
    return true;
}

function simple_php_hash($str) {
    $hash = 0;
    $len = strlen($str);
    for ($i = 0; $i < $len; $i++) {
        $char = ord($str[$i]);
        $hash = (($hash << 5) - $hash) + $char;
        $hash = $hash & 0xFFFFFFFF;
        if ($hash > 0x7FFFFFFF) {
            $hash -= 0x100000000;
        }
    }
    return $hash;
}

function get_fcm_access_token() {
    $env_json = getenv('FIREBASE_CREDENTIALS_JSON') ?: $_ENV['FIREBASE_CREDENTIALS_JSON'] ?? '';
    
    if (!empty($env_json)) {
        $key_data = json_decode($env_json, true);
    } else {
        $key_path = __DIR__ . '/firebase-credentials.json';
        if (!file_exists($key_path)) return null;
        $key_data = json_decode(file_get_contents($key_path), true);
    }

    $header = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
    $now = time();
    $payload = json_encode([
        'iss' => $key_data['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud' => 'https://oauth2.googleapis.com/token',
        'exp' => $now + 3600,
        'iat' => $now
    ]);

    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    openssl_sign($base64UrlHeader . "." . $base64UrlPayload, $signature, $key_data['private_key'], OPENSSL_ALGO_SHA256);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $jwt
    ]));
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true)['access_token'] ?? null;
}
// =======================================================
// 🚀 نظام Cloudflare CDN Cache Purge
// وظيفة الدالة: مسح الكاش لملفات تاجر محدد فقط لضمان التحديث اللحظي 
// =======================================================
function purge_merchant_cloudflare_cache($merchant_username, $pages_count = 1) {
    $zone_id = getenv('CLOUDFLARE_ZONE_ID') ?: ($_ENV['CLOUDFLARE_ZONE_ID'] ?? '');
    $api_token = getenv('CLOUDFLARE_API_TOKEN') ?: ($_ENV['CLOUDFLARE_API_TOKEN'] ?? '');
    $domain = rtrim(getenv('CLOUDFLARE_DOMAIN') ?: ($_ENV['CLOUDFLARE_DOMAIN'] ?? 'https://nalsh.vercel.app'), '/');

    if (empty($zone_id) || empty($api_token)) {
        error_log("Cloudflare Purge Error: Credentials missing.");
        return false;
    }

    // تجهيز مسارات الملفات الخاصة بهذا التاجر فقط (يجب أن تطابق الروابط التي يطلبها الفرونت إند)
    $base_path = "$domain/stores/$merchant_username";
    
    // الملفات الأساسية التي تتحدث دائماً
    $files_to_purge = [
        "$base_path/manifest.json",
        "$base_path/search_index.json",
        "$base_path/categories.json",
        "$base_path/info.json"
    ];

    // إضافة صفحات المنتجات (لأن التاجر قد يكون لديه عدة صفحات)
    for ($i = 1; $i <= $pages_count; $i++) {
        $files_to_purge[] = "$base_path/products_page_{$i}.json";
    }

    // إعداد طلب Cloudflare API (مسح بالروابط - مدعوم في الخطة المجانية)
    // بحد أقصى 30 رابط في الطلب الواحد حسب قيود كلاودفلير
    $chunks = array_chunk($files_to_purge, 30);
    
    $success = true;
    foreach ($chunks as $chunk) {
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones/{$zone_id}/purge_cache");
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => "POST",
            CURLOPT_POSTFIELDS     => json_encode(["files" => $chunk]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 3, // Timeout قصير حتى لا يعلق السيرفر
            CURLOPT_HTTPHEADER     => [
                "Authorization: Bearer {$api_token}",
                "Content-Type: application/json"
            ]
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200) {
            error_log("Cloudflare Purge Failed for {$merchant_username}: HTTP {$http_code} - {$response}");
            $success = false;
        }
    }

    return $success;
}
function send_silent_push_to_merchant($merchant_fcm_token, $order_id) {
    if (empty($merchant_fcm_token)) return;
    
    $env_json = getenv('FIREBASE_CREDENTIALS_JSON') ?: $_ENV['FIREBASE_CREDENTIALS_JSON'] ?? '';
    if (!empty($env_json)) {
        $project_id = json_decode($env_json, true)['project_id'];
    } else {
        $key_path = __DIR__ . '/firebase-credentials.json';
        if (!file_exists($key_path)) return;
        $project_id = json_decode(file_get_contents($key_path), true)['project_id'];
    }
    
    $access_token = get_fcm_access_token();
    if (!$access_token) return;

    $payload = [
        'message' => [
            'token' => $merchant_fcm_token,
            'notification' => [
                'title' => 'طلب جديد واصل الآن! 🛍️',
                'body' => 'لديك طلب جديد بانتظار الموافقة.'
            ],
            'data' => [
                'action' => 'new_order',
                'order_id' => (string)$order_id
            ],
            'webpush' => [
                'notification' => [
                    'icon' => '/images/icons/icon-192x192.png',
                    'vibrate' => [200, 100, 200, 100, 200]
                ],
                'fcm_options' => [
                    'link' => '/merchant-dashboard.html'
                ]
            ]
        ]
    ];

    $ch = curl_init('https://fcm.googleapis.com/v1/projects/' . $project_id . '/messages:send');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $access_token,
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2); 
    $fcm_result = curl_exec($ch);
    $fcm_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if (curl_errno($ch)) {
        error_log("FCM Push Error: " . curl_error($ch));
    } elseif ($fcm_http_code >= 400) {
        error_log("FCM Push HTTP Error: $fcm_http_code | Response: $fcm_result");
    }
    curl_close($ch);
}

function verify_signed_token($token, $expected_purpose) {
    if (empty($token)) throw new Exception("التذكرة مفقودة. تم رفض العملية لتأمين النظام.");
    $parts = explode('.', $token);
    if (count($parts) !== 3) throw new Exception("تذكرة غير صالحة.");
    
    list($header, $payload, $signature) = $parts;
    $valid_signature = hash_hmac('sha256', $header . "." . $payload, APP_SECRET_KEY, true);
    $base64UrlValidSignature = str_replace(['+', '/', '='],['-', '_', ''], base64_encode($valid_signature));
    
    if (!hash_equals($base64UrlValidSignature, $signature)) {
        throw new Exception("تذكرة مزورة أو تم التلاعب بها.");
    }
    
    $decoded_payload = json_decode(base64_decode(str_replace(['-', '_'],['+', '/'], $payload)), true);
    if (!$decoded_payload || !isset($decoded_payload['exp']) || time() > $decoded_payload['exp']) {
        throw new Exception("انتهت صلاحية العملية (Timeout). يرجى البدء من جديد.");
    }
    
    if (!isset($decoded_payload['purpose']) || $decoded_payload['purpose'] !== $expected_purpose) {
        throw new Exception("محاولة تجاوز حالة غير مصرح بها. (State Machine Error)");
    }
    
    return $decoded_payload;
}

function generate_uuid() {
    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
        mt_rand( 0, 0xffff ),
        mt_rand( 0, 0x0fff ) | 0x4000,
        mt_rand( 0, 0x3fff ) | 0x8000,
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
}

function send_response($status, $data = [], $http_code = 200) {
    if (ob_get_length()) ob_clean();
    http_response_code($http_code);
    $data = is_array($data) ? $data : []; 
    echo json_encode(array_merge(['status' => $status], $data), JSON_UNESCAPED_UNICODE);
    exit();
}

/**
 * =======================================================
 * 🚀 send_response_and_continue_in_background — حيلة FastCGI معمّمة
 * =======================================================
 * ترسل استجابة JSON نهائية للعميل وتُنهي اتصال الـ HTTP فوراً (أو تُفرغ
 * المخازن قدر الإمكان في حال عدم توفر fastcgi_finish_request)، بحيث لا
 * ينتظر المتصفح أي عمليات لاحقة (مثل رفع الملفات إلى GitHub).
 *
 * ⚠️ هامة: هذه الدالة لا تستدعي exit() ولا تُنهي تنفيذ السكربت —
 * فهي تسمح للكود الذي يليها (مثل trigger_cache_rebuild) بالاستمرار
 * في العمل "في الخلفية" بعد أن يكون العميل قد استلم رده فعلياً.
 * يجب على المستدعي وضع exit() بعد آخر عملية خلفية إن أراد إيقاف التنفيذ.
 *
 * @param string $status    'success' أو 'error'
 * @param array  $data      بيانات إضافية تُدمج مع status في الاستجابة
 * @param int    $http_code كود حالة HTTP (افتراضياً 200)
 */
function send_response_and_continue_in_background($status, $data = [], $http_code = 200) {
    $data = is_array($data) ? $data : [];
    $response_json = json_encode(array_merge(['status' => $status], $data), JSON_UNESCAPED_UNICODE);

    // أ) تنظيف أي مخرجات سابقة في المخزن المؤقت (كما تفعل send_response)
    if (ob_get_length()) ob_clean();
    http_response_code($http_code);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($response_json));
    // إخبار الخادم/المتصفح أن الاتصال سيُغلق فوراً بعد هذه الاستجابة
    header('Connection: close');
    echo $response_json;

    // ب) إنهاء الاتصال الفعلي مع العميل بأسرع طريقة متاحة على السيرفر
    if (function_exists('fastcgi_finish_request')) {
        // ✅ الطريقة المثلى: متاحة عند تشغيل PHP عبر PHP-FPM (FastCGI)
        fastcgi_finish_request();
    } else {
        // ✅ بديل عام لأي بيئة أخرى (Apache mod_php أو غيرها):
        // نُفرغ كل مخازن الإخراج فوراً لإرسال البيانات ثم نغلق الجلسة
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
        flush();
    }
    // من هنا فصاعداً، اتصال الـ HTTP مع العميل قد انتهى فعلياً (أو أُفرغ قدر الإمكان)
    // وأي كود يُنفَّذ بعد استدعاء هذه الدالة يعمل في الخلفية بهدوء دون أن ينتظره العميل.
}

function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    // ملاحظة: لا نستخدم htmlspecialchars هنا لأن PDO يحمي من SQL Injection تلقائياً،
    // وتطبيق htmlspecialchars على البيانات المخزنة يُشوّه النصوص العربية والرموز.
    // يجب تطبيق htmlspecialchars عند عرض البيانات في HTML فقط.
    return trim($data ?? '');
}

/**
 * =======================================================
 * ⚡ sync_user_to_worker — مزامنة فورية لبيانات المستخدم إلى D1 (Cloudflare Worker)
 * =======================================================
 * تُستدعى بعد كل تسجيل دخول ناجح لضمان أن الداشبورد (الذي أصبح يعتمد على
 * الـ Worker/D1 لكل شيء عدا تسجيل الدخول) يرى دائماً أحدث بيانات المستخدم.
 * لا تُفشل تسجيل الدخول أبداً حتى لو تعذّر الاتصال بالـ Worker (best-effort،
 * بمهلة قصيرة جداً، وتُستدعى دائماً بعد إرسال الرد للمستخدم).
 */
function sync_user_to_worker($pdo, $user_id) {
    try {
        $worker_url = getenv('WORKER_API_URL') ?: ($_ENV['WORKER_API_URL'] ?? '');
        $internal_key = getenv('INTERNAL_SYNC_KEY') ?: ($_ENV['INTERNAL_SYNC_KEY'] ?? '');
        if (empty($worker_url) || empty($internal_key)) {
            error_log("sync_user_to_worker SKIPPED (user_id={$user_id}): url_set=" . (empty($worker_url) ? 'NO' : 'YES') . ", key_set=" . (empty($internal_key) ? 'NO' : 'YES'));
            return;
        }

        $stmt = $pdo->prepare(
            "SELECT id, username, role, store_name, phone, store_type, settings, fcm_token,
                    UNIX_TIMESTAMP(created_at) as created_at
             FROM users WHERE id = ?"
        );
        $stmt->execute([$user_id]);
        $u = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$u) return;

        $payload = [
            'action'     => 'sync_user',
            'id'         => (string)$u['id'],
            'username'   => $u['username'],
            'role'       => $u['role'],
            'store_name' => $u['store_name'],
            'phone'      => $u['phone'],
            'store_type' => $u['store_type'],
            'settings'   => $u['settings'], // نص JSON جاهز أصلاً من عمود settings
            'fcm_token'  => $u['fcm_token'],
            'created_at' => $u['created_at'] ? ((int)$u['created_at'] * 1000) : null,
        ];

        $ch = curl_init(rtrim($worker_url, '/'));
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Internal-Key: ' . $internal_key],
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        ]);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // ⭐ تسجيل صريح للنتيجة — بدون هذا كنا عمياً عن أي فشل حقيقي (401/500/شبكة)
        if ($err) {
            error_log("sync_user_to_worker CURL ERROR (user_id={$user_id}): {$err}");
        } elseif ($http_code < 200 || $http_code >= 300) {
            error_log("sync_user_to_worker FAILED (user_id={$user_id}, http_code={$http_code}): " . substr($resp, 0, 500));
        }
    } catch (Throwable $e) {
        error_log('sync_user_to_worker error: ' . $e->getMessage());
    }
}
/**
 * =======================================================
 * ⭐ إضافة (2026-07-21): sync_customer_to_worker — مزامنة فورية لبيانات
 * العميل إلى D1 (Cloudflare Worker)، بنفس نمط sync_user_to_worker تماماً.
 * تُستدعى بعد نجاح تسجيل دخول العميل (auth_verify_otp) حتى يقدر الـ Worker
 * يخدم check_customer_session و create_order و get_user_orders مباشرة
 * دون المرور على api.php. best-effort ولا تُفشل تسجيل الدخول أبداً.
 * =======================================================
 */
function sync_customer_to_worker($pdo, $customer_id) {
    try {
        $worker_url = getenv('WORKER_API_URL') ?: ($_ENV['WORKER_API_URL'] ?? '');
        $internal_key = getenv('INTERNAL_SYNC_KEY') ?: ($_ENV['INTERNAL_SYNC_KEY'] ?? '');
        if (empty($worker_url) || empty($internal_key)) {
            error_log("sync_customer_to_worker SKIPPED (customer_id={$customer_id}): url_set=" . (empty($worker_url) ? 'NO' : 'YES') . ", key_set=" . (empty($internal_key) ? 'NO' : 'YES'));
            return;
        }

        $stmt = $pdo->prepare(
            "SELECT id, full_name, phone, address, is_active FROM customers WHERE id = ?"
        );
        $stmt->execute([$customer_id]);
        $c = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$c) return;

        $payload = [
            'action'    => 'sync_customer',
            'id'        => (string)$c['id'],
            'full_name' => $c['full_name'],
            'phone'     => $c['phone'],
            'address'   => $c['address'],
            'is_active' => isset($c['is_active']) ? (int)$c['is_active'] : 1,
        ];

        $ch = curl_init(rtrim($worker_url, '/'));
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Internal-Key: ' . $internal_key],
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        ]);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($err) {
            error_log("sync_customer_to_worker CURL ERROR (customer_id={$customer_id}): {$err}");
        } elseif ($http_code < 200 || $http_code >= 300) {
            error_log("sync_customer_to_worker FAILED (customer_id={$customer_id}, http_code={$http_code}): " . substr($resp, 0, 500));
        }
    } catch (Throwable $e) {
        error_log('sync_customer_to_worker error: ' . $e->getMessage());
    }
}

/**
 * ⭐ إضافة: مزامنة عكسية لحالة التذكرة إلى D1 (الـ Worker) بعد أي تغيير نهائي على
 * حالتها في MySQL (موافقة/رفض/تحديث حالة/إلغاء/تسليم) عبر أكشنات api.php القديمة.
 * بدون هذا، تبقى نسخة D1 من التذكرة بحالتها القديمة (pending) للأبد، فيعتبرها
 * create_order بالـ Worker "تذكرة قائمة" قابلة للدمج مع طلب جديد لاحق لنفس
 * العميل/التاجر، ويُعيد إحياء طلبات مُلغاة/مكتملة بالخطأ في MySQL.
 */
function sync_ticket_status_to_worker($ticket_id, $status) {
    try {
        $worker_url = getenv('WORKER_API_URL') ?: ($_ENV['WORKER_API_URL'] ?? '');
        $internal_key = getenv('INTERNAL_SYNC_KEY') ?: ($_ENV['INTERNAL_SYNC_KEY'] ?? '');
        if (empty($worker_url) || empty($internal_key)) {
            error_log("sync_ticket_status_to_worker SKIPPED (ticket_id={$ticket_id}): url_set=" . (empty($worker_url) ? 'NO' : 'YES') . ", key_set=" . (empty($internal_key) ? 'NO' : 'YES'));
            return;
        }

        $ch = curl_init(rtrim($worker_url, '/'));
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Internal-Key: ' . $internal_key],
            CURLOPT_POSTFIELDS => json_encode(['action' => 'sync_ticket_status', 'ticket_id' => $ticket_id, 'status' => $status], JSON_UNESCAPED_UNICODE),
        ]);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($err) {
            error_log("sync_ticket_status_to_worker CURL ERROR (ticket_id={$ticket_id}): {$err}");
        } elseif ($http_code < 200 || $http_code >= 300) {
            error_log("sync_ticket_status_to_worker FAILED (ticket_id={$ticket_id}, http_code={$http_code}): " . substr($resp, 0, 500));
        }
    } catch (Throwable $e) {
        error_log('sync_ticket_status_to_worker error: ' . $e->getMessage());
    }
}


function trigger_cache_rebuild($merchant_id, $merchant_username) {
    global $pdo;
    if (!$pdo) return false;

    try {
        // 1. جلب كافة المنتجات النشطة والمقبولة لهذا التاجر من TiDB Cloud
        $stmt = $pdo->prepare("SELECT * FROM products WHERE merchant_id = ? AND is_available = 1 AND (approval_status = 'approved' OR approval_status IS NULL OR approval_status = '')");
        $stmt->execute([$merchant_id]);
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // 2. جلب فئات هذا التاجر + الفئات العامة المشتركة فقط (استعلام واحد خفيف)
        $stmt_cats = $pdo->prepare("SELECT id, name, parent_id FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY parent_id, name");
        $stmt_cats->execute([$merchant_id]);
        $all_categories = $stmt_cats->fetchAll(PDO::FETCH_ASSOC);

        $timestamp = round(microtime(true) * 1000);
        $PAGE_SIZE = 20;

        // =======================================================
        // ⭐ إعادة هيكلة كاملة لملفات JSON لمنع تكرار كتابة نفس بيانات
        //    المنتج أو الفئة في أكثر من ملف:
        //    - ملفات products_page_N.json هي المصدر الوحيد للبيانات الكاملة للمنتج
        //      (مُخزَّنة ككائن مفهرس بمعرّف المنتج id => بياناته، وليس كمصفوفة، لسرعة
        //      الوصول المباشر O(1) بدل البحث الخطي).
        //    - ملف categories.json يحتوي الشجرة الكاملة للفئات (فئة داخل فئة بلا حد
        //      للعمق عبر parent_id)، وكل فئة تحمل فقط "مرجعاً مختصراً" لكل منتج تابع لها:
        //      {id, n: اسم مختصر, pg: رقم الصفحة} — دون تكرار وصف/سعر/صورة المنتج الكامل.
        //    - ملف search_index.json يبقى خفيفاً جداً لغرض البحث السريع فقط (نفس المرجع
        //      المختصر أعلاه)، ولا يكرر أي بيانات كاملة أيضاً.
        //    النتيجة: كل منتج وكل فئة يُكتبان مرة واحدة فقط عبر كل ملفات المتجر،
        //    ما يقلّل حجم البيانات المرفوعة لكل تحديث ويجعل بناء الكاش أسرع وأخف على السيرفر.
        // =======================================================

        $pages = [];       // pageNum => [ productId => fullProductData ]
        $productRef = [];  // productId => ['id','n' (اسم مختصر),'pg' (رقم الصفحة),'cid' (معرّف الفئة)]

        $chunks = array_chunk($products, $PAGE_SIZE);
        foreach ($chunks as $index => $chunk) {
            $pageNum = $index + 1;
            $pageData = [];
            foreach ($chunk as $p) {
                $opts = !empty($p['options']) ? (json_decode($p['options'], true) ?: []) : [];
                $feats = !empty($p['features']) ? (json_decode($p['features'], true) ?: []) : [];
                $cid = !empty($p['category_id']) ? (int)$p['category_id'] : null;

                // البيانات الكاملة تُكتب هنا فقط، مرة واحدة، ضمن ملف صفحتها
                $pageData[$p['id']] = [
                    'id' => $p['id'],
                    'name' => $p['name'],
                    'mainDescription' => $p['description'] ?? '',
                    'price' => (float)$p['price'],
                    'discount' => (float)($p['discount'] ?? 0),
                    'image' => $p['image'] ?? '',
                    'type' => $p['type'] ?? 'عام',
                    'category_id' => $cid,
                    'options' => $opts,
                    'features' => $feats,
                    'quantity' => (int)($p['quantity'] ?? 0),
                    'quantity_type' => $p['quantity_type'] ?? 'tracked',
                    'is_available' => (int)($p['is_available'] ?? 1)
                ];

                // مرجع مختصر فقط (اختصار الاسم + رقم الصفحة) يُستخدم في كل من
                // categories.json و search_index.json بدل تكرار المنتج كاملاً
                $productRef[$p['id']] = [
                    'id' => $p['id'],
                    'n'  => mb_substr((string)$p['name'], 0, 40),
                    'pg' => $pageNum,
                    'cid' => $cid,
                ];
            }
            $pages[$pageNum] = $pageData;
        }
        if (empty($pages)) $pages[1] = [];

        // 3. بناء شجرة الفئات الكاملة (تدعم فئة داخل فئة داخل فئة بلا حد للعمق)
        $catMap = [];
        foreach ($all_categories as $c) {
            $catMap[(int)$c['id']] = [
                'id' => (int)$c['id'],
                'name' => $c['name'],
                'parent_id' => !empty($c['parent_id']) ? (int)$c['parent_id'] : 0,
                'products' => [],
                'children' => [],
            ];
        }
        // ربط كل منتج بفئته عبر مرجعه المختصر فقط (بدون تكرار بياناته الكاملة)
        foreach ($productRef as $ref) {
            if ($ref['cid'] && isset($catMap[$ref['cid']])) {
                $catMap[$ref['cid']]['products'][] = ['id' => $ref['id'], 'n' => $ref['n'], 'pg' => $ref['pg']];
            }
        }
        // ترتيب الفئات هرمياً: كل فئة تُدرَج داخل مصفوفة "children" الخاصة بأبيها
        $catRoots = [];
        foreach ($catMap as $id => &$node) {
            if ($node['parent_id'] && isset($catMap[$node['parent_id']])) {
                $catMap[$node['parent_id']]['children'][] = &$node;
            } else {
                $catRoots[] = &$node;
            }
        }
        unset($node);

        $categoriesData = [
            '_version' => $timestamp,
            'data' => $catRoots
        ];

        // 4. كشاف بحث خفيف جداً: نفس المرجع المختصر فقط (id + اسم + رقم صفحة)
        $searchIndex = [
            '_version' => $timestamp,
            'data' => array_values(array_map(function($r) {
                return ['id' => $r['id'], 'n' => $r['n'], 'pg' => $r['pg']];
            }, $productRef))
        ];

        $manifestVersions = [
            'search' => $timestamp,
            'categories' => $timestamp,
            'info' => $timestamp,
            'pages' => []
        ];

        // =======================================================
        // 5. ⭐ تجميع كل الملفات (search_index + categories + صفحات المنتجات + manifest)
        //    في مصفوفة واحدة، ثم رفعها بـ Commit واحد فقط عبر
        //    gh_upload_multiple_files (بدلاً من استدعاء kv_request عدة مرات
        //    داخل foreach، وهو ما كان يسبب طلبات HTTP متتالية وبطيئة).
        // =======================================================
        $files_to_upload = [];

        $files_to_upload['search_index'] = $searchIndex;
        $files_to_upload['categories']   = $categoriesData;

        foreach ($pages as $pageNum => $pageData) {
            $pagePayload = [
                '_version' => $timestamp,
                'page' => $pageNum,
                'total_pages' => count($pages),
                'data' => $pageData // كائن مفهرس بمعرّف المنتج، وليس مصفوفة
            ];
            $files_to_upload["products_page_{$pageNum}"] = $pagePayload;
            $manifestVersions['pages']["page_{$pageNum}"] = $timestamp;
        }

        // 6. إضافة ملف المانيفست النهائي إلى نفس دفعة الرفع
        $manifestPayload = [
            'version' => $timestamp,
            'total_products' => count($products),
            'total_pages' => count($pages),
            'files' => $manifestVersions
        ];
        $files_to_upload['manifest'] = $manifestPayload;

        // 7. ⭐ استدعاء واحد فقط لرفع جميع الملفات دفعة واحدة (Batch Upload)
        $upload_ok = gh_upload_multiple_files($merchant_username, $files_to_upload);

        if (!$upload_ok) {
            error_log("Batch upload إلى GitHub فشل للتاجر: {$merchant_username}");
        }

        // =======================================================
        // ⭐ مسح كاش Cloudflare لهذا التاجر فقط (يبقى كما هو دون تغيير)
        // =======================================================
        $total_pages = count($pages) ?: 1;
        purge_merchant_cloudflare_cache($merchant_username, $total_pages);

        return $upload_ok;
    } catch (Exception $e) {
        error_log("Failed to rebuild cache for merchant $merchant_id: " . $e->getMessage());
        return false;
    }
}
function escape_like_search($search) {
    return str_replace(['\\', '%', '_'],['\\\\', '\%', '\_'], $search);
}

function filter_allowed_keys($data, $allowed_keys) {
    if (!is_array($data)) return[];
    return array_intersect_key($data, array_flip($allowed_keys));
}

function validate_image_upload($file) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return "حدث خطأ أثناء رفع الملف. قد يكون حجمه كبيراً جداً.";
    }
    if ($file['size'] === 0) {
        return "الملف المرفوع فارغ.";
    }
    $max_size = 2 * 1024 * 1024; // 2MB
    if ($file['size'] > $max_size) {
        return "حجم الملف كبير جداً. الحد الأقصى المسموح به هو 2 ميجابايت.";
    }

    $allowed_mime_types =['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $file_mime_type = mime_content_type($file['tmp_name']);
    if (!in_array($file_mime_type, $allowed_mime_types)) {
        return "نوع الملف غير مسموح به. الرجاء رفع صور من نوع (JPG, PNG, GIF, WEBP) فقط.";
    }

    $allowed_extensions =['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_extension, $allowed_extensions)) {
        return "امتداد الملف غير صالح. الامتدادات المسموحة هي (jpg, jpeg, png, gif, webp).";
    }
    return true;
}

function is_safe_image_url($url) {
    if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    return true;
}

function extract_coords_from_url($url) {
    if (!$url) return null;
    if (preg_match('/@?(-?\d+\.\d+),(-?\d+\.\d+)/', $url, $matches)) {
        return['lat' => (float)$matches[1], 'lng' => (float)$matches[2]];
    }
    if (preg_match('/q=(-?\d+\.\d+),(-?\d+\.\d+)/', $url, $matches)) {
        return['lat' => (float)$matches[1], 'lng' => (float)$matches[2]];
    }
    return null;
}

/**
 * update_kv_manifest — تحديث ملف manifest.json على GitHub مباشرة.
 * يجلب المانيفست الحالي أولاً لدمج الـ files معه قبل الرفع.
 */
function update_kv_manifest($merchant_username) {
    $timestamp = round(microtime(true) * 1000);

    // جلب المانيفست الحالي من GitHub (إن وجد) لدمج البيانات
    $current = kv_request("stores/$merchant_username/manifest", 'GET') ?: [];

    $current['version']   = $timestamp;
    $current['updated_at'] = date('Y-m-d H:i:s');

    // رفع المانيفست المحدّث مباشرة إلى GitHub
    kv_request("stores/$merchant_username/manifest", 'PUT', $current);
}

function is_valid_gps_location($url) {
    $coords = extract_coords_from_url($url);
    if (!$coords) return false; 
    
    $lat = $coords['lat'];
    $lng = $coords['lng'];
    
    if ($lat < MIN_ALLOWED_LAT || $lat > MAX_ALLOWED_LAT) return false;
    if ($lng < MIN_ALLOWED_LNG || $lng > MAX_ALLOWED_LNG) return false;
    
    return true;
}

function calculate_distance($lat1, $lon1, $lat2, $lon2) {
    $earthRadius = 6371;
    $dLat = deg2rad($lat2 - $lat1);
    $dLon = deg2rad($lon2 - $lon1);
    $a = sin($dLat / 2) * sin($dLat / 2) + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) * sin($dLon / 2);
    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
    return $earthRadius * $c;
}

function update_order_tracking($merchant_username, $order_id, $status) {
    $tracking_data = [
        'status' => $status,
        'updated_at' => time()
    ];
    sync_to_firebase($merchant_username, "tracking", $order_id, $tracking_data, 'PUT');
}

function calculate_delivery_fee($distance_km) {
    $base_fee = 300; // السعر الأساسي الثابت
    $fee_per_km = 100; // السعر لكل كيلومتر
    $rounding_factor = 50; // التقريب لأقرب 50 ريال لتجنب الكسور في الحساب
    
    // حساب الإجمالي: (300) + (المسافة * 100)
    $total_fee = $base_fee + ($distance_km * $fee_per_km);
    
    // تقريب الرقم النهائي (مثلاً 520 تصبح 550)
    return ceil($total_fee / $rounding_factor) * $rounding_factor;
}
/**
 * sync_merchant_info_json — مزامنة بيانات المتجر إلى GitHub مباشرة.
 * ✅ لا يوجد Cloudflare KV — GitHub هو المصدر الوحيد.
 */
function sync_merchant_info_json($pdo, $user_id, $merchant_username) {
    $stmt = $pdo->prepare("SELECT store_name, store_type, phone, settings FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user_record = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user_record) return;

    $timestamp = round(microtime(true) * 1000);
    $settings  = json_decode($user_record['settings'] ?: '{}', true);

    $info_data = [
        '_version'   => $timestamp,
        'merchant_id'=> $user_id,
        'username'   => $merchant_username,
        'store_name' => $user_record['store_name'],
        'store_type' => $user_record['store_type'],
        'phone'      => $settings['phone'] ?? $user_record['phone'] ?? '',
        'settings'   => $settings,
    ];

    // 1. رفع info.json مباشرة إلى GitHub عبر kv_request (الموحّدة)
    kv_request("stores/$merchant_username/info", 'PUT', $info_data);

    // 2. تحديث المانيفست على GitHub
    // 2. تحديث المانيفست على GitHub
    $manifest_path = "stores/$merchant_username/manifest";
    $current_manifest = kv_request($manifest_path, 'GET') ?: [];

    $current_manifest['version'] = $timestamp;
    if (!isset($current_manifest['files'])) $current_manifest['files'] = [];
    $current_manifest['files']['info'] = $timestamp;

    kv_request($manifest_path, 'PUT', $current_manifest);
    
    // ⭐ مسح الكاش لملف info فقط بعد تحديثه
    purge_merchant_cloudflare_cache($merchant_username, 0); // 0 يعني لا تمسح صفحات المنتجات
}
function reassign_stale_orders($pdo) {
    try {
        $pdo->beginTransaction();
        
        $timeout_seconds = ORDER_ACCEPT_TIMEOUT_SECONDS;
        $stale_orders_stmt = $pdo->prepare(
            "SELECT id, delivery_agent_id FROM orders 
             WHERE status = 'accepted_by_delivery' 
             AND accepted_at < NOW() - INTERVAL ? SECOND"
        );
        $stale_orders_stmt->execute([$timeout_seconds]);
        $stale_orders = $stale_orders_stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($stale_orders) > 0) {
            $agent_ids_to_strike = array_map(function($order) {
                return ['agent_id' => $order['delivery_agent_id'], 'order_id' => $order['id']];
            }, $stale_orders);
            
            $strike_stmt = $pdo->prepare("INSERT INTO delivery_agent_strikes (agent_id, order_id, strike_type) VALUES (?, ?, 'accept_timeout')");
            foreach ($agent_ids_to_strike as $strike) {
                $strike_stmt->execute([$strike['agent_id'], $strike['order_id']]);
            }
            
            $order_ids_to_reset = array_column($stale_orders, 'id');
            if (!empty($order_ids_to_reset)) {
                $placeholders = implode(',', array_fill(0, count($order_ids_to_reset), '?'));
                $reset_stmt = $pdo->prepare("UPDATE orders SET delivery_agent_id = NULL, status = 'pending_delivery_acceptance', accepted_at = NULL, exclusive_agent_id = NULL, dispatch_queue = NULL, exclusive_until = NULL WHERE id IN ($placeholders)");
                $reset_stmt->execute($order_ids_to_reset);
            }
        }

        $dispatch_stmt = $pdo->prepare(
            "SELECT id, dispatch_queue FROM orders 
             WHERE status = 'pending_delivery_acceptance' 
             AND exclusive_agent_id IS NOT NULL 
             AND exclusive_until <= NOW()"
        );
        $dispatch_stmt->execute();
        $stale_dispatches = $dispatch_stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($stale_dispatches as $dispatch) {
            $queue = json_decode($dispatch['dispatch_queue'], true) ?:[];
            if (count($queue) > 0) {
                $next_agent = array_shift($queue);
                $new_queue_json = count($queue) > 0 ? json_encode($queue) : null;
                $update_dispatch = $pdo->prepare("UPDATE orders SET exclusive_agent_id = ?, dispatch_queue = ?, exclusive_until = DATE_ADD(NOW(), INTERVAL 3 MINUTE) WHERE id = ?");
                $update_dispatch->execute([$next_agent, $new_queue_json, $dispatch['id']]);
            } else {
                $update_dispatch = $pdo->prepare("UPDATE orders SET exclusive_agent_id = NULL, dispatch_queue = NULL, exclusive_until = NULL WHERE id = ?");
                $update_dispatch->execute([$dispatch['id']]);
            }
        }

        $pdo->commit();
    } catch (Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log("Error in reassign_stale_orders: " . $e->getMessage());
    }
}

function push_update_to_clients($topic, $data) {
    return;
}

// ✅ يبحث عن فئة (باسمها وأبيها) ضمن فئات هذا التاجر أو الفئات العامة المشتركة، وإن لم توجد ينشئها.
//    مصمّمة عمداً لتكون "مقاومة للأعطال": بعض قواعد البيانات قد يكون فيها قيد تفرّد (UNIQUE)
//    قديم على (name, parent_id) فقط دون user_id — ما قد يسبب فشل الإدخال إن استخدم تاجرٌ آخر
//    نفس اسم الفئة من قبل. بدل أن يفشل نشر المنتج بالكامل برسالة "خطأ في قاعدة البيانات"،
//    نلتقط هذا التعارض ونعيد استخدام أي فئة مطابقة موجودة فعلاً بدلاً من ذلك.
function resolve_or_create_category($pdo, $name, $parent_id, $user_id) {
    $stmt_find = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND parent_id = ? AND (user_id = ? OR user_id IS NULL) LIMIT 1");
    $stmt_find->execute([$name, $parent_id, $user_id]);
    $existing_id = $stmt_find->fetchColumn();
    if ($existing_id) return (int)$existing_id;

    try {
        $stmt_ins = $pdo->prepare("INSERT INTO categories (name, parent_id, user_id, created_at) VALUES (?, ?, ?, ?)");
        $stmt_ins->execute([$name, $parent_id, $user_id, round(microtime(true) * 1000)]);
        return (int)$pdo->lastInsertId();
    } catch (PDOException $e) {
        // تعارض غير متوقع (مثل قيد تفرّد لا يأخذ user_id بعين الاعتبار) — لا نفشل نشر المنتج،
        // بل نستخدم أي فئة مطابقة موجودة فعلاً في قاعدة البيانات بنفس الاسم والأب.
        $stmt_fallback = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND parent_id = ? LIMIT 1");
        $stmt_fallback->execute([$name, $parent_id]);
        $fallback_id = $stmt_fallback->fetchColumn();
        if ($fallback_id) return (int)$fallback_id;
        throw $e; // لم نجد أي بديل مناسب — أعد رمي الاستثناء الأصلي
    }
}

function get_full_category_paths($pdo) {
    try {
        $stmt = $pdo->query("SELECT id, name, parent_id FROM categories ORDER BY parent_id, name");
        $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $paths = [];
        
        foreach ($categories as $cat) {
            if ($cat['parent_id'] == 0 || is_null($cat['parent_id'])) {
                $paths[$cat['id']] = $cat['name'];
            } else {
                $parent_name = isset($paths[$cat['parent_id']]) ? $paths[$cat['parent_id']] : '';
                $paths[$cat['id']] = $parent_name ? $parent_name . ' > ' . $cat['name'] : $cat['name'];
            }
        }
        return $paths;
    } catch (Exception $e) {
        return [];
    }
}

// دالة جديدة لبناء شجرة الفئات
// ✅ ترجع قائمة "مسطّحة" (flat) وليست متداخلة، لأن الواجهة الأمامية تبني الشجرة بنفسها
//    من خلال حقل parent_id لكل عنصر. إرجاع بنية متداخلة (children) كان يسبب اختفاء أي
//    فئة أعمق من المستوى الأول (فئة داخل فئة داخل فئة) من قوائم الاختيار في لوحة التاجر.
// ✅ تُفلتر النتائج بحيث يرى كل تاجر فئاته الخاصة فقط + الفئات العامة المشتركة
//    (user_id = NULL)، ولا يرى فئات تاجر آخر إطلاقاً.
function build_category_tree($pdo, $user_id = null) {
    try {
        if ($user_id) {
            $stmt = $pdo->prepare("SELECT id, name, parent_id FROM categories WHERE (user_id = ? OR user_id IS NULL) ORDER BY parent_id, name");
            $stmt->execute([$user_id]);
        } else {
            $stmt = $pdo->query("SELECT id, name, parent_id FROM categories WHERE user_id IS NULL ORDER BY parent_id, name");
        }
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        return [];
    }
}

function broadcast_store_update_signal($merchant_id, $action_name) {
    $signal_data =[
        'last_updated' => time(),
        'merchant_id' => $merchant_id,
        'action' => $action_name
    ];
}

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && ($error['type'] === E_ERROR || $error['type'] === E_PARSE)) {
        if (ob_get_length()) ob_clean();
        http_response_code(500); 
        echo json_encode([
            'status' => 'error', 
            'message' => 'عطل فادح: ' . $error['message'] . ' في السطر ' . $error['line']
        ], JSON_UNESCAPED_UNICODE);
    }
});

// =======================================================
// 3. الاتصال بقاعدة البيانات ومعالجة الطلب
// =======================================================
try {
    require_once (__DIR__) . '/nalsh-user-admin-name.php';
    
    // إنشاء وتهيئة الهيكل الموحد لجدول المنتجات في TiDB لضمان استقرار العمليات دون الحاجة لـ D1
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `products` (
            `id` VARCHAR(100) PRIMARY KEY,
            `merchant_id` INT NOT NULL,
            `name` VARCHAR(255) NOT NULL,
            `description` TEXT,
            `price` DECIMAL(10,2) NOT NULL DEFAULT 0,
            `cost_price` DECIMAL(10,2) DEFAULT 0,
            `discount` DECIMAL(5,2) DEFAULT 0,
            `image` TEXT,
            `type` VARCHAR(100) DEFAULT 'عام',
            `options` JSON,
            `features` JSON,
            `quantity` INT DEFAULT 0,
            `quantity_type` ENUM('tracked', 'unlimited') DEFAULT 'tracked',
            `is_available` TINYINT(1) DEFAULT 1,
            `currency` VARCHAR(10) DEFAULT 'YER',
            `updated_at` BIGINT,
            `approval_status` VARCHAR(50) DEFAULT 'approved',
            `isAvailable` TINYINT(1) DEFAULT 1,
            `category_id` INT,
            `department` VARCHAR(100) DEFAULT 'عام',
            `keywords` TEXT,
            INDEX `merchant_idx` (`merchant_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // ⭐ إصلاح جذري ثانٍ: CREATE TABLE IF NOT EXISTS لا يفعل شيئاً إن كان الجدول
        //    "products" موجوداً بالفعل من نسخة سابقة للنظام لا تحتوي على أعمدة أُضيفت
        //    لاحقاً (مثل category_id، approval_status، isAvailable...). في هذه الحالة
        //    أي استعلام INSERT/UPDATE/SELECT يذكر هذه الأعمدة يفشل بخطأ
        //    "Unknown column" ويظهر للتاجر كرسالة عامة "حدث خطأ في قاعدة البيانات".
        //    الحل: نتأكد من وجود كل عمود مطلوب ونضيفه إن كان ناقصاً، بأمان تام
        //    (كل عملية معزولة بـ try/catch حتى لا تتوقف البقية إن كان العمود موجوداً أصلاً).
        $products_columns_to_ensure = [
            "description"     => "ALTER TABLE products ADD COLUMN description TEXT",
            "cost_price"      => "ALTER TABLE products ADD COLUMN cost_price DECIMAL(10,2) DEFAULT 0",
            "discount"        => "ALTER TABLE products ADD COLUMN discount DECIMAL(5,2) DEFAULT 0",
            "image"           => "ALTER TABLE products ADD COLUMN image TEXT",
            "type"            => "ALTER TABLE products ADD COLUMN type VARCHAR(100) DEFAULT 'عام'",
            "options"         => "ALTER TABLE products ADD COLUMN options JSON",
            "features"        => "ALTER TABLE products ADD COLUMN features JSON",
            "quantity"        => "ALTER TABLE products ADD COLUMN quantity INT DEFAULT 0",
            "quantity_type"   => "ALTER TABLE products ADD COLUMN quantity_type ENUM('tracked','unlimited') DEFAULT 'tracked'",
            "is_available"    => "ALTER TABLE products ADD COLUMN is_available TINYINT(1) DEFAULT 1",
            "currency"        => "ALTER TABLE products ADD COLUMN currency VARCHAR(10) DEFAULT 'YER'",
            "updated_at"      => "ALTER TABLE products ADD COLUMN updated_at BIGINT",
            "approval_status" => "ALTER TABLE products ADD COLUMN approval_status VARCHAR(50) DEFAULT 'approved'",
            "isAvailable"     => "ALTER TABLE products ADD COLUMN isAvailable TINYINT(1) DEFAULT 1",
            "category_id"     => "ALTER TABLE products ADD COLUMN category_id INT",
            "department"      => "ALTER TABLE products ADD COLUMN department VARCHAR(100) DEFAULT 'عام'",
            "keywords"        => "ALTER TABLE products ADD COLUMN keywords TEXT",
        ];
        foreach ($products_columns_to_ensure as $col => $alter_sql) {
            try { $pdo->exec($alter_sql); } catch (Exception $e) {}
        }
        try {
            $pdo->exec("ALTER TABLE products ADD INDEX category_idx (category_id)");
        } catch (Exception $e) {}

        // ⭐ إصلاح جذري: إنشاء جدول الفئات categories إن لم يكن موجوداً إطلاقاً.
        //    (هذا هو السبب الأساسي لرسالة "حدث خطأ في قاعدة البيانات" عند إضافة منتج
        //    أو استخدام الفئات: كانت أوامر SELECT/INSERT على جدول categories تفشل لأن
        //    الجدول نفسه غير موجود في قاعدة البيانات، فيلتقطها catch(PDOException)
        //    في نهاية الملف ويحوّلها لرسالة عامة دون تفاصيل).
        $pdo->exec("CREATE TABLE IF NOT EXISTS `categories` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `name` VARCHAR(150) NOT NULL,
            `parent_id` INT DEFAULT 0,
            `user_id` INT DEFAULT NULL,
            `created_at` BIGINT,
            INDEX `parent_idx` (`parent_id`),
            INDEX `user_idx` (`user_id`),
            UNIQUE KEY `uniq_name_parent_user` (`name`, `parent_id`, `user_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // إضافة الأعمدة المطلوبة إن كان الجدول موجوداً مسبقاً بنسخة قديمة ناقصة الأعمدة
        try {
            $pdo->exec("ALTER TABLE categories ADD COLUMN parent_id INT DEFAULT 0");
        } catch (Exception $e) {}
        try {
            $pdo->exec("ALTER TABLE categories ADD COLUMN user_id INT DEFAULT NULL");
        } catch (Exception $e) {}
        try {
            $pdo->exec("ALTER TABLE categories ADD COLUMN created_at BIGINT DEFAULT NULL");
        } catch (Exception $e) {}
    } catch (Exception $e) {}

    $input =[];
    if (!empty(file_get_contents('php://input'))) {
        $input = json_decode(file_get_contents('php://input'), true) ?:[];
    }
    $input = array_merge($_POST, $_GET, $input);
    $action = $input['action'] ?? '';

    $customer_id = null;
    $user_id = null;
    $user_role = null;

    $exempted_actions = [
        'get_initial_data', 'check_store_updates', 'get_public_products', 
        'auth_request_otp', 'auth_verify_otp', 'check_customer_session', 
        'login', 'check_phone', 'register_init', 'register_verify',
        'select_role', 'verify_new_device_otp', 'resend_device_otp',
        'recover_init', 'recover_check_otp', 'recover_set_password', 'build_cache_cron',
        'worker_sync_settings', // نداء داخلي من الـ Worker فقط، محمي بمفتاح X-Internal-Key بدلاً من JWT
        'worker_sync_new_order', // ⭐ نداء داخلي من الـ Worker بعد إنشاء/دمج طلب في D1، محمي بنفس المفتاح
    ];

    $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? '';
    if (!$auth_header && isset($input['auth_token'])) {
        $auth_header = 'Bearer ' . $input['auth_token'];
    }

    if (!empty($auth_header)) {
        try {  // <====== قُم بإضافة هذا السطر هنا
// APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة
            list($type, $token) = explode(' ', $auth_header, 2);
            if (strcasecmp($type, 'Bearer') == 0 && !empty($token)) {
                $token_parts = explode('.', $token); // ✅ إصلاح: تعريف $token_parts قبل استخدامه
                if (count($token_parts) === 3) {
                    // APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة
                    list($header_enc, $payload_encoded, $signature_enc) = $token_parts;
                    $expected_sig = hash_hmac('sha256', "$header_enc.$payload_encoded", APP_SECRET_KEY, true);
                    
                    $expected_sig_b64url = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($expected_sig));
                    
                    if (hash_equals($signature_enc, $expected_sig_b64url) || hash_equals(base64_decode($signature_enc), $expected_sig)) {
                        $b64_payload = str_replace(['-', '_'], ['+', '/'], $payload_encoded);
                        $payload = json_decode(base64_decode($b64_payload), true);
                        
                        if ($payload && isset($payload['exp']) && $payload['exp'] > time()) {
                            if (isset($payload['role']) && $payload['role'] === 'customer') {
                                $customer_id = $payload['customer_id'];
                                $_SESSION['customer_id'] = $customer_id;
                            } else {
                                $user_id = $payload['user_id'] ?? null;
                                $user_role = $payload['role'] ?? null;
                                $merchant_username = $payload['username'] ?? null;
                                $_SESSION['user_id'] = $user_id;
                                $_SESSION['role'] = $user_role;
                                if ($merchant_username) {
                                    $_SESSION['username'] = $merchant_username;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            // تجاهل الخطأ - نظام التحقق من القفل بالأسفل سيتصرف
        }
    }

    if (!in_array($action, $exempted_actions) && !$customer_id && !$user_id) {
        send_response('error', ['message' => 'يرجى تسجيل الدخول (انتهت الجلسة)'], 401);
    }

    if (!isset($pdo) || !$pdo) {
        throw new Exception("فشل الاتصال بقاعدة البيانات.");
    }

    $is_secure_cookie = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    if (strpos($_SERVER['HTTP_HOST'], 'localhost') !== false || strpos($_SERVER['HTTP_HOST'], '127.0.0.1') !== false) {
        $is_secure_cookie = false;
    }
    
    // ⭐ إدارة الجلسات الصارمة (سنة كاملة لتجنب الخروج التلقائي المزعج)
    $idle_timeout = 315360000; 
    $absolute_timeout = 315360000; 

    if (isset($_SESSION['user_id']) || isset($_SESSION['customer_id'])) {
        if (!isset($_SESSION['session_created_at'])) {
            $_SESSION['session_created_at'] = time();
        } elseif (time() - $_SESSION['session_created_at'] > $absolute_timeout) {
            session_unset(); 
            session_destroy();
            setcookie('device_token', '', time() - 3600, '/');
            setcookie('remember_me_customer', '', time() - 3600, '/');
            send_response('error',['message' => 'انتهت صلاحية الجلسة لأسباب أمنية. يرجى تسجيل الدخول مجدداً.'], 401);
        }

        if (isset($_SESSION['last_active_time']) && (time() - $_SESSION['last_active_time'] > $idle_timeout)) {
            session_unset(); 
            session_destroy();
            send_response('error',['message' => 'تم تسجيل خروجك تلقائياً بسبب عدم النشاط لفترة طويلة.'], 401);
        }
        $_SESSION['last_active_time'] = time();
    }

    define('MAX_REQUESTS_PER_MINUTE', 60); 
    define('TIME_PERIOD_SECONDS', 60);     

    $user_ip = $_SERVER['REMOTE_ADDR'];

    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `api_requests` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `ip_address` VARCHAR(45) NOT NULL,
            `request_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX (`ip_address`),
            INDEX (`request_time`)
        ) ENGINE=InnoDB;");
    } catch (PDOException $e) {}

    try { $pdo->exec("ALTER TABLE users ADD COLUMN fcm_token TEXT NULL AFTER phone"); } catch (Exception $e) {}
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `trusted_devices` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `user_id` INT NOT NULL,
            `device_token` VARCHAR(128) NOT NULL,
            `user_agent` TEXT,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `last_used_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX (`user_id`),
            INDEX (`device_token`)
        ) ENGINE=InnoDB;");
    } catch (PDOException $e) {}
    
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `idempotency_keys` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `key_token` VARCHAR(128) NOT NULL UNIQUE,
            `response_data` TEXT NOT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX (`key_token`),
            INDEX (`created_at`)
        ) ENGINE=InnoDB;");
        $pdo->exec("DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL 1 DAY");
    } catch (PDOException $e) {}
    
    try {
        $pdo->exec("DELETE FROM api_requests WHERE request_time < NOW() - INTERVAL " . TIME_PERIOD_SECONDS . " SECOND");
        $stmt_count = $pdo->prepare("SELECT COUNT(*) FROM api_requests WHERE ip_address = ?");
        $stmt_count->execute([$user_ip]);
        if ($stmt_count->fetchColumn() >= MAX_REQUESTS_PER_MINUTE) {
            send_response('error',['message' => 'لقد تجاوزت الحد الأقصى للطلبات. يرجى المحاولة بعد قليل.'], 429);
        }
        $pdo->prepare("INSERT INTO api_requests (ip_address) VALUES (?)")->execute([$user_ip]);
    } catch (PDOException $e) {}

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    header('X-New-CSRF-Token: ' . $_SESSION['csrf_token']);

    // =======================================================
    // ⭐ نظام الحماية الذكي: الاعتماد على التوكن وإلغاء الـ CSRF
    // =======================================================
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $is_jwt_authenticated = ($customer_id !== null || $user_id !== null);

        if (!$is_jwt_authenticated) {
            $token_from_session = $_SESSION['csrf_token'] ?? null;
            $token_from_header = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
            
            if (empty($token_from_session) || empty($token_from_header) || !hash_equals((string)$token_from_session, (string)$token_from_header)) {
                $exempt_actions =[
                    'auth_request_otp', 'auth_verify_otp', 'check_customer_session', 'get_initial_data',
                    'login', 'check_phone', 'select_role', 'verify_new_device_otp',
                    'register_init', 'register_verify', 'recover_init', 'recover_check_otp', 'recover_set_password'
                ];
                
                if (!in_array($action, $exempt_actions) && (isset($_SESSION['user_id']) || isset($_SESSION['customer_id']))) {
                    header('X-New-CSRF-Token: ' . $token_from_session);
                    send_response('error', [
                        'message' => 'انتهت صلاحية الصفحة. يرجى تحديث الصفحة (Refresh).', 
                        'error_type' => 'csrf_mismatch'
                    ], 403);
                }
            }
        }
    }

    $user_role = $user_role ?? $_SESSION['role'] ?? null;
    $user_id = $user_id ?? $_SESSION['user_id'] ?? null;
    $customer_id = $customer_id ?? $_SESSION['customer_id'] ?? null;

    if (empty($_SESSION['customer_id']) && isset($_COOKIE['remember_me_customer'])) {
        list($selector, $validator) = explode(':', $_COOKIE['remember_me_customer']);
        if ($selector && $validator) {
            $stmt = $pdo->prepare("SELECT * FROM auth_tokens WHERE selector = ? AND expires >= NOW()");
            $stmt->execute([$selector]);
            $token_data = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($token_data) {
                $hashed_validator_from_cookie = hash('sha256', $validator);
                if (hash_equals($token_data['hashed_validator'], $hashed_validator_from_cookie)) {
                    $stmt_cust = $pdo->prepare("SELECT full_name, phone, address FROM customers WHERE id = ?");
                    $stmt_cust->execute([$token_data['user_id']]);
                    $customer = $stmt_cust->fetch(PDO::FETCH_ASSOC);
                    if ($customer && $customer['is_active']) {
                        $_SESSION['customer_id'] = $customer['id'];
                        $_SESSION['customer_name'] = $customer['full_name'];
                    }
                }
            }
        }
    }

    $user_role = $user_role ?? $_SESSION['role'] ?? null;
    $user_id = $user_id ?? $_SESSION['user_id'] ?? null;
    $customer_id = $customer_id ?? $_SESSION['customer_id'] ?? null;

    // التقاط الـ Token من الـ Payload إذا كان موجوداً
    $jwt_device_token = null;
    if (isset($payload) && is_array($payload) && isset($payload['device_token'])) {
        $jwt_device_token = $payload['device_token'];
    }

    if ($user_id && in_array($user_role,['merchant', 'delivery', 'admin'])) {
        // الاعتماد على الكوكي، وإذا لم يوجد نأخذه من الـ JWT Token
        $current_device_token = $_COOKIE['device_token'] ?? $jwt_device_token;
        
        // حفظه في الجلسة لاستخدامه عند تغيير الباسورد
        if ($current_device_token) $_SESSION['current_device_token'] = $current_device_token;

        if (empty($current_device_token)) {
            // طرد مباشر: يمنع أي محاولة دخول بدون بصمة الجهاز
            session_unset(); session_destroy();
            send_response('error',['message' => 'جلسة غير صالحة أو غير مكتملة. يرجى إعادة تسجيل الدخول.'], 401);
        } else {
            // التحقق الصارم والإجباري من قاعدة البيانات في كل طلب
            $stmt_check_dev = $pdo->prepare("SELECT id FROM trusted_devices WHERE user_id = ? AND device_token = ?");
            $stmt_check_dev->execute([$user_id, $current_device_token]);
            if (!$stmt_check_dev->fetchColumn()) {
                session_unset(); session_destroy();
                setcookie('device_token', '', time() - 3600, '/');
                send_response('error',['message' => 'تم تغيير كلمة المرور أو إنهاء هذه الجلسة عن بعد. يرجى تسجيل الدخول مجدداً.'], 401);
            }
        }
    }

    if ($customer_id) {
        $stmt_check_cust = $pdo->prepare("SELECT is_active FROM customers WHERE id = ?");
        $stmt_check_cust->execute([$customer_id]);
        $isActiveStatus = $stmt_check_cust->fetchColumn();
        if ($isActiveStatus !== false && (int)$isActiveStatus === 0) {
            session_unset(); session_destroy();
            setcookie('remember_me_customer', '', time() - 3600, '/');
            send_response('error',['message' => 'تم إنهاء الجلسة أو حظر الحساب. يرجى مراجعة الإدارة.'], 401);
        }
    }

    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if (strpos($referer, '/admin/') !== false && $user_id && $user_role !== 'admin') {
        send_response('error',['message' => 'تم تسجيل الدخول بحساب آخر. يرجى تسجيل الدخول كمدير.'], 401);
    }
    if (strpos($referer, 'merchant-dashboard') !== false && $user_id && $user_role !== 'merchant') {
        send_response('error',['message' => 'تغيرت الجلسة في نافذة أخرى. يرجى إعادة تسجيل الدخول.'], 401);
    }
    if (strpos($referer, 'delivery-dashboard') !== false && $user_id && $user_role !== 'delivery') {
        send_response('error',['message' => 'تغيرت الجلسة في نافذة أخرى. يرجى إعادة تسجيل الدخول.'], 401);
    }

    // =======================================================
    // 4. توجيه الطلبات (API Router)
    // =======================================================

    switch ($action) {
        case 'get_firebase_config':
            if (!$user_id) send_response('error', ['message' => 'غير مصرح'], 401);
            $config = [
                'apiKey' => getenv('FCM_API_KEY') ?: '',
                'authDomain' => getenv('FCM_AUTH_DOMAIN') ?: '',
                'projectId' => getenv('FCM_PROJECT_ID') ?: '',
                'messagingSenderId' => getenv('FCM_SENDER_ID') ?: '',
                'appId' => getenv('FCM_APP_ID') ?: '',
                'vapidKey' => getenv('FCM_VAPID_KEY') ?: ''
            ];
            if (empty($config['apiKey'])) throw new Exception("إعدادات الإشعارات غير مهيأة.");
            send_response('success', ['config' => $config]);
            break;

        case 'upload_image':
            if (!$user_id) send_response('error', ['message' => 'غير مصرح'], 401);
            if (isset($_FILES['image_data']) && $_FILES['image_data']['error'] === UPLOAD_ERR_OK) {
                // ⭐ مراجعة أمنية: التحقق من نوع وحجم الملف قبل رفعه
                $validation_result = validate_image_upload($_FILES['image_data']);
                if ($validation_result !== true) {
                    throw new Exception($validation_result);
                }

                $env_keys = getenv('IMGBB_KEYS') ?: $_ENV['IMGBB_KEYS'] ?? '';
                if (empty($env_keys)) throw new Exception("مفتاح السيرفر مفقود.");
                
                $keys_array = array_map('trim', explode(',', $env_keys));
                $api_key = $keys_array[array_rand($keys_array)];
                
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, "https://api.imgbb.com/1/upload?key=" . $api_key);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $mime = mime_content_type($_FILES['image_data']['tmp_name']);
                $filename = $_FILES['image_data']['name'] ?? 'variant.webp';
                curl_setopt($ch, CURLOPT_POSTFIELDS, ['image' => new CURLFile($_FILES['image_data']['tmp_name'], $mime, $filename)]);
                $result = json_decode(curl_exec($ch), true);
                curl_close($ch);
                
                if ($result && isset($result['data']['url'])) {
                    send_response('success', ['url' => $result['data']['url']]);
                } else {
                    throw new Exception("فشل رفع صورة الخيار المتعدد.");
                }
            }
            throw new Exception("لم يتم استلام أي صورة صالحة.");
            break;
// --- باقات الاشتراك الذكية للتجار ---
        
        case 'save_fcm_token':
            if (!$user_id) send_response('error', ['message' => 'غير مصرح'], 401);
            $fcm_token = sanitize_input($input['fcm_token'] ?? '');
            if (!empty($fcm_token)) {
                $pdo->prepare("UPDATE users SET fcm_token = ? WHERE id = ?")->execute([$fcm_token, $user_id]);
            }
            send_response('success');
            break;    

        case 'verify_cart_live':
            $cart_items = $input['items'] ?? [];
            if (empty($cart_items)) send_response('success', ['can_proceed' => true]);

            $changes = [];
            $new_cart = [];
            $can_proceed = true;

            foreach ($cart_items as $item) {
                $product_id = $item['product_id'] ?? $item['listing_id'];
                $size_id = $item['size_id'] ?? null;
                $db_item = null;

                // ⭐ جلب بيانات المنتج والكمية مباشرة من TiDB Cloud
                $stmt_check = $pdo->prepare("SELECT price, quantity, quantity_type, is_available, discount, options FROM products WHERE id = ?");
                $stmt_check->execute([$product_id]);
                $db_item = $stmt_check->fetch(PDO::FETCH_ASSOC);

                // الدعم العكسي للمنتجات القديمة المخزنة بنمط Listings
                if (!$db_item) {
                    $stmt_check = $pdo->prepare("SELECT l.merchant_price as price, l.quantity, l.quantity_type, l.is_available, p.discount, p.sizes as options FROM merchant_listings l JOIN products p ON l.global_product_id = p.id WHERE l.id = ? OR p.id = ?");
                    $stmt_check->execute([$product_id, $product_id]);
                    $db_item = $stmt_check->fetch(PDO::FETCH_ASSOC);
                }

                if (!$db_item || $db_item['is_available'] == 0) {
                    $changes[] = "المنتج '{$item['name']}' نفد أو تم إخفاؤه. تم حذفه من سلتك.";
                    $can_proceed = false;
                    continue; 
                }

                $available_qty = (int)$db_item['quantity'];
                $qty_type = $db_item['quantity_type'];
                $base_price = (float)$db_item['price'];

                // فحص المقاسات والخيارات (إن وجدت) داخل قاعدة البيانات الحية
                if ($size_id && !empty($db_item['options'])) {
                    $options = json_decode($db_item['options'], true) ?: [];
                    $found_opt = false;
                    foreach ($options as $opt) {
                        if (isset($opt['id']) && $opt['id'] === $size_id) {
                            if (isset($opt['custom_price']) && $opt['custom_price'] !== '') {
                                $base_price = (float)$opt['custom_price'];
                            }
                            if (($opt['quantity_type'] ?? 'tracked') === 'tracked') {
                                $available_qty = (int)($opt['quantity'] ?? 0);
                                $qty_type = 'tracked';
                            } else {
                                $qty_type = 'unlimited';
                            }
                            $found_opt = true;
                            break;
                        }
                    }
                    if (!$found_opt) {
                        $changes[] = "المقاس أو الخيار المختار لـ '{$item['name']}' لم يعد متوفراً.";
                        $can_proceed = false;
                        continue;
                    }
                }

                // حساب السعر النهائي بعد الخصم
                $real_price = $base_price * (1 - ($db_item['discount'] / 100));
                if (abs((float)$real_price - (float)$item['price']) > 1) {
                    $changes[] = "تغير سعر '{$item['name']}' من {$item['price']} إلى {$real_price}.";
                    $item['price'] = $real_price;
                    $can_proceed = false;
                }

                // الفحص الصارم للكمية المطلوبة
                if ($qty_type === 'tracked' && $available_qty < $item['qty']) {
                    $changes[] = "الكمية المتاحة من '{$item['name']}' هي {$available_qty} فقط.";
                    $item['qty'] = $available_qty;
                    if ($item['qty'] <= 0) continue; 
                    $can_proceed = false;
                }

                $new_cart[] = $item;
            }

            send_response('success', [
                'can_proceed' => $can_proceed,
                'changes' => $changes,
                'new_cart' => $new_cart
            ]);
            break;
// 1. التاجر يرسل رقم العملية من لوحة التحكم
 // 1. التاجر يرسل رقم العملية (بدون أن نثق بالمبلغ الذي يحدده هو)
        
        case 'get_initial_data':
            $stmt_settings = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'store_settings'");
            $settings = json_decode($stmt_settings->fetchColumn() ?: '{}', true);

            $sql_merchants = "SELECT id, store_name, username FROM users WHERE role = 'merchant' AND is_active = 1";
            $merchants = $pdo->query($sql_merchants)->fetchAll(PDO::FETCH_ASSOC);

            $sql_all = "
                SELECT
                    p.id, p.name, p.mainDescription, p.image, p.sizes, p.discount, p.department, p.keywords,
                    l.id as listing_id, l.merchant_price as price, l.quantity, l.quantity_type, l.currency,
                    u.id as merchant_id, u.store_name as merchant_name, c.name as type
                FROM merchant_listings l
                JOIN products p ON l.global_product_id = p.id
                JOIN users u ON l.merchant_id = u.id
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE l.is_available = 1 AND (l.quantity > 0 OR l.quantity_type = 'unlimited')
                  AND p.approval_status = 'approved' AND p.isAvailable = 1 AND u.role != 'admin'
                ORDER BY l.updated_at DESC
            ";
            $products = $pdo->query($sql_all)->fetchAll(PDO::FETCH_ASSOC);

            foreach ($products as &$product) {
                $product['options'] = json_decode($product['sizes'] ?? '[]', true) ?: [];
                unset($product['sizes']);
                $product['price'] = floatval($product['price']);
                $product['discount'] = floatval($product['discount']);
                $product['quantity'] = intval($product['quantity']);
                $product['department'] = $product['department'] ?? 'عام';
                $product['user_id'] = $product['merchant_id'] ?? null;
                $product['currency'] = $product['currency'] ?? 'YER';
            }
            
            unset($product); 

            send_response('success', [
                'settings' => $settings,
                'merchants' => $merchants,
                'products' => $products,
                'contact_whatsapp' => $settings['whatsappNumber'] ?? '967770094456'
            ]);
            break;

        case 'check_profile_completeness':
            if (!$user_id) send_response('error', ['message' => 'Unauthorized'], 401);
            $stmt = $pdo->prepare("SELECT store_name, store_type, settings, role FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $u = $stmt->fetch(PDO::FETCH_ASSOC);
            $settings = json_decode($u['settings'] ?: '{}', true);
            
            $incomplete = [];
            if (empty($u['store_name'])) $incomplete[] = 'store_name';
            if ($u['role'] === 'merchant') {
                if (empty($u['store_type'])) $incomplete[] = 'store_type';
                if (empty($settings['location'])) $incomplete[] = 'location';
            }
            
            send_response('success', ['is_complete' => count($incomplete) === 0, 'missing' => $incomplete]);
            break;

        case 'check_store_updates':
            $last_update = $pdo->query("SELECT MAX(updated_at) FROM merchant_listings WHERE is_available = 1")->fetchColumn();
            send_response('success', ['latest_update' => $last_update]);
            break;

        case 'get_public_products':
            $page = max(1, intval($input['page'] ?? 1));
            $limit = max(1, min(50, intval($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $category = sanitize_input($input['category'] ?? null);
            $merchant_id = sanitize_input($input['merchant_id'] ?? null); 

            $where_clauses =[
                "l.is_available = 1",
                "(l.quantity > 0 OR l.quantity_type = 'unlimited')",
                "p.approval_status = 'approved'",
                "p.isAvailable = 1"
            ];
            $params =[];

            if ($category) {
                if (is_numeric($category)) {
                    $where_clauses[] = "p.category_id = :category";
                    $params[':category'] = $category;
                } else {
                    $where_clauses[] = "(c.name = :category OR p.department = :category)";
                    $params[':category'] = $category;
                }
            }
            
            if ($merchant_id) {
                $where_clauses[] = "l.merchant_id = :merchant_id";
                $params[':merchant_id'] = $merchant_id;
            }

            $where_sql = implode(' AND ', $where_clauses);
            $base_query = " FROM merchant_listings l JOIN products p ON l.global_product_id = p.id JOIN users u ON l.merchant_id = u.id LEFT JOIN categories c ON p.category_id = c.id WHERE $where_sql";

            $sql_all = "SELECT p.id, p.name, SUBSTRING(p.mainDescription, 1, 120) as mainDescription, p.image, p.sizes, p.category_id, c.name as type, p.department, p.base_price, l.id as listing_id, l.merchant_price, l.quantity, l.quantity_type, u.id as merchant_id, u.store_name as merchant_name, u.store_type $base_query ORDER BY l.updated_at DESC LIMIT :limit OFFSET :offset";
            
            $stmt = $pdo->prepare($sql_all);
            foreach ($params as $key => &$val) { $stmt->bindParam($key, $val); }
            $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $listings = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $catPaths = get_full_category_paths($pdo);
            foreach ($listings as &$item) {
                $item['options'] = json_decode($item['sizes'] ?? '[]', true) ?: [];
                unset($item['sizes']);
                $base_price = (float)($item['base_price'] ?: $item['merchant_price']);
                $merchant_price = (float)$item['merchant_price'];
                if ($merchant_price < $base_price && $base_price > 0) {
                    $item['price'] = $base_price; $item['discount'] = (1 - ($merchant_price / $base_price)) * 100;
                } else { $item['price'] = $merchant_price; $item['discount'] = 0; }
                unset($item['base_price'], $item['merchant_price']);
                $item['price'] = floatval($item['price']); $item['discount'] = floatval($item['discount']); $item['quantity'] = intval($item['quantity']);
                $item['department'] = $item['department'] ?? 'عام';
                if (!empty($item['category_id']) && isset($catPaths[$item['category_id']])) { $item['type'] = $catPaths[$item['category_id']]; }
            }
            unset($item);
            send_response('success',['data' => $listings]);
            break;

        case 'auth_request_otp':
            try {
                if (empty($input['proof_token'])) throw new Exception("فشل التحقق الأمني (1).");

                $parts = explode('.', $input['proof_token']);
                if (count($parts) !== 2) throw new Exception("فشل التحقق الأمني (2).");

                list($encoded_payload, $client_hash) = $parts;
                $payload = base64_decode($encoded_payload, true);
                if ($payload === false) throw new Exception("فشل التحقق الأمني (3).");

                $payload_parts = explode('|', $payload);
                if (count($payload_parts) !== 3) {
                    throw new Exception("فشل التحقق الأمني (4).");
                }
                list($start_time, $tap_time, $nonce) = $payload_parts;
                
                if (!is_numeric($start_time) || !is_numeric($tap_time) || empty($nonce)) {
                    throw new Exception("فشل التحقق الأمني (5).");
                }

                $server_hash = simple_php_hash("{$start_time}|{$tap_time}|{$nonce}");
                if ((string)$server_hash !== (string)$client_hash) {
                    throw new Exception("فشل التحقق من صحة الطلب (مزور).");
                }

                $time_since_tap = time() - ($tap_time / 1000);
                if ($time_since_tap < -120 || $time_since_tap > 120) {
                    throw new Exception("انتهت صلاحية محاولة التحقق. يرجى المحاولة مرة أخرى.");
                }

                $challenge_duration = $tap_time - $start_time;
                $required_duration = 2000; 
                $allowed_window = 400;    

                if ($challenge_duration < ($required_duration - $allowed_window) || $challenge_duration > ($required_duration + $allowed_window)) {
                    throw new Exception("فشل التحقق من التوقيت. محاولة آلية محتملة.");
                }
                
                if (!isset($_SESSION['seen_proofs'])) $_SESSION['seen_proofs'] =[];
                $_SESSION['seen_proofs'] = array_filter($_SESSION['seen_proofs'], function($ts) { return time() - $ts < 120; });
                if (isset($_SESSION['seen_proofs'][$nonce])) {
                    throw new Exception("تم اكتشاف محاولة مكررة. تم رفض الطلب.");
                }
                $_SESSION['seen_proofs'][$nonce] = time();

            } catch (Exception $e) {
                throw new Exception("فشل التحقق من أنك لست روبوت. يرجى تحديث الصفحة والمحاولة مجدداً.");
            }

            $ip_address = $_SERVER['REMOTE_ADDR'];
            $phone = preg_replace('/[^0-9]/', '', $input['phone'] ?? '');

            if (strlen($phone) < 9) throw new Exception('رقم الهاتف غير صحيح.');
            
            try {
                $pdo->exec("CREATE TABLE IF NOT EXISTS `rate_limits` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `ip_address` VARCHAR(45) NOT NULL,
                    `phone_number` VARCHAR(20) NOT NULL,
                    `request_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX (`request_time`),
                    INDEX (`ip_address`),
                    INDEX (`phone_number`)
                ) ENGINE=InnoDB;");
            } catch (PDOException $e) {}

            $pdo->exec("DELETE FROM rate_limits WHERE request_time < NOW() - INTERVAL 15 MINUTE");

            // ⭐ تعديل أمني: حساب وقت الكولداون مسبقاً وتمريره كقيمة في استعلام مجهز لتفادي أخطاء المحركات وتأمين المدخلات
            $cooldown_time = date('Y-m-d H:i:s', time() - OTP_COOLDOWN_SECONDS);
            $check_stmt = $pdo->prepare(
                "SELECT request_time FROM rate_limits 
                 WHERE (ip_address = :ip OR phone_number = :phone) AND request_time > :cooldown_time 
                 ORDER BY request_time DESC LIMIT 1"
            );
            $check_stmt->execute([':ip' => $ip_address, ':phone' => $phone, ':cooldown_time' => $cooldown_time]);
            $last_request = $check_stmt->fetch(PDO::FETCH_ASSOC);

            if ($last_request) {
                $time_passed = time() - strtotime($last_request['request_time']);
                $time_left = OTP_COOLDOWN_SECONDS - $time_passed;
                if ($time_left > 0) {
                    throw new Exception("لقد طلبت كوداً مؤخراً. يرجى الانتظار $time_left ثانية.");
                }
            }

            $otp = generate_secure_otp();
            $otp_hash = hash_otp($otp);
            $message = "كود التحقق الخاص بك هو: {$otp}\nلا تشاركه مع أحد.";

            $stmt = $pdo->prepare("SELECT id, is_active, full_name FROM customers WHERE phone = ?");
            $stmt->execute([$phone]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($customer) {
                if ($customer['is_active'] == 0) throw new Exception('عذراً، هذا الرقم محظور من استخدام المتجر.');
                $pdo->prepare("UPDATE customers SET otp_code = ? WHERE id = ?")->execute([$otp_hash, $customer['id']]);

                try {
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message, status) VALUES (?, ?, 'pending')")->execute([$phone, $message]);
                } catch (PDOException $e) {}
                send_via_macrodroid($phone, $message);

            } else {
                $random_pass = password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT);
                $default_name = "عميل " . substr($phone, -4);
                
                try { $pdo->exec("ALTER TABLE customers ADD COLUMN otp_code VARCHAR(64) NULL AFTER phone"); } catch(Exception $e){}
                try { $pdo->exec("ALTER TABLE customers ADD COLUMN is_verified TINYINT(1) DEFAULT 0 AFTER is_active"); } catch(Exception $e){}
                try {
                    $pdo->exec("CREATE TABLE IF NOT EXISTS `sms_queue` (
                        `id` INT AUTO_INCREMENT PRIMARY KEY,
                        `phone_number` VARCHAR(25) NOT NULL,
                        `message` TEXT NOT NULL,
                        `status` ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
                        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        `processed_at` TIMESTAMP NULL,
                        INDEX `status_index` (`status`)
                    ) ENGINE=InnoDB;");
                } catch (PDOException $e) {}

                $stmt = $pdo->prepare("INSERT INTO customers (full_name, phone, password, address, is_verified, is_active, otp_code) VALUES (?, ?, ?, '', 1, 1, ?)");
                $stmt->execute([$default_name, $phone, $random_pass, $otp_hash]);

                try {
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message, status) VALUES (?, ?, 'pending')")->execute([$phone, $message]);
                } catch (PDOException $e) {}
                send_via_macrodroid($phone, $message);
            }

            // ⭐ إصلاح أمني حرج: لم يعد الكود يُخزَّن داخل التوكن الموقَّع المُرسَل للعميل.
            // التوكن كان "موقّعاً" فقط (HMAC) وليس مُشفَّراً، فأي عميل يقدر يفك base64
            // ويقرأ الكود مباشرة من الكوكي دون انتظار الرسالة. المصدر الوحيد للتحقق الآن هو
            // قاعدة البيانات (otp_code المُخزَّن كـ hash).
            $token_payload =[
                'purpose' => 'customer_login',
                'phone' => $phone,
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 5);
            
            setcookie('state_token', $state_token, [
                'expires' => time() + 300,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None'
            ]);
            
            $pdo->prepare("INSERT INTO rate_limits (ip_address, phone_number) VALUES (?, ?)")->execute([$ip_address, $phone]);

            send_response('success',['message' => 'تم إرسال كود التحقق بنجاح.', 'otp' => 'sent', 'phone' => $phone, 'cooldown' => OTP_COOLDOWN_SECONDS, 'state_token' => $state_token]);
            break;

        case 'auth_verify_otp':
            $otp_input = sanitize_input($input['otp'] ?? '');
            $token = $input['state_token'] ?? $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'customer_login');
            } catch (Exception $e) {
                throw new Exception($e->getMessage());
            }

            $phone = $payload['phone'];
            if (empty($otp_input)) throw new Exception('الرجاء إدخال الكود.');

            $stmt_cust = $pdo->prepare("SELECT id, full_name, address, is_active FROM customers WHERE phone = ?");
            $stmt_cust->execute([$phone]);
            $cust = $stmt_cust->fetch(PDO::FETCH_ASSOC);

            if (!$cust) throw new Exception('رقم الهاتف غير مسجل في النظام.');
            if ($cust['is_active'] == 0) throw new Exception('عذراً، حسابك محظور من الإدارة.');

            // ⭐ حد لعدد المحاولات الخاطئة على نفس التوكن (يمنع تجربة كل الأكواد الممكنة)
            $otp_attempts = (int) ($payload['attempts'] ?? 0);
            if ($otp_attempts >= 5) {
                throw new Exception('تجاوزت عدد المحاولات المسموح بها. يرجى طلب كود جديد.');
            }

            $stmt_otp = $pdo->prepare("SELECT otp_code FROM customers WHERE id = ?");
            $stmt_otp->execute([$cust['id']]);
            $otp_row = $stmt_otp->fetch(PDO::FETCH_ASSOC);

            // ⭐ إصلاح أمني حرج: المقارنة الوحيدة المسموحة الآن هي مقابل الـ hash المخزَّن
            // في قاعدة البيانات باستخدام hash_equals (آمن ضد ثغرات التوقيت). تم حذف
            // المسار البديل القديم الذي كان يقبل الكود لو طابق قيمة داخل التوكن نفسه.
            if (!verify_otp_hash($otp_input, $otp_row['otp_code'] ?? null)) {
                $new_payload = $payload;
                $new_payload['attempts'] = $otp_attempts + 1;
                unset($new_payload['exp']);
                $retry_token = generate_signed_token($new_payload, 5);
                setcookie('state_token', $retry_token, [
                    'expires' => time() + 300,
                    'path' => '/',
                    'domain' => '',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None'
                ]);
                throw new Exception('كود التحقق غير صحيح.');
            }

            {
                $pdo->prepare("UPDATE customers SET otp_code = NULL, is_verified = 1 WHERE id = ?")->execute([$cust['id']]);
                $is_new_user = (strpos($cust['full_name'], 'عميل') === 0);

                session_regenerate_id(true); 

                $_SESSION['customer_id'] = $cust['id'];
                $_SESSION['customer_name'] = $cust['full_name'];
                $_SESSION['loggedin'] = true;
                
                $is_secure_cookie = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
                
                setcookie('state_token', '', [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => $is_secure_cookie,
                    'httponly' => true,
                    'samesite' => $is_secure_cookie ? 'None' : 'Lax'
                ]);

                try {
                    $pdo->prepare("DELETE FROM auth_tokens WHERE user_id = ?")->execute([$cust['id']]);
                    $selector = bin2hex(random_bytes(16)); $validator = bin2hex(random_bytes(32)); $hashed_validator = hash('sha256', $validator);
                    $expires = date('Y-m-d H:i:s', time() + (86400 * 60)); 
                    $pdo->prepare("INSERT INTO auth_tokens (selector, hashed_validator, user_id, expires) VALUES (?, ?, ?, ?)")->execute([$selector, $hashed_validator, $cust['id'], $expires]);
                    
                    setcookie('remember_me_customer', $selector . ':' . $validator,[
                        'expires' => time() + (86400 * 60),
                        'path' => '/',
                        'domain' => '',
                        'secure' => $is_secure_cookie, 
                        'httponly' => true,
                        'samesite' => $is_secure_cookie ? 'None' : 'Lax' 
                    ]);
                } catch (PDOException $token_error) {}
                
                $payload_token = [
                    'customer_id' => $cust['id'],
                    // ⭐ إضافة (2026-07-21): الـ Worker (Cloudflare) يرفض أي توكن بدون
                    // user_id صراحة (security/auth.js). العملاء تاريخياً يستخدمون
                    // customer_id فقط، فنضيف user_id كنسخة مطابقة له حتى تصير
                    // توكنات العملاء صالحة للمصادقة على الـ Worker أيضاً، دون أي
                    // تأثير على أي كود قديم بـ api.php (لأنه ما يزال يقرأ customer_id
                    // كما هو تماماً).
                    'user_id' => $cust['id'],
                    'customer_name' => $cust['full_name'],
                    'role' => 'customer'
                ];
                // APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة
                $customer_jwt_token = generate_signed_token($payload_token, 527040); // ⭐ أكثر من سنة (366 يوم) بدل 30 يوم

                session_write_close();

                // ⭐ تصحيح (2026-07-21): نقلنا المزامنة إلى D1 لتصير *قبل* إرسال الرد
                // وليس بعده. السبب: send_response_and_continue_in_background تعتمد على
                // fastcgi_finish_request()، وهي تقنية خاصة بـ PHP-FPM فقط. على منصات
                // استضافة مُدارة مثل Render (اللي ما تستخدم بالضرورة PHP-FPM بنفس
                // الإعداد)، دالة fastcgi_finish_request قد لا تكون متاحة، فيدخل الكود
                // بالمسار البديل (flush فقط) اللي لا يضمن استمرار تنفيذ PHP فعلياً
                // بعد إغلاق الاتصال مع العميل — والنتيجة عملياً أن sync_customer_to_worker
                // لا تُنفَّذ إطلاقاً على الإنتاج رغم عدم وجود أي خطأ ظاهر (لأنها best-effort
                // ومغلّفة بـ try/catch). لتفادي هذا نهائياً، نستدعيها الآن بشكل متزامن
                // (تضيف ~100-300ms على رد تسجيل الدخول) قبل إرسال التوكن للعميل، حتى
                // تكون بيانات العميل موجودة في D1 بشكل مضمون قبل أي استدعاء لاحق فوري
                // لـ check_customer_session من الواجهة.
                sync_customer_to_worker($pdo, $cust['id']);

                send_response('success',[
                    'message' => 'تم تسجيل الدخول بنجاح!', 
                    'token' => $customer_jwt_token, 
                    'customer' => ['full_name' => $cust['full_name'], 'phone' => $phone], 
                    'needs_profile_update' => $is_new_user
                ]);
            }
            break;

        case 'check_customer_session':
            $target_id = $customer_id ?: ($_SESSION['customer_id'] ?? null);

            if ($target_id) {
                $stmt = $pdo->prepare("SELECT id, full_name, phone, address, is_active FROM customers WHERE id = ?");
                $stmt->execute([$target_id]);
                $customer_data = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($customer_data && (!isset($customer_data['is_active']) || $customer_data['is_active'] == 1)) {
                    $is_new_user = (strpos($customer_data['full_name'], 'عميل') === 0);
                    send_response('success', [
                        'loggedIn' => true, 
                        'customer' => $customer_data, 
                        'needs_profile_update' => $is_new_user
                    ]);
                }
            }
            
            send_response('success', ['loggedIn' => false]);
            break;
        
        case 'update_customer_name_only':
            if (!$customer_id) throw new Exception("يرجى تسجيل الدخول");
            $name = sanitize_input($input['name'] ?? '');
            if (empty($name) || strpos($name, 'عميل') === 0 || mb_strlen($name) < 3) throw new Exception("يرجى إدخال اسمك الحقيقي.");
            
            $pdo->prepare("UPDATE customers SET full_name = ? WHERE id = ?")->execute([$name, $customer_id]);
            $_SESSION['customer_name'] = $name;
            send_response('success',['message' => 'تم حفظ الاسم بنجاح']);
            break;            

        case 'update_customer_profile':
            if (!$customer_id) throw new Exception("يرجى تسجيل الدخول");
            
            $allowed_fields =['name', 'gps', 'description'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $name = sanitize_input($safe_input['name'] ?? ''); 
            $gps = sanitize_input($safe_input['gps'] ?? ''); 
            $desc = sanitize_input($safe_input['description'] ?? '');

            if (empty($name) || strpos($name, 'عميل') === 0) throw new Exception("يرجى إدخال اسمك الحقيقي.");
            if (empty($gps) || strpos($gps, 'http') === false) throw new Exception("يرجى تحديد موقعك الصحيح على الخريطة.");
            if (!is_valid_gps_location($gps)) throw new Exception("الموقع المحدد غير صالح أو يقع خارج النطاق الجغرافي المسموح به لخدماتنا.");
            if (empty($desc) || strlen($desc) < 4) throw new Exception("يرجى إدخال وصف دقيق للموقع ليتمكن المندوب من الوصول إليك.");
            
            $full_address = "رابط الموقع: $gps | التفاصيل: $desc";
            $pdo->prepare("UPDATE customers SET full_name = ?, address = ? WHERE id = ?")->execute([$name, $full_address, $customer_id]);
            $_SESSION['customer_name'] = $name;
            send_response('success',['message' => 'تم حفظ بياناتك بنجاح. يمكنك الآن إتمام طلباتك.']);
            break;

        case 'get_user_data':
            if (!$customer_id) send_response('error',['message' => 'غير مسجل دخول'], 401);
            
            $sql = "SELECT c.id, c.product_id, c.listing_id, c.merchant_id, c.size_id, c.quantity, 
                           p.name, p.price, p.discount, p.image, p.sizes, 
                           u.store_name as merchant_name 
                    FROM user_cart c 
                    JOIN products p ON c.product_id = p.id 
                    LEFT JOIN users u ON c.merchant_id = u.id 
                    WHERE c.customer_id = ?";
                    
            $stmt = $pdo->prepare($sql); 
            $stmt->execute([$customer_id]); 
            $cart_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($cart_items as &$item) {
                if ($item['size_id'] && $item['sizes']) {
                    $options_data = json_decode($item['sizes'], true);
                    if (is_array($options_data)) {
                        foreach ($options_data as $option) {
                            if (isset($option['id']) && $option['id'] === $item['size_id']) {
                                $item['size_name'] = $option['name'] ?? ($option['size_name'] ?? ''); 
                                $item['size_image'] = $option['image'] ?? null; 
                                break;
                            }
                        }
                    }
                } 
                unset($item['sizes']);
            }
            
            $fav = $pdo->prepare("SELECT product_id FROM user_favorites WHERE customer_id = ?"); 
            $fav->execute([$customer_id]);
            
            send_response('success',['cart' => $cart_items, 'favorites' => $fav->fetchAll(PDO::FETCH_COLUMN)]);
            break;

        case 'add_to_cart_db':
            if (!$customer_id) send_response('error',['message' => 'يجب تسجيل الدخول أولاً'], 401);

            $listing_id = sanitize_input($input['listing_id'] ?? '');
            $product_id = sanitize_input($input['product_id'] ?? $listing_id); // الاعتماد على الـ ID العالمي
            $quantity = max(1, intval($input['quantity'] ?? 1));
            $size_id = sanitize_input($input['sizeId'] ?? null);

            if (empty($product_id)) {
                throw new Exception("معرّف المنتج غير صالح.");
            }
            
            // ⭐ استعلام مباشر من قاعدة بيانات TiDB Cloud لجلب التفاصيل اللحظية
            $stmt_check = $pdo->prepare("SELECT merchant_id, id as global_product_id, quantity, quantity_type, is_available, options FROM products WHERE id = ?");
            $stmt_check->execute([$product_id]);
            $listing = $stmt_check->fetch(PDO::FETCH_ASSOC);

            // الدعم العكسي للمنتجات القديمة ومنتجات الكتالوج
            if (!$listing) {
                $stmt_check = $pdo->prepare("SELECT l.merchant_id, p.id as global_product_id, l.quantity, l.quantity_type, l.is_available, p.sizes as options FROM merchant_listings l JOIN products p ON l.global_product_id = p.id WHERE l.id = ? OR p.id = ?");
                $stmt_check->execute([$product_id, $product_id]);
                $listing = $stmt_check->fetch(PDO::FETCH_ASSOC);
            }

            if (!$listing || $listing['is_available'] == 0) {
                throw new Exception("هذا المنتج غير متاح للبيع من هذا التاجر حالياً.");
            }

            $merchant_id = $listing['merchant_id'];
            $global_product_id = $listing['global_product_id'];

            // تحديد الكمية المتاحة (للمنتج العادي أو للخيارات والمقاسات)
            $available_qty = (int)$listing['quantity'];
            $qty_type = $listing['quantity_type'];

            if ($size_id && !empty($listing['options'])) {
                $options = json_decode($listing['options'], true) ?: [];
                $found_opt = false;
                foreach ($options as $opt) {
                    if (isset($opt['id']) && $opt['id'] === $size_id) {
                        if (($opt['quantity_type'] ?? 'tracked') === 'tracked') {
                            $available_qty = (int)($opt['quantity'] ?? 0);
                            $qty_type = 'tracked';
                        } else {
                            $qty_type = 'unlimited';
                        }
                        $found_opt = true;
                        break;
                    }
                }
                if (!$found_opt) throw new Exception("المقاس أو الخيار المحدد غير موجود.");
            }

            // تحديث هيكل السلة إذا لم يكن محدثاً
            try { 
                $pdo->exec("ALTER TABLE `user_cart` ADD COLUMN `listing_id` VARCHAR(100) NULL AFTER `product_id`, ADD COLUMN `merchant_id` INT(11) NULL AFTER `user_id`"); 
                $pdo->exec("ALTER TABLE `user_cart` ADD UNIQUE KEY IF NOT EXISTS `customer_item_unique` (`customer_id`, `product_id`, `size_id`)");
            } catch (PDOException $e) {}

            $stmt_cart_qty = $pdo->prepare("SELECT quantity FROM user_cart WHERE customer_id = ? AND product_id = ? AND (size_id <=> ?)");
            $stmt_cart_qty->execute([$customer_id, $product_id, $size_id]);
            $current_cart_qty = (int)$stmt_cart_qty->fetchColumn();
            
            // الفحص الصارم للمخزون
            if ($qty_type === 'tracked' && ($current_cart_qty + $quantity) > $available_qty) {
                throw new Exception("عذراً، الكمية المطلوبة غير متوفرة في المخزون (المتاح فعلياً: $available_qty).");
            }

            $sql = "INSERT INTO user_cart (customer_id, product_id, listing_id, user_id, merchant_id, size_id, quantity) 
                    VALUES (?, ?, ?, ?, ?, ?, ?) 
                    ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)";
            
            $stmt_insert = $pdo->prepare($sql);
            $stmt_insert->execute([$customer_id, $global_product_id, $listing_id, $merchant_id, $merchant_id, $size_id, $quantity]);

            send_response('success',['message' => 'تمت الإضافة للسلة بنجاح']);
            break;

        case 'remove_from_cart_db':
            if (!$customer_id) send_response('error',[], 401);
            $pdo->prepare("DELETE FROM user_cart WHERE id = ? AND customer_id = ?")->execute([sanitize_input($input['cartId']), $customer_id]);
            send_response('success');
            break;
            
        case 'update_cart_qty_db':
            if (!$customer_id) send_response('error',[], 401);
            $pdo->prepare("UPDATE user_cart SET quantity = ? WHERE id = ? AND customer_id = ?")->execute([(int)$input['quantity'], sanitize_input($input['cartId']), $customer_id]);
            send_response('success');
            break;

        case 'toggle_favorite_db':
            if (!$customer_id) send_response('error',['message' => 'يجب تسجيل الدخول'], 401);
            $pid = sanitize_input($input['productId']);
            $check = $pdo->prepare("SELECT id FROM user_favorites WHERE customer_id = ? AND product_id = ?"); $check->execute([$customer_id, $pid]);
            if ($check->fetch()) {
                $pdo->prepare("DELETE FROM user_favorites WHERE customer_id = ? AND product_id = ?")->execute([$customer_id, $pid]);
                send_response('success',['action' => 'removed']);
            } else {
                $pdo->prepare("INSERT INTO user_favorites (customer_id, product_id) VALUES (?, ?)")->execute([$customer_id, $pid]);
                send_response('success',['action' => 'added']);
            }
            break;

        case 'create_order':
            // 🔒 معطّل عمداً: إنشاء الطلبات صار حصرياً عبر الـ Worker (D1).
            // هذا المسار القديم غير متزامن مع نظام المخزون/الطلبات الحالي، وتفعيله
            // مجدداً قد يُنشئ طلبات "يتيمة" لا يراها التاجر ولا الزبون بشكل صحيح.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            if (!$customer_id) {
                send_response('error', ['message' => 'يجب تسجيل الدخول أولاً لإتمام الطلب.'], 401);
            }
            
            // 1. نظام منع التكرار (Idempotency)
            $idempotency_key = sanitize_input($input['idempotency_key'] ?? '');
            if (!empty($idempotency_key)) {
                try {
                    $stmt_check_key = $pdo->prepare("SELECT response_data FROM idempotency_keys WHERE key_token = ?");
                    $stmt_check_key->execute([$idempotency_key]);
                    $existing_response = $stmt_check_key->fetchColumn();
                    
                    if ($existing_response !== false) {
                        if ($existing_response === 'processing') {
                            send_response('success', ['message' => 'طلبك قيد المعالجة حالياً، يرجى الانتظار...']);
                        }
                        $decoded_response = json_decode($existing_response, true);
                        send_response('success', $decoded_response ?: ['message' => 'تم استلام طلبك بنجاح (تأكيد مكرر).']);
                    }
                    $pdo->prepare("INSERT INTO idempotency_keys (key_token, response_data) VALUES (?, 'processing')")->execute([$idempotency_key]);
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) send_response('success', ['message' => 'تم استلام طلبك بنجاح (تم تجاهل الطلب المكرر).']);
                }
            }

            // 2. معالجة بيانات الزبون والموقع الجغرافي
            $allowed_customer_keys = ['name', 'address', 'gps'];
            $c_data = filter_allowed_keys($input['customer'] ?? [], $allowed_customer_keys);
            
            $raw_address = $c_data['address'] ?? '';
            $details_part = '';
            
            if (strpos($raw_address, '| التفاصيل:') !== false) {
                $parts = explode('| التفاصيل:', $raw_address);
                $details_part = isset($parts[1]) ? trim($parts[1]) : '';
            } else {
                $safe_gps_temp = sanitize_input($c_data['gps'] ?? '');
                $details_part = trim(str_replace('رابط الموقع: ' . $safe_gps_temp, '', $raw_address));
            }
            
            $details_part = strip_tags($details_part);
            if (mb_strlen($details_part, 'UTF-8') > 255) $details_part = mb_substr($details_part, 0, 252, 'UTF-8') . '...';
            $details_part = sanitize_input($details_part);

            $stmt_cust = $pdo->prepare("SELECT full_name, address, phone FROM customers WHERE id = ?");
            $stmt_cust->execute([$customer_id]);
            $cust_db = $stmt_cust->fetch(PDO::FETCH_ASSOC);

            $final_name = !empty($c_data['name']) ? sanitize_input($c_data['name']) : $cust_db['full_name'];
            $customer_gps_link = sanitize_input($c_data['gps'] ?? '');
            
            $final_address = "رابط الموقع: " . $customer_gps_link;
            if (!empty($details_part)) {
                $final_address .= " | التفاصيل: " . $details_part;
            } elseif (empty($customer_gps_link) && !empty($cust_db['address'])) {
                $final_address = $cust_db['address']; 
            }

            if (empty($final_name) || strpos($final_name, 'عميل') === 0) throw new Exception("يجب إدخال اسمك الحقيقي في حسابك أولاً لإتمام الطلب.");
            if (empty($final_address) || strpos($final_address, 'http') === false) throw new Exception("الرجاء تحديد عنوان التوصيل الدقيق على الخريطة وكتابة وصف للموقع 📍");
            
            $customer_coords = extract_coords_from_url($customer_gps_link);
            if (!$customer_coords) throw new Exception("الرجاء تحديد موقع دقيق على الخريطة لتتمكن من إتمام الطلب.");

            $dist_from_center = calculate_distance(ALLOWED_DELIVERY_CENTER_LAT, ALLOWED_DELIVERY_CENTER_LNG, $customer_coords['lat'], $customer_coords['lng']);
            if ($dist_from_center > MAX_ALLOWED_DELIVERY_RADIUS_KM) throw new Exception("عذراً، موقعك يقع خارج نطاق التغطية المسموح لخدمة التوصيل.");

            // 3. التحقق المبدئي من السلة
            $cart_items = $input['local_cart'] ?? [];
            if (!is_array($cart_items) || empty($cart_items)) throw new Exception('سلة المشتريات فارغة أو تم إرسال الطلب بالفعل!');

            $MIN_CART_VALUE = 1000; 
            $MAX_QTY_PER_ITEM = 50; 
            $MAX_TOTAL_QTY = 200;   

            $total_requested_qty = 0;
            $grouped_by_merchant = [];

            foreach ($cart_items as $c_item) {
                $qty = (int)$c_item['qty'];
                if ($qty <= 0) throw new Exception("الكمية المطلوبة لأحد المنتجات غير صالحة.");
                if ($qty > $MAX_QTY_PER_ITEM) throw new Exception("عذراً، لا يمكنك طلب أكثر من {$MAX_QTY_PER_ITEM} وحدة من نفس المنتج.");

                $total_requested_qty += $qty;
                
                $m_id = $c_item['merchant_id'] ?? $c_item['user_id'] ?? $c_item['merchant_username'] ?? null;
                if ($m_id === 'null' || $m_id === 'undefined' || $m_id === '') $m_id = null;

                // إذا السلة لم ترسل رقم التاجر، نسحبه فوراً من TiDB
                if (!$m_id) {
                    $product_id = $c_item['product_id'] ?? $c_item['listing_id'] ?? $c_item['id'] ?? null;
                    if ($product_id) {
                        $stmt_find_m = $pdo->prepare("SELECT merchant_id FROM products WHERE id = ?");
                        $stmt_find_m->execute([$product_id]);
                        $m_id = $stmt_find_m->fetchColumn();
                        
                        // الدعم العكسي من MySQL
                        if (!$m_id) {
                            $stmt_find_m = $pdo->prepare("SELECT merchant_id FROM merchant_listings WHERE global_product_id = ? OR id = ?");
                            $stmt_find_m->execute([$product_id, $product_id]);
                            $m_id = $stmt_find_m->fetchColumn();
                        }
                    }
                }

                if (!$m_id) {
                    throw new Exception("عذراً، المنتج '" . ($c_item['name'] ?? 'غير معروف') . "' لم يعد متاحاً. يرجى حذفه من السلة.");
                }

                $c_item['merchant_id'] = $m_id;
                $grouped_by_merchant[$m_id][] = $c_item;
            }

            if ($total_requested_qty > $MAX_TOTAL_QTY) throw new Exception("تجاوزت الحد الأقصى لإجمالي المنتجات المسموح بها في الطلب الواحد.");

            // 4. حساب رسوم التوصيل
            $total_delivery_fee = 1500; 
            $merchant_locations = [];
            $merchant_details = [];

            $raw_merchant_ids = array_keys($grouped_by_merchant);

            foreach ($raw_merchant_ids as $raw_m_id) {
                $stmt_merchant = $pdo->prepare("SELECT id, username, store_name, settings FROM users WHERE id = ? OR username = ?");
                $stmt_merchant->execute([$raw_m_id, $raw_m_id]);
                $m_info = $stmt_merchant->fetch(PDO::FETCH_ASSOC);
                
                if (!$m_info) {
                    throw new Exception("المتجر غير موجود أو غير متاح حالياً (المعرف: $raw_m_id). يرجى إزالة منتجاته من السلة.");
                }
                
                $actual_m_id = $m_info['id'];

                if ((string)$raw_m_id !== (string)$actual_m_id) {
                    $grouped_by_merchant[$actual_m_id] = $grouped_by_merchant[$raw_m_id];
                    unset($grouped_by_merchant[$raw_m_id]);
                }

                $merchant_details[$actual_m_id] = $m_info;
                $m_settings = json_decode($m_info['settings'] ?: '{}', true);
                $m_coords = extract_coords_from_url($m_settings['location'] ?? null);
                if ($m_coords) $merchant_locations[$actual_m_id] = $m_coords;
            }

            if ($customer_coords && count($merchant_locations) > 0) {
                $route_distance = 0;
                $locations = array_values($merchant_locations);
                for ($i = 0; $i < count($locations) - 1; $i++) {
                    $route_distance += calculate_distance($locations[$i]['lat'], $locations[$i]['lng'], $locations[$i+1]['lat'], $locations[$i+1]['lng']);
                }
                $last_merchant = end($locations);
                $route_distance += calculate_distance($last_merchant['lat'], $last_merchant['lng'], $customer_coords['lat'], $customer_coords['lng']);
                
                $calculated_base_fee = calculate_delivery_fee($route_distance);
                $total_delivery_fee = $calculated_base_fee + ((count($grouped_by_merchant) - 1) * 300);
            } else {
                $total_delivery_fee = 1500 + ((count($grouped_by_merchant) - 1) * 500);
            }

            $fee_per_order = count($grouped_by_merchant) > 0 ? ceil(($total_delivery_fee / count($grouped_by_merchant)) / 50) * 50 : $total_delivery_fee;

            $prepared_sub_orders = [];
            $overall_cart_total = 0;

            // ========================================================
            // 5. التحقق الصارم من الأسعار والمخزون عبر TiDB Cloud (PDO)
            // ========================================================
            foreach ($grouped_by_merchant as $merchant_id => $items) {
                $m_info = $merchant_details[$merchant_id];
                $m_settings = json_decode($m_info['settings'] ?: '{}', true);
                
                $product_ids = array_map(function($i) { return $i['product_id'] ?? $i['listing_id'] ?? $i['id']; }, $items);
                $product_ids = array_filter(array_values($product_ids)); // إزالة القيم الفارغة
                if (empty($product_ids)) continue; // تجاهل التاجر إذا لم توجد منتجات صالحة
                $placeholders = implode(',', array_fill(0, count($product_ids), '?'));
                $params = array_merge([$merchant_id], $product_ids);

                $d1_products = [];

                // 1. جلب المنتجات مباشرة من جدول المنتجات الأساسي في TiDB
                $stmt_p = $pdo->prepare("SELECT * FROM products WHERE merchant_id = ? AND id IN ($placeholders)");
                $stmt_p->execute($params);
                $d1_results = $stmt_p->fetchAll(PDO::FETCH_ASSOC);
                foreach($d1_results as $row) {
                    $row['options'] = json_decode($row['options'] ?? '[]', true) ?: [];
                    $d1_products[$row['id']] = $row;
                }

                // 2. الدعم العكسي للمنتجات التي ما زالت في نظام listings القديم
               $pdo_sql = "
    SELECT p.id as global_product_id, p.name, p.image, p.options, p.discount, p.cost_price, 
           l.id as listing_id, l.merchant_price as price, l.quantity, l.quantity_type, l.currency, l.is_available 
    FROM merchant_listings l 
    JOIN products p ON l.global_product_id = p.id 
    WHERE l.merchant_id = ? AND (l.id IN ($placeholders) OR p.id IN ($placeholders))
";
                $stmt_pdo = $pdo->prepare($pdo_sql);
                $params_pdo = array_merge([$merchant_id], $product_ids, $product_ids);
                $stmt_pdo->execute($params_pdo);
                $pdo_results = $stmt_pdo->fetchAll(PDO::FETCH_ASSOC);

                foreach($pdo_results as $row) {
                    $pid = $row['global_product_id'];
                    $lid = $row['listing_id'];
                    
                    $row['id'] = $pid; 
                    $row['options'] = json_decode($row['options'] ?? '[]', true) ?: [];
                    
                    if (!isset($d1_products[$pid])) $d1_products[$pid] = $row;
                    if (!isset($d1_products[$lid])) $d1_products[$lid] = $row;
                }
                
                $order_items_array = [];
                $total_products_price = 0;
                $currency = 'YER';
                $merchant_item_count = 0;

                foreach ($items as $item) {
                    $product_id = $item['product_id'] ?? $item['listing_id'] ?? $item['id'];
                    
                    if (!isset($d1_products[$product_id])) {
                        $err_msg = "المنتج '{$item['name']}' نفد أو تم حذفه من متجر {$m_info['store_name']}.";
                        throw new Exception($err_msg);
                    }
                    
                    $product = $d1_products[$product_id];
                    if ($product['is_available'] == 0) {
                        throw new Exception("المنتج '{$product['name']}' غير متاح حالياً للطلب.");
                    }

                    $currency = $product['currency'] ?? 'YER';
                    $qty = (int)$item['qty'];
                    $merchant_item_count += $qty;

                    $available_qty = (int)($product['quantity'] ?? 0);
                    $qty_type = $product['quantity_type'] ?? 'tracked';
                    $item_option_id = $item['size_id'] ?? null;
                    $option_info = null;
                    $item_image = $product['image'];
                    $base_price = (float)$product['price']; 

                    // معالجة الخيارات (Sizes/Colors)
                    if ($item_option_id && !empty($product['options'])) {
                        $found_opt = false;
                        foreach ($product['options'] as $opt) {
                            if (isset($opt['id']) && $opt['id'] === $item_option_id) {
                                $option_info = $opt['name'] ?? null;
                                if (isset($opt['custom_price']) && $opt['custom_price'] !== null && $opt['custom_price'] !== '') {
                                    $base_price = (float)$opt['custom_price'];
                                }
                                if ($opt['quantity_type'] === 'tracked') {
                                    $available_qty = (int)$opt['quantity'];
                                    $qty_type = 'tracked';
                                } else {
                                    $qty_type = 'unlimited';
                                }
                                if (!empty($opt['image'])) $item_image = $opt['image'];
                                $found_opt = true;
                                break;
                            }
                        }
                        if (!$found_opt) throw new Exception("الخيار المختار للمنتج '{$product['name']}' لم يعد متوفراً.");
                    }

                    if ($qty_type === 'tracked' && $available_qty < $qty) {
                        throw new Exception("عذراً، الكمية المطلوبة من '{$product['name']}' غير كافية بالمخزون (المتاح: {$available_qty}).");
                    }

                    $final_secure_price = $base_price * (1 - ((float)($product['discount'] ?? 0) / 100));
                    $total_products_price += ($final_secure_price * $qty);
                    
                    $order_items_array[] = [
                        'product_id' => $product['id'],
                        'listing_id' => $product['id'],
                        'size_id' => $item_option_id,
                        'product_name' => $product['name'],
                        'size_info' => $option_info,
                        'quantity' => $qty,
                        'price' => $final_secure_price,
                        'cost_price' => $product['cost_price'] ?? 0,
                        'image' => $item_image,
                        'qty_type' => $qty_type,
                        'current_db_qty' => $available_qty,
                        'options_raw' => $product['options'] ?? []
                    ];
                }

                $overall_cart_total += $total_products_price;

                // حساب التوصيل المجاني إن وجد
                $actual_delivery_fee = $fee_per_order;
                if (isset($m_settings['free_shipping_enabled']) && ($m_settings['free_shipping_enabled'] === true || $m_settings['free_shipping_enabled'] === 'true')) {
                    $f_type = $m_settings['free_shipping_type'] ?? 'always';
                    $f_thresh = (float)($m_settings['free_shipping_threshold'] ?? 0);
                    
                    if ($f_type === 'always') $actual_delivery_fee = 0;
                    elseif ($f_type === 'order_value' && $total_products_price >= $f_thresh) $actual_delivery_fee = 0;
                    elseif ($f_type === 'item_count' && $merchant_item_count >= $f_thresh) $actual_delivery_fee = 0;
                }

                $grand_total = ($currency === 'YER') ? ($total_products_price + $actual_delivery_fee) : $total_products_price;

                $prepared_sub_orders[$merchant_id] = [
                    'merchant_info' => $m_info,
                    'financials' => [
                        'products_total' => $total_products_price,
                        'delivery_fee' => $actual_delivery_fee,
                        'grand_total' => $grand_total,
                        'currency' => $currency,
                        'delivery_currency' => 'YER'
                    ],
                    'items' => $order_items_array
                ];
            }

            if ($overall_cart_total < $MIN_CART_VALUE) {
                throw new Exception("عذراً، الحد الأدنى لإتمام الطلب هو {$MIN_CART_VALUE}. قيمة منتجاتك الحالية: " . number_format($overall_cart_total) . ".");
            }

            $new_order_group_id = 'GRP-' . generate_uuid();
            $is_order_merged = false;
            $created_tickets = [];

            // ========================================================
            // 6. إنشاء الطلب في (TiDB)
            // ========================================================
            try {
                $pdo->beginTransaction();

                $pdo->prepare("UPDATE customers SET full_name = ?, address = ? WHERE id = ?")
                    ->execute([$final_name, $final_address, $customer_id]);

                foreach ($prepared_sub_orders as $merchant_id => $sub_order) {
                    $m_info = $sub_order['merchant_info'];
                    $m_username = $m_info['username'];
                    
                    // البحث عن طلب معلق سابق لنفس التاجر لدمجه
                    $stmt_check_pending = $pdo->prepare(
                        "SELECT ticket_id, ticket_data, status 
                         FROM live_tickets 
                         WHERE customer_id = ? AND merchant_id = ? 
                         AND status IN ('pending_merchant_approval', 'pending_delivery_acceptance') 
                         AND delivery_agent_id IS NULL 
                         FOR UPDATE"
                    );
                    $stmt_check_pending->execute([$customer_id, $merchant_id]);
                    $existing_ticket = $stmt_check_pending->fetch(PDO::FETCH_ASSOC);

                    if ($existing_ticket) {
                        $existing_data = json_decode($existing_ticket['ticket_data'], true) ?: [];
                        $old_items = $existing_data['items'] ?? [];

                        foreach ($sub_order['items'] as $new_item) {
                            $found = false;
                            foreach ($old_items as &$o_item) {
                                if ((string)$o_item['product_id'] === (string)$new_item['product_id'] && (string)($o_item['size_id'] ?? '') === (string)($new_item['size_id'] ?? '')) {
                                    $o_item['quantity'] += $new_item['quantity'];
                                    $found = true;
                                    break;
                                }
                            }
                            unset($o_item);
                            if (!$found) {
                                $clean_new_item = $new_item;
                                unset($clean_new_item['qty_type'], $clean_new_item['current_db_qty'], $clean_new_item['options_raw']);
                                $old_items[] = $clean_new_item;
                            }
                        }

                        $existing_data['items'] = $old_items;
                        $existing_data['financials']['products_total'] += $sub_order['financials']['products_total'];
                        if ($sub_order['financials']['currency'] === 'YER') {
                            $existing_data['financials']['grand_total'] = $existing_data['financials']['products_total'] + $existing_data['financials']['delivery_fee'];
                        } else {
                            $existing_data['financials']['grand_total'] = $existing_data['financials']['products_total'];
                        }

                        $ticket_id = $existing_ticket['ticket_id'];
                        $json_data = json_encode($existing_data, JSON_UNESCAPED_UNICODE);
                        
                        $pdo->prepare("UPDATE live_tickets SET ticket_data = ? WHERE ticket_id = ?")->execute([$json_data, $ticket_id]);
                        $is_order_merged = true;
                        
                        $created_tickets[] = [
                            'ticket_id' => $ticket_id,
                            'merchant_id' => $merchant_id,
                            'merchant_username' => $m_username,
                            'status' => $existing_ticket['status'],
                            'ticket_data' => $existing_data,
                            'original_items_to_deduct' => $sub_order['items']
                        ];

                    } else {
                        $delivery_code = rand(1000, 9999);
                        $ticket_id = 'TCK-' . generate_uuid();
                        $final_status = 'pending_merchant_approval';

                        $clean_items_list = [];
                        foreach ($sub_order['items'] as $it) {
                            $clean_it = $it;
                            unset($clean_it['qty_type'], $clean_it['current_db_qty'], $clean_it['options_raw']);
                            $clean_items_list[] = $clean_it;
                        }

                        $ticket_payload = [
                            'customer' => [
                                'id' => $customer_id,
                                'name' => $final_name,
                                'phone' => $cust_db['phone'] ?? '',
                                'address_text' => $final_address,
                                'gps_link' => $customer_gps_link
                            ],
                            'merchant' => [
                                'id' => $merchant_id,
                                'name' => $m_info['store_name'] ?: 'المتجر'
                            ],
                            'financials' => $sub_order['financials'],
                            'items' => $clean_items_list,
                            'order_group_id' => $new_order_group_id
                        ];

                        $json_data = json_encode($ticket_payload, JSON_UNESCAPED_UNICODE);

                        $stmt = $pdo->prepare("INSERT INTO live_tickets (ticket_id, order_group_id, merchant_id, customer_id, status, delivery_code, ticket_data) VALUES (?, ?, ?, ?, ?, ?, ?)");
                        $stmt->execute([$ticket_id, $new_order_group_id, $merchant_id, $customer_id, $final_status, $delivery_code, $json_data]);

                        $created_tickets[] = [
                            'ticket_id' => $ticket_id,
                            'merchant_id' => $merchant_id,
                            'merchant_username' => $m_username,
                            'status' => $final_status,
                            'ticket_data' => $ticket_payload,
                            'original_items_to_deduct' => $sub_order['items']
                        ];
                    }
                }

                $pdo->prepare("DELETE FROM user_cart WHERE customer_id = ?")->execute([$customer_id]);
                
                $pdo->commit();
            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $e;
            }
    
            // ========================================================
            // 7. خصم المخزون من TiDB وإرسال الطلبات لـ Firebase (Post-Processing)
            // ========================================================
            foreach ($created_tickets as $tick) {
                $m_username = $tick['merchant_username'];
                $m_id = $tick['merchant_id'];
                
                try {
                    $fb_products_update = [];
                    try {
                        // جلب كاش المنتجات الحالي من GitHub (عبر raw.githubusercontent.com)
                        $fb_products_update = kv_request("stores/$m_username/products") ?: []; 
                    } catch (Exception $kv_err) {
                        error_log("Ignored GitHub fetch error: " . $kv_err->getMessage());
                    }
                    
                    $needs_github_sync = false; 

                    foreach ($tick['original_items_to_deduct'] as $item) {
                        $pid = $item['product_id'];
                        
                        if ($item['qty_type'] === 'tracked') {
                            if ($item['size_id']) {
                                // معالجة الخيارات المتعددة JSON
                                $options_array = $item['options_raw'];
                                $total_remaining_qty = 0;
                                
                                foreach ($options_array as &$opt) {
                                    if (isset($opt['id']) && $opt['id'] === $item['size_id']) {
                                        $opt['quantity'] = max(0, $opt['quantity'] - $item['quantity']);
                                    }
                                    $total_remaining_qty += (int)($opt['quantity'] ?? 0);
                                }
                                unset($opt);
                                
                                $opts_json = json_encode($options_array, JSON_UNESCAPED_UNICODE);
                                
                                // تحديث TiDB للخيارات
                                $stmt_deduct = $pdo->prepare("UPDATE products SET quantity = ?, options = ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                                $stmt_deduct->execute([$total_remaining_qty, $opts_json, time(), $pid, $m_id]);
                                    
                                // تجهيز بيانات المزامنة    
                                if(isset($fb_products_update[$pid])) {
                                    $fb_products_update[$pid]['quantity'] = $total_remaining_qty;
                                    $fb_products_update[$pid]['options'] = $options_array;

                                    if ($total_remaining_qty <= 0) {
                                        unset($fb_products_update[$pid]);
                                        $needs_github_sync = true;
                                    }
                                }
                            } else {
                                // تحديث TiDB للمنتج العادي
                                $stmt_deduct = $pdo->prepare("UPDATE products SET quantity = quantity - ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                                $stmt_deduct->execute([$item['quantity'], time(), $pid, $m_id]);
                                    
                                if(isset($fb_products_update[$pid])) {
                                    $new_qty = max(0, $item['current_db_qty'] - $item['quantity']);
                                    $fb_products_update[$pid]['quantity'] = $new_qty;

                                    if ($new_qty <= 0) {
                                        unset($fb_products_update[$pid]);
                                        $needs_github_sync = true;
                                    }
                                }
                            }
                        }
                    }

                    // مزامنة الكاش لـ GitHub في حال نفاد المخزون
                    if ($needs_github_sync) {
                        try {
                            kv_request("stores/$m_username/products", 'PUT', $fb_products_update);
                            if (function_exists('build_and_sync_split_json')) {
                                build_and_sync_split_json($m_username, $fb_products_update);
                            }
                        } catch (Exception $sync_err) {
                            error_log("GitHub cache sync failed: " . $sync_err->getMessage());
                        }
                    }
                } catch (Exception $inventory_err) {
                    error_log("Inventory update failed: " . $inventory_err->getMessage());
                }

                // [ب] دفع الطلب إلى Firebase
                // [ب] إرسال إشارة (Signal) لفايربيس لتنبيه التاجر بتحديث الطلبات
                try {
                    sync_to_firebase($m_username, "signals/orders_updated", null, time(), 'PUT');
                } catch (Exception $fb_err) {
                    error_log("Firebase signal sync failed: " . $fb_err->getMessage());
                }
                
                // [ج] إرسال الإشعارات الفورية
                try {
                    $stmt_m_info = $pdo->prepare("SELECT phone, store_name, settings FROM users WHERE id = ?");
                    $stmt_m_info->execute([$m_id]);
                    $m_info_db = $stmt_m_info->fetch(PDO::FETCH_ASSOC);
                    
                    if ($m_info_db) {
                        $m_settings = json_decode($m_info_db['settings'] ?? '{}', true);
                        if (isset($m_settings['push_notifications']) && ($m_settings['push_notifications'] === true || $m_settings['push_notifications'] === 'true')) {
                            $m_phone = preg_replace('/[^0-9]/', '', $m_info_db['phone']);
                            if (strpos($m_phone, '967') === 0 && strlen($m_phone) >= 12) $m_phone = substr($m_phone, 3);
                            elseif (strpos($m_phone, '00967') === 0) $m_phone = substr($m_phone, 5);
                            elseif (strpos($m_phone, '0') === 0 && strlen($m_phone) == 10) $m_phone = substr($m_phone, 1);
                            
                            $msg_alert = "🛍️ طلب جديد!\nمرحباً متجر {$m_info_db['store_name']}،\nلديك طلب جديد بانتظار الموافقة والتجهيز.\nرقم الطلب: " . substr($tick['ticket_id'], 0, 8);
                            send_via_macrodroid($m_phone, $msg_alert);
                        }
                    }
                } catch (Exception $notif_err) {
                    error_log("Notification dispatch failed: " . $notif_err->getMessage());
                }
            }

            // 9. الاستجابة النهائية للزبون
            $success_msg = $is_order_merged ? 'تم دمج المنتجات الجديدة لطلبك السابق بنجاح! 🛍️' : 'تم استلام طلبك وبانتظار موافقة التاجر لتجهيزه!';
            $response_data = ['message' => $success_msg];

            if (!empty($idempotency_key)) {
                $pdo->prepare("UPDATE idempotency_keys SET response_data = ? WHERE key_token = ?")
                    ->execute([json_encode($response_data, JSON_UNESCAPED_UNICODE), $idempotency_key]);
            }

            foreach ($created_tickets as $tick) {
                $stmt_get_token = $pdo->prepare("SELECT fcm_token FROM users WHERE id = ?");
                $stmt_get_token->execute([$tick['merchant_id']]);
                $merchant_fcm_token = $stmt_get_token->fetchColumn();

                if ($merchant_fcm_token) {
                    send_silent_push_to_merchant($merchant_fcm_token, $tick['ticket_id']);
                }
            }
            
            send_response('success', $response_data);
            break;

        case 'get_orders':
            // 🔒 معطّل عمداً: قراءة الطلبات (نشطة/مؤرشفة) صارت حصرياً عبر الـ Worker (D1).
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            if (!$user_id) send_response('error',['message' => 'غير مصرح لك بالوصول'], 401);
            $filter = sanitize_input($input['filter'] ?? 'active'); 
            
            $orders = []; 
            $m_id = intval($user_id);

            try {
                if ($filter === 'active') { 
                    $sql = "SELECT ticket_id as id, order_group_id, status, created_at, delivery_code, delivery_agent_id, ticket_data 
                            FROM live_tickets WHERE merchant_id = ? ORDER BY created_at DESC";
                    $stmt = $pdo->prepare($sql); 
                    $stmt->execute([$m_id]); 
                    $tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    foreach ($tickets as $t) {
                        $data = json_decode($t['ticket_data'], true);
                        if (!is_array($data)) continue; 

                        $fin = $data['financials'] ?? [];
                        $cust = $data['customer'] ?? [];
                        $merch = $data['merchant'] ?? [];
                        $agent = $data['delivery_agent'] ?? [];

                        $orders[] = [
                            'id' => $t['id'],
                            'order_group_id' => $t['order_group_id'],
                            'total_amount' => $fin['grand_total'] ?? 0,
                            'currency' => $fin['currency'] ?? 'YER',
                            'delivery_fee' => $fin['delivery_fee'] ?? 0,
                            'delivery_address_text' => $cust['address_text'] ?? 'عنوان غير محدد',
                            'delivery_gps_link' => $cust['gps_link'] ?? '',
                            'status' => $t['status'],
                            'created_at' => $t['created_at'],
                            'delivery_code' => $t['delivery_code'] ?? '',
                            'customer_name' => $cust['name'] ?? 'عميل',
                            'customer_phone' => $cust['phone'] ?? '',
                            'items' => $data['items'] ?? [],
                            'is_agent_assigned' => ($t['delivery_agent_id'] !== null)
                        ];
                    }
                } else { 
                    $sql = "SELECT ticket_id as id, final_status as status, archived_at as created_at, archived_data, total_amount 
                            FROM orders_archive WHERE merchant_id = ? ORDER BY archived_at DESC";
                    $stmt = $pdo->prepare($sql); 
                    $stmt->execute([$m_id]); 
                    $archives = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    foreach ($archives as $arc) {
                        $data = json_decode($arc['archived_data'], true);
                        if (!is_array($data)) continue;
                        
                        $fin = $data['financials'] ?? [];
                        $cust = $data['customer'] ?? [];

                        $orders[] = [
                            'id' => $arc['id'],
                            'total_amount' => $arc['total_amount'],
                            'status' => $arc['status'],
                            'created_at' => $arc['created_at'],
                            'customer_name' => $cust['name'] ?? 'عميل',
                            'items' => $data['items'] ?? []
                        ];
                    }
                }
                send_response('success',['data' => $orders]);
            } catch (Exception $e) {
                send_response('error',['message' => 'حدث خطأ أثناء جلب البيانات: ' . $e->getMessage()]);
            }
            break;     

        case 'get_user_orders':
            if (!$customer_id) send_response('error',[], 401);
            
            $grouped_orders = [];
            $processed_ticket_ids = []; 

            try {
                $sql_live = "SELECT ticket_id as id, order_group_id, merchant_id, status, created_at, delivery_code, delivery_agent_id, ticket_data 
                             FROM live_tickets WHERE customer_id = ? ORDER BY created_at DESC";
                $stmt_live = $pdo->prepare($sql_live);
                $stmt_live->execute([$customer_id]);
                $live_tickets = $stmt_live->fetchAll(PDO::FETCH_ASSOC);

                foreach ($live_tickets as $t) {
                    $processed_ticket_ids[] = $t['id'];
                    $data = json_decode($t['ticket_data'], true);
                    if (!is_array($data)) $data = [];
                    
                    $fin = isset($data['financials']) && is_array($data['financials']) ? $data['financials'] : [];
                    $cust = isset($data['customer']) && is_array($data['customer']) ? $data['customer'] : [];
                    $merch = isset($data['merchant']) && is_array($data['merchant']) ? $data['merchant'] : [];
                    
                    $agent_name = null; $agent_phone = null; $is_private = false;
                    if (!empty($t['delivery_agent_id'])) {
                        $stmt_agent = $pdo->prepare("SELECT store_name, username, phone, employer_id FROM users WHERE id = ?");
                        $stmt_agent->execute([$t['delivery_agent_id']]);
                        $agent = $stmt_agent->fetch(PDO::FETCH_ASSOC);
                        if ($agent) {
                            $agent_name = !empty($agent['store_name']) ? $agent['store_name'] : $agent['username'];
                            $agent_phone = $agent['phone'] ?? null;
                            $is_private = !empty($agent['employer_id']);
                        }
                    }

                    $order = [
                        'id' => $t['id'] ?? 'Unknown',
                        'order_group_id' => $t['order_group_id'] ?? 'Unknown',
                        'total_amount' => $fin['grand_total'] ?? 0,
                        'currency' => $fin['currency'] ?? 'YER',
                        'delivery_fee' => $fin['delivery_fee'] ?? 0,
                        'delivery_address_text' => $cust['address_text'] ?? 'عنوان غير محدد',
                        'status' => $t['status'] ?? 'pending',
                        'created_at' => $t['created_at'] ?? date('Y-m-d H:i:s'),
                        'delivery_code' => $t['delivery_code'] ?? null,
                        'cancel_reason' => null,
                        'merchant_id' => $t['merchant_id'] ?? $merch['id'] ?? null, 
                        'merchant_name' => $merch['name'] ?? 'متجر',
                        'customer_phone' => $cust['phone'] ?? '',
                        'delivery_agent_name' => $agent_name,
                        'delivery_agent_phone' => $agent_phone,
                        'is_private_agent' => $is_private,
                        'items' => isset($data['items']) && is_array($data['items']) ? array_values($data['items']) : [] 
                    ];

                    $group_id = $t['order_group_id'] ?? $t['id'];
                    if (!isset($grouped_orders[$group_id])) { 
                        $grouped_orders[$group_id] = ['group_id' => $group_id, 'created_at' => $t['created_at'], 'sub_orders' => []]; 
                    }
                    $grouped_orders[$group_id]['sub_orders'][] = $order;
                }

                $sql_archive = "SELECT ticket_id as id, merchant_id, final_status as status, archived_at as created_at, archived_data, total_amount 
                                FROM orders_archive WHERE customer_id = ? ORDER BY archived_at DESC";
                $stmt_archive = $pdo->prepare($sql_archive);
                $stmt_archive->execute([$customer_id]);
                $archive_tickets = $stmt_archive->fetchAll(PDO::FETCH_ASSOC);

                foreach ($archive_tickets as $arc) {
                    $processed_ticket_ids[] = $arc['id'];
                    $data = json_decode($arc['archived_data'], true);
                    if (!is_array($data)) $data = [];

                    $fin = isset($data['financials']) && is_array($data['financials']) ? $data['financials'] : [];
                    $cust = isset($data['customer']) && is_array($data['customer']) ? $data['customer'] : [];
                    $merch = isset($data['merchant']) && is_array($data['merchant']) ? $data['merchant'] : [];
                    $agent = isset($data['delivery_agent']) && is_array($data['delivery_agent']) ? $data['delivery_agent'] : [];
                    
                    $group_id = $data['order_group_id'] ?? $arc['id']; 

                    $order = [
                        'id' => $arc['id'] ?? 'Unknown',
                        'order_group_id' => $group_id,
                        'total_amount' => $arc['total_amount'] ?? 0,
                        'currency' => $fin['currency'] ?? 'YER',
                        'delivery_fee' => $fin['delivery_fee'] ?? 0,
                        'delivery_address_text' => $cust['address_text'] ?? '',
                        'status' => $arc['status'] ?? 'completed',
                        'created_at' => $arc['created_at'] ?? date('Y-m-d H:i:s'),
                        'delivery_code' => null,
                        'cancel_reason' => null,
                        'merchant_id' => $arc['merchant_id'] ?? $merch['id'] ?? null, 
                        'merchant_name' => $merch['name'] ?? 'متجر',
                        'customer_phone' => $cust['phone'] ?? '',
                        'delivery_agent_name' => $agent['name'] ?? null,
                        'delivery_agent_phone' => null,
                        'is_private_agent' => false,
                        'items' => isset($data['items']) && is_array($data['items']) ? array_values($data['items']) : []
                    ];

                    if (!isset($grouped_orders[$group_id])) { 
                        $grouped_orders[$group_id] = ['group_id' => $group_id, 'created_at' => $arc['created_at'], 'sub_orders' => []]; 
                    }
                    $grouped_orders[$group_id]['sub_orders'][] = $order;
                }

                try {
                    $sql_legacy = "
                        SELECT o.id, o.merchant_id, o.total_amount, o.currency, o.delivery_fee, o.delivery_address_text, o.status, o.created_at, o.delivery_code, o.cancel_reason, c.phone as customer_phone, m.store_name as merchant_name, da.store_name as delivery_agent_name, da.phone as delivery_agent_phone, da.employer_id as agent_employer_id
                        FROM orders o
                        LEFT JOIN users m ON o.merchant_id = m.id
                        LEFT JOIN customers c ON o.customer_id = c.id
                        LEFT JOIN users da ON o.delivery_agent_id = da.id
                        WHERE o.customer_id = ? ORDER BY o.created_at DESC
                    ";
                    $stmt_legacy = $pdo->prepare($sql_legacy);
                    $stmt_legacy->execute([$customer_id]);
                    $legacy_orders = $stmt_legacy->fetchAll(PDO::FETCH_ASSOC);

                    foreach($legacy_orders as $lo) {
                        $legacy_ticket_id = 'LEGACY-' . $lo['id'];
                        if (in_array($legacy_ticket_id, $processed_ticket_ids)) continue;

                        $items_stmt = $pdo->prepare("SELECT oi.product_id, oi.quantity, oi.price, oi.size_id, p.name as product_name, p.image, s.name as size_info FROM order_items oi JOIN products p ON oi.product_id = p.id LEFT JOIN product_sizes s ON oi.size_id = s.id WHERE oi.order_id = ?");
                        $items_stmt->execute([$lo['id']]);
                        $legacy_items = $items_stmt->fetchAll(PDO::FETCH_ASSOC);

                        $order = [
                            'id' => $legacy_ticket_id,
                            'order_group_id' => $legacy_ticket_id,
                            'total_amount' => $lo['total_amount'] ?? 0,
                            'currency' => $lo['currency'] ?? 'YER',
                            'delivery_fee' => $lo['delivery_fee'] ?? 0,
                            'delivery_address_text' => $lo['delivery_address_text'] ?? '',
                            'status' => $lo['status'] ?? 'pending',
                            'created_at' => $lo['created_at'] ?? '',
                            'delivery_code' => $lo['delivery_code'] ?? null,
                            'cancel_reason' => $lo['cancel_reason'] ?? null,
                            'merchant_id' => $lo['merchant_id'] ?? null, 
                            'merchant_name' => $lo['merchant_name'] ?? 'متجر',
                            'customer_phone' => $lo['customer_phone'] ?? '',
                            'delivery_agent_name' => $lo['delivery_agent_name'] ?? null,
                            'delivery_agent_phone' => $lo['delivery_agent_phone'] ?? null,
                            'is_private_agent' => !empty($lo['agent_employer_id']),
                            'items' => $legacy_items
                        ];

                        if (!isset($grouped_orders[$legacy_ticket_id])) { 
                            $grouped_orders[$legacy_ticket_id] = ['group_id' => $legacy_ticket_id, 'created_at' => $lo['created_at'], 'sub_orders' => []]; 
                        }
                        $grouped_orders[$legacy_ticket_id]['sub_orders'][] = $order;
                    }
                } catch (Exception $e) {}

                $final_groups = array_values($grouped_orders);
                usort($final_groups, function($a, $b) {
                    return strtotime($b['created_at']) - strtotime($a['created_at']);
                });

                send_response('success', ['data' => $final_groups]);

            } catch (Exception $e) {
                error_log("API Error in get_user_orders: " . $e->getMessage());
                send_response('success', ['data' => []]); 
            }
            break;

        case 'generate_user_otp':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $customer_id_for_otp = sanitize_input($input['customer_id']);
            $otp = generate_secure_otp();
            try { $pdo->exec("ALTER TABLE customers ADD COLUMN otp_code VARCHAR(64) NULL AFTER phone"); } catch (Exception $e) { }
            $pdo->prepare("UPDATE customers SET otp_code = ? WHERE id = ?")->execute([hash_otp($otp), $customer_id_for_otp]);
            $stmt = $pdo->prepare("SELECT phone, full_name FROM customers WHERE id = ?"); $stmt->execute([$customer_id_for_otp]); $cust = $stmt->fetch(PDO::FETCH_ASSOC);
            $phone = preg_replace('/[^0-9]/', '', $cust['phone']);
            if (strpos($phone, '967') === 0 && strlen($phone) >= 12) $phone = substr($phone, 3);
            elseif (strpos($phone, '00967') === 0) $phone = substr($phone, 5);
            elseif (strpos($phone, '0') === 0 && strlen($phone) == 10) $phone = substr($phone, 1);
            $message = "مرحباً {$cust['full_name']}\nكود التفعيل الخاص بك هو: {$otp}\nلا تشاركه مع أحد.";
            $sms_sent = send_via_macrodroid($phone, $message);
            $smsMsg = $sms_sent ? "، جاري إرسال الـ SMS من هاتفك" : "، (ملاحظة: يبدو أن سيرفر الإرسال/الجوال متوقف، لن يتم إرسال SMS)";
            send_response('success',['message' => 'تم توليد الكود' . $smsMsg, 'otp' => $otp, 'phone' => $phone, 'name' => $cust['full_name']]);
            break;

        case 'check_phone':
            $identifier = sanitize_input($input['phone'] ?? ''); 
            $is_phone = (bool)preg_match('/^[0-9]+$/', $identifier);

            if ($is_phone) {
                if (strlen($identifier) < 9) throw new Exception("رقم الهاتف غير صحيح.");
                $stmt = $pdo->prepare("SELECT id, username, store_name, role FROM users WHERE phone = ? AND role IN ('merchant', 'delivery')");
                $stmt->execute([$identifier]);
            } else {
                $stmt = $pdo->prepare("SELECT id, username, store_name, role FROM users WHERE username = ? AND role IN ('merchant', 'delivery')");
                $stmt->execute([$identifier]);
            }
            
            $accounts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
            if (count($accounts) === 0) {
                send_response('user_not_found');
            } elseif (count($accounts) === 1) {
                $account = $accounts[0];
                $original_name = $account['store_name'] ?: $account['username'];
                $masked_name = $original_name;
                if (mb_strlen($original_name) > 4) {
                    $masked_name = mb_substr($original_name, 0, 2) . '...' . mb_substr($original_name, -2);
                }
                
                $can_add_role = null;
                if ($is_phone) {
                     $can_add_role = ($account['role'] === 'merchant') ? 'delivery' : 'merchant';
                }
               
                send_response('user_found',['name' => $masked_name, 'can_add_role' => $can_add_role]);
            } else {
                $accounts_by_role =[];
                foreach ($accounts as $acc) {
                    $accounts_by_role[$acc['role']] =['name' => $acc['store_name'] ?: $acc['username']];
                }
                send_response('multiple_users_found',['accounts' => $accounts_by_role]);
            }
            break;
                                    
        case 'select_role':
            $user_id_to_login = $input['user_id'] ?? null;
            $allowed_accounts = $_SESSION['login_selection_data'] ??[];
            $user_to_login = null;

            foreach($allowed_accounts as $role_data){
                if($role_data['id'] == $user_id_to_login){
                    $user_to_login = $role_data;
                    break;
                }
            }
            if (!$user_to_login) throw new Exception("طلب غير صالح.");

            $stmt = $pdo->prepare("SELECT id, username, store_name, role, is_active FROM users WHERE id = ?");
            $stmt->execute([$user_id_to_login]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
            if (!$user || !$user['is_active']) throw new Exception("الحساب غير موجود أو غير نشط.");
        
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['store_name'] = $user['store_name'];
            $_SESSION['loggedin'] = true;
            $_SESSION['role'] = $user['role'];
            $_SESSION['device_token'] = $_COOKIE['device_token'] ?? '';
            unset($_SESSION['login_selection_data']);
            
            $payload =['user_id' => $user['id'], 'username' => $user['username'], 'store_name' => $user['store_name'], 'role' => $user['role'], 'device_token' => $_COOKIE['device_token'] ?? ''];
            // APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة
            $token = generate_signed_token($payload, 480);
            
            $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.php' : 'delivery-dashboard.php';
            // ⭐ تصحيح (2026-07-21): نفس تصحيح مزامنة العميل — نزامن التاجر إلى D1
            // *قبل* إرسال الرد، لأن send_response_and_continue_in_background تعتمد
            // على fastcgi_finish_request غير المضمونة على منصات مثل Render، وهذا
            // كان يمنع مزامنة أي تاجر إطلاقاً حتى الآن.
            sync_user_to_worker($pdo, $user['id']);
            send_response('success', ['token' => $token, 'redirect' => $redirect]);

        case 'login':
            try { $pdo->exec("ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0 AFTER password"); } catch (Exception $e) {}
            try { $pdo->exec("ALTER TABLE users ADD COLUMN lockout_until DATETIME NULL AFTER failed_login_attempts"); } catch (Exception $e) {}

            $max_attempts = 5;
            $lockout_time_minutes = 15;
            $identifier = sanitize_input($input['phone'] ?? '');
            $password = $input['password'] ?? '';

            $is_phone = (bool)preg_match('/^[0-9]+$/', $identifier);
            if ($is_phone) {
                $stmt = $pdo->prepare("SELECT id, username, password, store_name, role, is_active, phone, failed_login_attempts, lockout_until, settings, account_status FROM users WHERE phone = ? AND role IN ('merchant', 'delivery')");
            } else {
                $stmt = $pdo->prepare("SELECT id, username, password, store_name, role, is_active, phone, failed_login_attempts, lockout_until, settings, account_status FROM users WHERE username = ? AND role IN ('merchant', 'delivery')");
            }
            $stmt->execute([$identifier]);
            $accounts = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (empty($accounts)) {
                throw new Exception("بيانات الدخول غير صحيحة.");
            }

            $is_locked = false;
            $lockout_time_remaining = 0;
            foreach ($accounts as $acc) {
                if ($acc['lockout_until'] && strtotime($acc['lockout_until']) > time()) {
                    $is_locked = true;
                    $lockout_time_remaining = ceil((strtotime($acc['lockout_until']) - time()) / 60);
                    break;
                }
            }

            if ($is_locked) {
                throw new Exception("تم قفل هذا الحساب تحديداً لمدة 15 دقيقة بسبب تجاوز 5 محاولات دخول فاشلة. يرجى المحاولة بعد {$lockout_time_remaining} دقيقة.");
            }
            
            foreach ($accounts as $acc) {
                if (password_verify($password, $acc['password']) && $acc['account_status'] === 'pending') {
                    throw new Exception("حسابك حالياً قيد المراجعة من قبل الإدارة لتخصيص مساحة التخزين الخاصة بك. سيتم تفعيل حسابك قريباً.");
                }
                if (password_verify($password, $acc['password']) && $acc['account_status'] === 'rejected') {
                    throw new Exception("نعتذر، تم رفض طلب انضمامك كتاجر.");
                }
            }
            
            $valid_logins =[];
            foreach ($accounts as $account) {
                if (password_verify($password, $account['password'])) {
                    if ($account['is_active']) {
                        $valid_logins[] = $account;
                    }
                }
            }

            if (empty($valid_logins)) {
                $account_ids = array_column($accounts, 'id');
                if (empty($account_ids)) {
                    throw new Exception("بيانات الدخول غير صحيحة.");
                }
                $placeholders = implode(',', array_fill(0, count($account_ids), '?'));
                $pdo->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id IN ($placeholders)")->execute($account_ids);
                $stmt_check = $pdo->prepare("SELECT MAX(failed_login_attempts) FROM users WHERE id IN ($placeholders)");
                $stmt_check->execute($account_ids);
                $current_attempts = $stmt_check->fetchColumn();
                if ($current_attempts >= $max_attempts) {
                    $pdo->prepare("UPDATE users SET lockout_until = DATE_ADD(NOW(), INTERVAL " . (int)$lockout_time_minutes . " MINUTE) WHERE id IN ($placeholders)")->execute($account_ids);
                    throw new Exception("تم قفل الحساب تحديداً لمدة 15 دقيقة بسبب تجاوز 5 محاولات فاشلة.");
                }
                $attempts_left = $max_attempts - $current_attempts;
                throw new Exception("بيانات الدخول غير صحيحة. تبقى لك {$attempts_left} محاولات قبل قفل الحساب.");
            }

            $successful_ids = array_column($valid_logins, 'id');
            if (!empty($successful_ids)) {
                $placeholders_success = implode(',', array_fill(0, count($successful_ids), '?'));
                $pdo->prepare("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id IN ($placeholders_success)")->execute($successful_ids);
            }

            $device_token = $_COOKIE['device_token'] ?? '';
            $is_fully_trusted = false;

            if (!empty($device_token) && !empty($valid_logins)) {
                $user_ids_to_check = array_column($valid_logins, 'id');
                $placeholders = implode(',', array_fill(0, count($user_ids_to_check), '?'));
                $stmt_dev = $pdo->prepare("SELECT COUNT(DISTINCT user_id) FROM trusted_devices WHERE user_id IN ($placeholders) AND device_token = ?");
                $params = array_merge($user_ids_to_check,[$device_token]);
                $stmt_dev->execute($params);
                $trusted_count = (int) $stmt_dev->fetchColumn();
                
                if ($trusted_count === count($valid_logins)) {
                    $is_fully_trusted = true;
                    $pdo->prepare("UPDATE trusted_devices SET last_used_at = NOW() WHERE user_id IN ($placeholders) AND device_token = ?")
                        ->execute($params);
                }
            }

            if (!$is_fully_trusted) {
                $phone_to_check = $valid_logins[0]['phone'];
                $otp = generate_secure_otp();
                
                // ⭐ التوكن موقَّع (HMAC) فقط وليس مُشفَّراً، لذلك لم يعد يحمل الكود الصريح
                // بل hash_hmac منه فقط، بحيث لا يقدر أي شخص يملك الكوكي أن يقرأ الكود بفك base64.
                $token_payload =[ 'purpose' => 'new_device_login', 'phone' => $phone_to_check, 'valid_logins' => $valid_logins, 'otp_hash' => hash_otp($otp), 'attempts' => 0 ];
                $state_token = generate_signed_token($token_payload, 5);
                
                setcookie('state_token', $state_token, [
                    'expires' => time() + 300,
                    'path' => '/',
                    'domain' => '',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None'
                ]);
                
                $message = "رمز التحقق لتسجيل الدخول من جهاز جديد هو: {$otp}";
                try { 
                    $pdo->prepare("DELETE FROM sms_queue WHERE phone_number = ?")->execute([$phone_to_check]);
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone_to_check, $message]); 
                } catch(PDOException $e) {}
                send_via_macrodroid($phone_to_check, $message);
                
                send_response('new_device_otp_required',['message' => 'تم اكتشاف محاولة دخول من جهاز جديد. يرجى إدخال رمز التحقق المرسل لجوالك.', 'state_token' => $state_token]);
            }

            if (count($valid_logins) === 1) {
                $user = $valid_logins[0];

                // APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة

                $payload = [
                    'user_id' => $user['id'], 
                    'username' => $user['username'],
                    'store_name' => $user['store_name'], 
                    'role' => $user['role'],
                    'device_token' => $device_token // إضافة بصمة الجهاز
                ];
                // تم إزالة المسار السري لفايربيس لسد ثغرة الوصول المباشر
                
                $token = generate_signed_token($payload, 5256000); // 30 يوماً
                $needs_settings = false;
                if ($user['role'] === 'merchant') {
                    $stmt_check = $pdo->prepare("SELECT store_type, settings FROM users WHERE id = ?");
                    $stmt_check->execute([$user['id']]);
                    $u_data = $stmt_check->fetch(PDO::FETCH_ASSOC);
                    $set = json_decode($u_data['settings'] ?: '{}', true);
                    if (empty($u_data['store_type']) || empty($set['location'])) {
                        $needs_settings = true;
                    }
                }
                
                $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.php' : 'delivery-dashboard.php';
                if ($needs_settings) $redirect .= '?force_settings=1';

                // ⭐ تصحيح (2026-07-21): كانت المزامنة تصير بعد send_response_and_continue_in_background
                // اللي تعتمد على fastcgi_finish_request غير المضمونة على Render، فما كانت
                // تنفّذ فعلياً أبداً. الآن نزامن *قبل* إرسال الرد لضمان وصول بيانات
                // التاجر لـ D1 قبل أي طلب لاحق (مثل create_order من العميل).
                sync_user_to_worker($pdo, $user['id']);
                send_response('success', ['token' => $token, 'redirect' => $redirect]);

            } else {
                $selection_data =[];
                foreach ($valid_logins as $account) {
                    $selection_data[$account['role']] = [ 'id' => $account['id'], 'name' => $account['store_name'] ?: $account['username'] ];
                }
                $_SESSION['login_selection_data'] = $selection_data;
                send_response('role_selection_required',['accounts' => $selection_data]);
            }
            break;
            
        case 'verify_new_device_otp':
            $otp_input = $input['otp'] ?? '';
            $token = $input['state_token'] ?? $_COOKIE['state_token'] ?? '';
            $is_secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
            
            try {
                $payload = verify_signed_token($token, 'new_device_login');
            } catch (Exception $e) {
                throw new Exception($e->getMessage());
            }
            
            if (!verify_otp_hash($otp_input, $payload['otp_hash'] ?? null)) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']);
                    throw new Exception("تم إلغاء العملية لتجاوز عدد المحاولات (3 محاولات). يرجى تسجيل الدخول من جديد.");
                }
                $new_token = generate_signed_token($payload, 5);
                setcookie('state_token', $new_token, ['expires' => time() + 300, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']);
                throw new Exception('رمز التحقق غير صحيح. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
            }
            
            $valid_logins = $payload['valid_logins'];
            $new_device_token = bin2hex(random_bytes(32));
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

            $stmt_insert = $pdo->prepare("INSERT INTO trusted_devices (user_id, device_token, user_agent) VALUES (?, ?, ?)");
            foreach ($valid_logins as $account_to_trust) {
                $stmt_insert->execute([$account_to_trust['id'], $new_device_token, $user_agent]);
            }
            
            setcookie('device_token', $new_device_token,[
                'expires' => time() + (86400 * 365), 
                'path' => '/',
                'secure' => $is_secure,
                'httponly' => true,
                'samesite' => $is_secure ? 'None' : 'Lax'
            ]);
            
            setcookie('state_token', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']); 
            
            if (count($valid_logins) === 1) {
                $user = $valid_logins[0];
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['store_name'] = $user['store_name'];
                $_SESSION['loggedin'] = true;
                $_SESSION['role'] = $user['role'];
                $_SESSION['device_token'] = $new_device_token;
                
                $payload = ['user_id' => $user['id'], 'username' => $user['username'], 'store_name' => $user['store_name'], 'role' => $user['role'], 'device_token' => $new_device_token];
                // APP_SECRET_KEY مُعرَّف بالفعل عند بداية الملف عبر متغيرات البيئة
                $token = generate_signed_token($payload, 480);
                
                $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.html' : 'delivery-dashboard.html';
                // ⭐ تصحيح (2026-07-21): هذا المسار (تسجيل دخول بجهاز جديد عبر كود
                // تحقق) كان لا يستدعي sync_user_to_worker() إطلاقاً من الأساس —
                // بعكس مسارات تسجيل الدخول الأخرى. وهو الأشيع عملياً (أي دخول من
                // جهاز/متصفح جديد أو بعد تسجيل خروج)، فكان سبب استمرار خلو جدول
                // users في D1 من بيانات التاجر حتى بعد تصحيح مشكلة التايمنج بالمسارات
                // الأخرى.
                sync_user_to_worker($pdo, $user['id']);
                send_response('success',['token' => $token, 'redirect' => $redirect]);
            } else {
                $selection_data =[];
                foreach ($valid_logins as $account) {
                    $selection_data[$account['role']] = [ 'id' => $account['id'], 'name' => $account['store_name'] ?: $account['username'] ];
                }
                $_SESSION['login_selection_data'] = $selection_data;
                send_response('role_selection_required',['accounts' => $selection_data]);
            }
            break;        

        case 'register_init':
            $allowed_fields = ['phone', 'role', 'name', 'username', 'password', 'location', 'store_type']; 
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $phone = preg_replace('/[^0-9]/', '', $safe_input['phone'] ?? '');
            $role = in_array($safe_input['role'] ?? '', ['merchant', 'delivery']) ? $safe_input['role'] : null;
            $name = sanitize_input($safe_input['name'] ?? '');
            $username = sanitize_input($safe_input['username'] ?? '');
            $password = $safe_input['password'] ?? null;
            $location = sanitize_input($safe_input['location'] ?? '');
            $store_type = sanitize_input($safe_input['store_type'] ?? ''); 
            
            if (empty($location) || !is_valid_gps_location($location)) {
                throw new Exception("رابط الموقع الجغرافي (GPS) غير صالح أو يقع خارج النطاق المسموح للخدمة. يرجى تحديده بدقة.");
            }
            if ($role === 'merchant' && empty($store_type)) {
                throw new Exception("يرجى اختيار نوع النشاط (القسم) الخاص بمتجرك.");
            }

            if (!preg_match('/^[a-z][a-z0-9_.]{4,19}$/', $username)) {
                throw new Exception("اسم المستخدم غير صالح. يجب أن يبدأ بحرف، ويحتوي على حروف إنجليزية صغيرة وأرقام فقط، وطوله بين 5 و 20 حرفاً.");
            }
            if (strlen($password) < 8) throw new Exception("كلمة المرور يجب أن تكون 8 أحرف على الأقل.");

            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?"); $stmt->execute([$username]);
            if ($stmt->fetch()) throw new Exception("اسم المستخدم هذا محجوز بالفعل.");
            
            $stmt = $pdo->prepare("SELECT id FROM users WHERE phone = ?"); 
            $stmt->execute([$phone]);
            $existing_accounts = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (!empty($existing_accounts)) {
                throw new Exception("هذا الرقم مسجل مسبقاً في النظام. لإضافة دور جديد (تاجر/مندوب)، يرجى تسجيل الدخول أولاً ثم إضافته من إعدادات حسابك من الداخل.");
            }
            
            $otp = generate_secure_otp();
            $hashed_pass = password_hash($password, PASSWORD_DEFAULT);
            
            $token_payload = [
                'purpose' => 'registration',
                'username' => $username,
                'password' => $hashed_pass,
                'store_name' => $name,
                'phone' => $phone,
                'role' => $role,
                'location' => $location,
                'store_type' => $store_type, 
                'otp_hash' => hash_otp($otp),
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 10);
            
            setcookie('state_token', $state_token, [
                'expires' => time() + 600,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None'
            ]);

            $message = "كود تفعيل حساب الشريك الخاص بك هو: {$otp}";
            
            $pdo->prepare("DELETE FROM sms_queue WHERE phone_number = ?")->execute([$phone]);
            $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone, $message]);
            send_via_macrodroid($phone, $message);
            
            send_response('success_otp_sent', ['state_token' => $state_token]);
            break;
        
        case 'register_verify':
            $otp = $input['otp'] ?? '';
            $token = $input['state_token'] ?? $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'registration');
            } catch (Exception $e) {
                throw new Exception($e->getMessage());
            }

            $is_secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

            if (!verify_otp_hash($otp, $payload['otp_hash'] ?? null)) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']);
                    throw new Exception("تم تجاوز المحاولات (3 محاولات). يرجى طلب كود جديد.");
                }
                $new_token = generate_signed_token($payload, 10);
                setcookie('state_token', $new_token, ['expires' => time() + 600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']);
                throw new Exception('رمز التحقق غير صحيح. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
            }

            $default_settings = json_encode(['location' => $payload['location']], JSON_UNESCAPED_UNICODE);
            $stmt = $pdo->prepare("INSERT INTO users (username, password, store_name, phone, role, is_active, account_status, settings, store_type) VALUES (?, ?, ?, ?, ?, 1, 'approved', ?, ?)");
            $stmt->execute([$payload['username'], $payload['password'], $payload['store_name'], $payload['phone'], $payload['role'], $default_settings, $payload['store_type']]);
            
            $new_merchant_id = $pdo->lastInsertId();
            $merchant_username = $payload['username'];

            $new_device_token = bin2hex(random_bytes(32));
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $pdo->prepare("INSERT INTO trusted_devices (user_id, device_token, user_agent) VALUES (?, ?, ?)")->execute([$new_merchant_id, $new_device_token, $user_agent]);
            
            setcookie('device_token', $new_device_token, [
                'expires' => time() + (86400 * 365),
                'path' => '/',
                'secure' => $is_secure,
                'httponly' => true,
                'samesite' => $is_secure ? 'None' : 'Lax'
            ]);

            $initData = [
                'details' => ['id' => $new_merchant_id, 'name' => $payload['store_name'], 'username' => $merchant_username, 'phone' => $payload['phone']],
                'products' => [] 
            ];

            $fb_url = getenv('FIREBASE_DB_URL') ?: $_ENV['FIREBASE_DB_URL'] ?: 'https://shiban-a2757-default-rtdb.europe-west1.firebasedatabase.app/';
            if (substr($fb_url, -1) !== '/') $fb_url .= '/';
            $fb_secret = getenv('FIREBASE_DB_SECRET') ?: $_ENV['FIREBASE_DB_SECRET'] ?: '';

            $ch = curl_init($fb_url . "stores/" . $merchant_username . ".json?auth=" . $fb_secret);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($initData, JSON_UNESCAPED_UNICODE));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 2);
            curl_exec($ch);
            curl_close($ch);

            flag_cache_for_rebuild($new_merchant_id);
            
            // توليد ملف المتجر الأولي في GitHub
            sync_merchant_info_json($pdo, $new_merchant_id, $merchant_username);

            // ⭐ تصحيح: حساب التاجر/المندوب الجديد ما كان يتزامن مع D1 إطلاقاً عند
            // إنشائه لأول مرة — فيضل غائب عن الـ Worker لحد أول تسجيل دخول لاحق.
            sync_user_to_worker($pdo, $new_merchant_id);

            setcookie('state_token', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']);
            send_response('success',['message' => 'تم تفعيل حسابك بنجاح! يمكنك الآن تسجيل الدخول.']);
            break;        

        case 'create_private_agent':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك. هذه الخاصية للتجار فقط.");

            $allowed_fields =['username', 'store_name', 'phone', 'password'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $u = sanitize_input($safe_input['username'] ?? '');
            $s = sanitize_input($safe_input['store_name'] ?? ''); 
            $phone = sanitize_input($safe_input['phone'] ?? '');
            $p = $safe_input['password'] ?? '';

            if (empty($u) || empty($s) || empty($p) || empty($phone)) throw new Exception("الرجاء ملء جميع الحقول.");
            if (strlen($p) < 8) throw new Exception("كلمة المرور يجب أن تكون 8 أحرف على الأقل.");
            if (!preg_match('/^[a-z][a-z0-9_.]{4,19}$/', $u)) throw new Exception("اسم المستخدم غير صالح.");

            $check = $pdo->prepare("SELECT id FROM users WHERE username = ? OR phone = ?");
            $check->execute([$u, $phone]);
            if ($check->fetch()) throw new Exception("اسم المستخدم أو رقم الهاتف موجود مسبقاً.");

            $hashed_pass = password_hash($p, PASSWORD_DEFAULT);
            $settings_json = json_encode(['location' => null]);

            $stmt = $pdo->prepare("INSERT INTO users (username, password, store_name, phone, role, is_active, employer_id, settings) VALUES (?, ?, ?, ?, 'delivery', 1, ?, ?)");
            $stmt->execute([$u, $hashed_pass, $s, $phone, $user_id, $settings_json]);

            // ⭐ تصحيح: نفس المشكلة — المندوب الخاص الجديد ما كان يتزامن مع D1
            sync_user_to_worker($pdo, $pdo->lastInsertId());

            send_response('success',['message' => 'تم إضافة المندوب الخاص بنجاح.']);
            break;

        case 'get_private_agents':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            $stmt = $pdo->prepare("SELECT id, username, store_name, phone, created_at, is_active FROM users WHERE role = 'delivery' AND employer_id = ? ORDER BY created_at DESC");
            $stmt->execute([$user_id]);
            send_response('success', ['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;

        case 'get_nearby_agents':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك. للتاجر فقط.");

            $stmt_merchant = $pdo->prepare("SELECT settings FROM users WHERE id = ?");
            $stmt_merchant->execute([$user_id]);
            $merchant_settings = json_decode($stmt_merchant->fetchColumn() ?: '{}', true);
            $merchant_location_url = $merchant_settings['location'] ?? null;

            if (empty($merchant_location_url)) {
                throw new Exception("يرجى تحديد موقع متجرك (GPS) في قسم الإعدادات أولاً للبحث عن المناديب القريبين.");
            }

            $merchant_coords = extract_coords_from_url($merchant_location_url);
            if (!$merchant_coords) {
                throw new Exception("رابط موقع متجرك غير صالح. يرجى تحديثه في الإعدادات.");
            }

            $sql = "SELECT u.id, u.username, u.store_name as display_name, u.phone, u.last_location,
                    (SELECT status FROM merchant_agent_links WHERE merchant_id = ? AND agent_id = u.id LIMIT 1) as link_status
                    FROM users u
                    WHERE u.role = 'delivery'
                    AND u.is_active = 1
                    AND u.employer_id IS NULL
                    AND u.last_location IS NOT NULL
                    AND u.last_active_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)";

            $stmt = $pdo->prepare($sql);
            $stmt->execute([$user_id]);
            $agents = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $nearby_agents =[];

            foreach ($agents as $agent) {
                $agent_location = json_decode($agent['last_location'], true);
                if ($agent_location && isset($agent_location['lat']) && isset($agent_location['lng'])) {
                    $distance = calculate_distance(
                        $merchant_coords['lat'], $merchant_coords['lng'],
                        $agent_location['lat'], $agent_location['lng']
                    );

                    if ($distance <= 10) {
                        $agent['distance_km'] = round($distance, 2);
                        unset($agent['last_location']); 
                        $nearby_agents[] = $agent;
                    }
                }
            }

            usort($nearby_agents, function($a, $b) {
                return $a['distance_km'] <=> $b['distance_km'];
            });

            send_response('success',['data' => $nearby_agents]);
            break;

        case 'search_app_agents':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك. للتاجر فقط.");
            $search_term = sanitize_input($input['term'] ?? '');
            if (empty($search_term)) throw new Exception("يرجى إدخال رقم الهاتف أو اسم المستخدم للبحث.");

            $is_phone = (bool)preg_match('/^[0-9]+$/', $search_term);
            if ($is_phone) {
                if (strpos($search_term, '967') === 0 && strlen($search_term) >= 12) $search_term = substr($search_term, 3);
                elseif (strpos($search_term, '00967') === 0) $search_term = substr($search_term, 5);
                elseif (strpos($search_term, '0') === 0 && strlen($search_term) == 10) $search_term = substr($search_term, 1);
            }

            $sql = "SELECT u.id, u.username, u.store_name as display_name, 
                    (SELECT status FROM merchant_agent_links WHERE merchant_id = ? AND agent_id = u.id LIMIT 1) as link_status 
                    FROM users u 
                    WHERE u.role = 'delivery' AND u.is_active = 1 AND u.employer_id IS NULL 
                    AND (u.phone = ? OR u.username = ?) LIMIT 1";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$user_id, $search_term, $search_term]);
            $agent = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($agent) {
                send_response('success',['data' => $agent]);
            } else {
                throw new Exception("لم يتم العثور على مندوب مستقل بهذا الرقم أو اسم المستخدم.");
            }
            break;

        case 'send_agent_link_request':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك. للتاجر فقط.");
            $agent_id = sanitize_input($input['agent_id'] ?? '');
            if (empty($agent_id)) throw new Exception("رقم المندوب غير صالح.");

            $stmt_check = $pdo->prepare("SELECT id FROM users WHERE id = ? AND role = 'delivery' AND employer_id IS NULL AND is_active = 1");
            $stmt_check->execute([$agent_id]);
            if (!$stmt_check->fetchColumn()) throw new Exception("المندوب المحدد غير متاح للارتباط.");

            $stmt_link = $pdo->prepare("SELECT status FROM merchant_agent_links WHERE merchant_id = ? AND agent_id = ?");
            $stmt_link->execute([$user_id, $agent_id]);
            $existing_link = $stmt_link->fetchColumn();

            if ($existing_link === 'pending') throw new Exception("لقد قمت بإرسال طلب لهذا المندوب وهو قيد الانتظار.");
            if ($existing_link === 'accepted') throw new Exception("هذا المندوب مرتبط بك بالفعل.");

            if ($existing_link === 'rejected') {
                $stmt_update = $pdo->prepare("UPDATE merchant_agent_links SET status = 'pending' WHERE merchant_id = ? AND agent_id = ?");
                $stmt_update->execute([$user_id, $agent_id]);
            } else {
                $stmt_insert = $pdo->prepare("INSERT INTO merchant_agent_links (merchant_id, agent_id, status) VALUES (?, ?, 'pending')");
                $stmt_insert->execute([$user_id, $agent_id]);
            }

            send_response('success',['message' => 'تم إرسال طلب الارتباط للمندوب بنجاح.']);
            break;

        case 'get_agent_invitations':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك. للمندوب فقط.");
            
            $sql = "SELECT l.id as link_id, u.store_name as merchant_name, u.phone as merchant_phone, l.created_at 
                    FROM merchant_agent_links l 
                    JOIN users u ON l.merchant_id = u.id 
                    WHERE l.agent_id = ? AND l.status = 'pending' 
                    ORDER BY l.created_at DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$user_id]);
            send_response('success',['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;

        case 'respond_to_agent_link':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك. للمندوب فقط.");
            $link_id = sanitize_input($input['link_id'] ?? '');
            $response_action = sanitize_input($input['response'] ?? '');

            if (!in_array($response_action, ['accepted', 'rejected'])) throw new Exception("استجابة غير صالحة.");

            $stmt = $pdo->prepare("UPDATE merchant_agent_links SET status = ? WHERE id = ? AND agent_id = ? AND status = 'pending'");
            $stmt->execute([$response_action, $link_id, $user_id]);

            if ($stmt->rowCount() > 0) {
                $msg = $response_action === 'accepted' ? 'تم قبول طلب الارتباط بنجاح. ستتلقى طلبات هذا التاجر بشكل حصري مؤقتاً.' : 'تم رفض طلب الارتباط.';
                send_response('success',['message' => $msg]);
            } else {
                throw new Exception("لم يتم العثور على الطلب أو أنه تمت معالجته مسبقاً.");
            }
            break;

        case 'get_merchant_linked_agents':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك. للتاجر فقط.");
            $sql = "SELECT l.id as link_id, u.id as agent_id, u.username, u.store_name as display_name, u.phone, l.status, l.created_at 
                    FROM merchant_agent_links l 
                    JOIN users u ON l.agent_id = u.id 
                    WHERE l.merchant_id = ? AND l.status IN ('accepted', 'pending')
                    ORDER BY l.status ASC, l.created_at DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$user_id]);
            send_response('success',['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;
     
        case 'recover_init':
            $phone = preg_replace('/[^0-9]/', '', $input['phone'] ?? '');
            try { $pdo->exec("ALTER TABLE users ADD COLUMN password_changed_at DATETIME NULL"); } catch (Exception $e) {}
            
            $stmt_user = $pdo->prepare("SELECT id, password_changed_at FROM users WHERE phone = ? AND role IN ('merchant', 'delivery') LIMIT 1");
            $stmt_user->execute([$phone]);
            $user_data = $stmt_user->fetch(PDO::FETCH_ASSOC);

            if (!$user_data) throw new Exception("هذا الرقم غير مسجل لدينا كشريك.");
            
            if ($user_data['password_changed_at'] && (time() - strtotime($user_data['password_changed_at'])) < 1800) {
                throw new Exception("لقد قمت بتغيير كلمتك مؤخراً، يرجى الانتظار لحماية حسابك.");
            }
        
            $otp = generate_secure_otp();
            
            $token_payload =[
                'purpose' => 'password_recovery_otp',
                'phone' => $phone,
                'otp_hash' => hash_otp($otp),
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 10);
            
            setcookie('state_token', $state_token, [
                'expires' => time() + 600,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None'
            ]);
            
            $message = "كود استعادة كلمة المرور الخاص بك هو: {$otp}";
            
            $pdo->prepare("DELETE FROM sms_queue WHERE phone_number = ?")->execute([$phone]);
            $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone, $message]);
            send_via_macrodroid($phone, $message);
            
            send_response('success', ['state_token' => $state_token]);
            break;
        
        case 'recover_check_otp':
            $phone = preg_replace('/[^0-9]/', '', $input['phone'] ?? '');
            $otp_input = $input['otp'] ?? '';
            $token = $input['state_token'] ?? $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'password_recovery_otp');
            } catch (Exception $e) {
                throw new Exception($e->getMessage() . " يرجى طلب كود استعادة جديد.");
            }

            if ($phone !== $payload['phone']) {
                throw new Exception("بيانات غير متطابقة.");
            }

            if (!verify_otp_hash($otp_input, $payload['otp_hash'] ?? null)) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', [
                        'expires' => time() - 3600,
                        'path' => '/',
                        'secure' => true,
                        'httponly' => true,
                        'samesite' => 'None'
                    ]);
                    throw new Exception("تم تجاوز المحاولات (3 محاولات). يرجى طلب كود استعادة جديد.");
                }
                $new_token = generate_signed_token($payload, 10);
                setcookie('state_token', $new_token, [
                    'expires' => time() + 600,
                    'path' => '/',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None'
                ]);
                throw new Exception('رمز التحقق غير صحيح. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
            }

            $token_payload =[
                'purpose' => 'password_reset',
                'phone' => $phone
            ];
            $reset_token = generate_signed_token($token_payload, 10);
            
            setcookie('state_token', $reset_token, [
                'expires' => time() + 600,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None'
            ]);
            
            send_response('success', ['state_token' => $reset_token]);
            break;
        
        case 'recover_set_password':
            $token = $input['state_token'] ?? $_COOKIE['state_token'] ?? '';
            $is_secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

            try {
                $payload = verify_signed_token($token, 'password_reset');
            } catch (Exception $e) {
                throw new Exception($e->getMessage() . " يرجى إعادة طلب كود الاستعادة.");
            }

            $phone = $payload['phone'];
            $password = $input['password'] ?? '';
            if (strlen($password) < 8) throw new Exception("كلمة المرور يجب أن تكون 8 أحرف على الأقل.");
            
            $hashed_pass = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password = ?, password_changed_at = NOW() WHERE phone = ?");
            $stmt->execute([$hashed_pass, $phone]);
            
            $stmt_uid = $pdo->prepare("SELECT id FROM users WHERE phone = ?");
            $stmt_uid->execute([$phone]);
            $recovered_uid = $stmt_uid->fetchColumn();
            
            if ($recovered_uid) {
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?")->execute([$recovered_uid]);
                $new_device_token = bin2hex(random_bytes(32));
                $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
                $pdo->prepare("INSERT INTO trusted_devices (user_id, device_token, user_agent) VALUES (?, ?, ?)")->execute([$recovered_uid, $new_device_token, $user_agent]);
                
                setcookie('device_token', $new_device_token, [
                    'expires' => time() + (86400 * 365),
                    'path' => '/',
                    'secure' => $is_secure,
                    'httponly' => true,
                    'samesite' => $is_secure ? 'None' : 'Lax'
                ]);
            }
            
            setcookie('state_token', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $is_secure, 'httponly' => true, 'samesite' => $is_secure ? 'None' : 'Lax']); 
            send_response('success');
            break;                

        case 'logout':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);

            unset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['store_name'], $_SESSION['role']);
            
            if (empty($_SESSION['customer_id'])) {
                $_SESSION = [];
                session_destroy();
            }
            
            send_response('success',['message' => 'تم تسجيل الخروج بنجاح، وسيتذكر النظام هذا الجهاز في المرة القادمة.']);
            break;

        case 'get_trusted_devices':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $stmt_devices = $pdo->prepare("SELECT id, user_agent, created_at, last_used_at, device_token FROM trusted_devices WHERE user_id = ? ORDER BY last_used_at DESC");
            $stmt_devices->execute([$user_id]);
            $devices = $stmt_devices->fetchAll(PDO::FETCH_ASSOC);
            
            $current_device_token = $_COOKIE['device_token'] ?? '';
            foreach($devices as &$device) {
                $device['is_current_device'] = ($device['device_token'] === $current_device_token);
                unset($device['device_token']); 
            }
        
            send_response('success',['data' => $devices]);
            break;

        case 'revoke_trusted_device':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $device_id_to_revoke = sanitize_input($input['device_id'] ?? null);
            if(!$device_id_to_revoke) throw new Exception("معرّف الجهاز مطلوب.");
            
            $stmt_check = $pdo->prepare("SELECT device_token FROM trusted_devices WHERE id = ? AND user_id = ?");
            $stmt_check->execute([$device_id_to_revoke, $user_id]);
            $token_to_revoke = $stmt_check->fetchColumn();
            
            if(!$token_to_revoke) {
                throw new Exception("الجهاز غير موجود أو لا تملك صلاحية حذفه.");
            }
        
            $is_current_device = (isset($_COOKIE['device_token']) && $_COOKIE['device_token'] === $token_to_revoke);
        
            $stmt_delete = $pdo->prepare("DELETE FROM trusted_devices WHERE id = ? AND user_id = ?");
            $stmt_delete->execute([$device_id_to_revoke, $user_id]);
            
            if ($stmt_delete->rowCount() > 0) {
                if ($is_current_device) {
                    setcookie('device_token', '',[
                        'expires' => time() - 3600,
                        'path' => '/',
                        'domain' => '',
                        'secure' => $is_secure_cookie,
                        'httponly' => true,
                        'samesite' => 'Strict'
                    ]);
                    session_destroy();
                    send_response('success',['message' => 'تم إلغاء الثقة بالجهاز الحالي بنجاح. سيتم تسجيل خروجك الآن.', 'force_logout' => true]);
                } else {
                    send_response('success',['message' => 'تم تسجيل الخروج من الجهاز المحدد عن بعد بنجاح.']);
                }
            } else {
                throw new Exception("فشل إلغاء الثقة بالجهاز.");
            }
            break;

        // =======================================================
        // مهام المنتجات
        // =======================================================
        
        case 'get_next_product_number':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $num = ($pdo->query("SELECT MAX(CAST(product_number AS UNSIGNED)) FROM products")->fetchColumn() ?: 0) + 1;
            send_response('success',['number' => $num]);
            break;

        case 'save_product':     
            // 1. التحقق من الصلاحيات
            if (!$user_id || $user_role !== 'merchant') {
                send_response('error', ['message' => 'غير مصرح لك بإضافة أو تعديل المنتجات.'], 401);
            }
            // 2. تنظيف المدخلات
            $pid = !empty($_POST['id']) ? sanitize_input($_POST['id']) : 'prod_' . generate_uuid();
            $is_edit = !empty($_POST['id']);
            
            $sell_price = floatval($_POST['price'] ?? 0);
            $cost_price = floatval($_POST['cost_price'] ?? 0);
            $currency = sanitize_input($_POST['currency'] ?? 'YER');
            $discount_percent = floatval($_POST['discount'] ?? 0);
            
            $quantity_type = sanitize_input($_POST['quantity_type'] ?? 'tracked');
            $quantity = ($quantity_type === 'unlimited') ? 9999 : (int)($_POST['quantity'] ?? 0);
            // ✅ إصلاح: قراءة صحيحة لـ isAvailable سواء جاء '1', 'on', 'true', أو 1
            $is_available_raw = $_POST['isAvailable'] ?? '0';
            $is_available = ($is_available_raw === '1' || $is_available_raw === 'on' || $is_available_raw === 'true' || $is_available_raw === true || intval($is_available_raw) === 1) ? 1 : 0;
            
            $name = sanitize_input($_POST['name'] ?? '');
            $desc = sanitize_input($_POST['mainDescription'] ?? '');
            $options = $_POST['sizes'] ?? '[]'; 
            
            // ✅ التحقق من البيانات المطلوبة
            if (empty($name)) throw new Exception('اسم المنتج مطلوب ولا يمكن أن يكون فارغاً.');
            if (empty($desc)) throw new Exception('وصف المنتج مطلوب.');
            if ($sell_price <= 0) throw new Exception('سعر البيع يجب أن يكون أكبر من صفر.');
            
            // 3. معالجة التصنيف مع دعم الفئات المتداخلة (فئة داخل فئة داخل فئة... بلا حد للعمق)
            // ✅ الفئات الجديدة لا تُحفظ في قاعدة البيانات إلا هنا، أي فقط لحظة نشر/حفظ المنتج فعلياً.
            //    قبل ذلك تبقى الفئات المُضافة من الواجهة "معلّقة" في المتصفح فقط ولا تُسجَّل أبداً.
            // ✅ كل عملية بحث/إنشاء/تحقق من فئة تكون مقيدة بهذا التاجر (user_id) فقط، بحيث لا يرى
            //    تاجر فئات تاجر آخر ولا يتم الخلط بينها حتى لو تشابهت الأسماء.
            $category_id_input = sanitize_input($_POST['category_id'] ?? '');
            $category_id = null;
            $category_name = 'عام';

            if ($category_id_input === 'NEW_CHAIN') {
                // صيغة جديدة: سلسلة كاملة من الفئات المتداخلة غير المحفوظة بعد
                // category_chain_names: ["الأب", "الابن", "الحفيد", ...] من الأعلى إلى الأدنى
                // category_anchor_id: معرف فئة حقيقية موجودة مسبقاً تُربط بها السلسلة (أو 0 إن كانت فئة رئيسية جديدة بالكامل)
                $chain_raw = $_POST['category_chain_names'] ?? '[]';
                $chain_names = json_decode($chain_raw, true);
                $anchor_id = (int)($_POST['category_anchor_id'] ?? 0);

                // تحقق أن نقطة الربط (إن وُجدت) تعود فعلاً لهذا التاجر أو فئة عامة مشتركة
                $parent_id = 0;
                if ($anchor_id > 0) {
                    $stmt_anchor = $pdo->prepare("SELECT id FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                    $stmt_anchor->execute([$anchor_id, $user_id]);
                    $parent_id = (int)($stmt_anchor->fetchColumn() ?: 0);
                }

                if (is_array($chain_names)) {
                    foreach ($chain_names as $cat_step_name) {
                        $cat_step_name = sanitize_input($cat_step_name);
                        if ($cat_step_name === '') continue;

                        // ✅ نستخدم دالة مقاومة للأعطال بدل إدخال مباشر، حتى لا يفشل نشر
                        // المنتج بخطأ قاعدة بيانات عام إن تكرر اسم الفئة مع تاجر آخر
                        $parent_id = resolve_or_create_category($pdo, $cat_step_name, $parent_id, $user_id);
                        $category_name = $cat_step_name;
                    }
                    $category_id = $parent_id > 0 ? $parent_id : null;
                }
            } else if (strpos($category_id_input, 'NEW_CAT:') === 0) {
                // (توافق قديم لطلبات من نسخة واجهة سابقة) — صيغة: NEW_CAT:parent_id::اسم_الفئة
                $parts = explode('::', substr($category_id_input, 8));
                $parent_id = (int)($parts[0] ?? 0);
                $category_name = sanitize_input($parts[1] ?? '');

                if ($parent_id > 0) {
                    $stmt_p = $pdo->prepare("SELECT COUNT(*) FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                    $stmt_p->execute([$parent_id, $user_id]);
                    if (!$stmt_p->fetchColumn()) $parent_id = 0;
                }

                if (!empty($category_name)) {
                    // ✅ نفس الدالة المقاومة للأعطال، بدل إدخال مباشر قد يفشل بخطأ قاعدة بيانات
                    $category_id = resolve_or_create_category($pdo, $category_name, $parent_id, $user_id);
                }
            } else if (is_numeric($category_id_input)) {
                // فئة موجودة مسبقاً — تحقق من ملكيتها (تعود لهذا التاجر أو فئة عامة مشتركة)
                $candidate_id = (int)$category_id_input;
                $stmt_cat = $pdo->prepare("SELECT id, name FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                $stmt_cat->execute([$candidate_id, $user_id]);
                $row_cat = $stmt_cat->fetch(PDO::FETCH_ASSOC);

                if ($row_cat) {
                    $category_id = (int)$row_cat['id'];
                    $category_name = $row_cat['name'];
                } else {
                    // فئة غير موجودة أو لا تعود لهذا التاجر — لا نسمح بربط المنتج بها
                    $category_id = null;
                    $category_name = 'عام';
                }
            }
            
            // معالجة الميزات/الخصائص (حتى 10 ميزات)
            $features = [];
            for ($i = 1; $i <= 10; $i++) {
                $feature_key = "feature_key_$i";
                $feature_value = "feature_value_$i";
                $key = sanitize_input($_POST[$feature_key] ?? '');
                $value = sanitize_input($_POST[$feature_value] ?? '');
                
                if (!empty($key) && !empty($value)) {
                    $features[] = [
                        'key' => $key,
                        'value' => $value
                    ];
                }
            }
            $features_json = json_encode($features, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

            // 4. رفع الصورة بأمان
            $img = sanitize_input($_POST['existing_image'] ?? '');
            if (isset($_FILES['image_file']) && $_FILES['image_file']['error'] === UPLOAD_ERR_OK) {
                $validation_result = validate_image_upload($_FILES['image_file']);
                if ($validation_result !== true) {
                    throw new Exception($validation_result);
                }

                $env_keys = getenv('IMGBB_KEYS') ?: $_ENV['IMGBB_KEYS'] ?? '';
                if (empty($env_keys)) throw new Exception("مفتاح رفع الصور مفقود من إعدادات السيرفر.");
                
                $keys_array = array_map('trim', explode(',', $env_keys));
                $api_key = $keys_array[array_rand($keys_array)]; 
                
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, "https://api.imgbb.com/1/upload?key=" . $api_key);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $mime = mime_content_type($_FILES['image_file']['tmp_name']);
                $filename = $_FILES['image_file']['name'];
                curl_setopt($ch, CURLOPT_POSTFIELDS, ['image' => new CURLFile($_FILES['image_file']['tmp_name'], $mime, $filename)]);
                $result = json_decode(curl_exec($ch), true);
                curl_close($ch);
                
                if ($result && isset($result['data']['url'])) {
                    $img = $result['data']['url'];
                } else {
                    throw new Exception("فشل رفع الصورة لمركز الرفع.");
                }
            }
            
            if (empty($img)) throw new Exception("يجب توفير صورة للمنتج.");

            if (!$is_edit && $sell_price <= $cost_price) {
                throw new Exception('سعر البيع يجب أن يكون أعلى من التكلفة.');
            }

    // 5. الحفظ المباشر والآمن في قاعدة بيانات TiDB Cloud (PDO)
            if ($is_edit) {
                // استبدل استعلام الـ UPDATE القديم بهذا:
                $sql = "UPDATE products SET 
                        name = ?, description = ?, price = ?, cost_price = ?, discount = ?, 
                        image = ?, type = ?, options = ?, features = ?, quantity = ?, quantity_type = ?, 
                        is_available = ?, currency = ?, updated_at = ?, category_id = ?, approval_status = 'approved'
                        WHERE id = ? AND merchant_id = ?";
                $params = [
                    $name, $desc, $sell_price, $cost_price, $discount_percent, 
                    $img, $category_name, $options, $features_json, $quantity, $quantity_type, 
                    $is_available, $currency, time(), $category_id, $pid, $user_id
                ];
                $stmt_save = $pdo->prepare($sql);
                $stmt_save->execute($params);
            } else {
                // استبدل استعلام الـ INSERT القديم بهذا:
$sql = "INSERT INTO products 
        (id, merchant_id, name, description, price, cost_price, discount, image, type, options, features, quantity, quantity_type, is_available, currency, updated_at, category_id, approval_status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')";
$params = [
    $pid, $user_id, $name, $desc, $sell_price, $cost_price, $discount_percent, 
    $img, $category_name, $options, $features_json, $quantity, $quantity_type, 
    $is_available, $currency, time(), $category_id
];
                $stmt_save = $pdo->prepare($sql);
                $stmt_save->execute($params);
            }

            // =======================================================
            // 🚀 6. حيلة FastCGI: إرسال الاستجابة للتاجر فوراً وإنهاء الاتصال
            //    قبل تنفيذ trigger_cache_rebuild، حتى لا ينتظر المتصفح
            //    عملية الرفع إلى GitHub (التي أصبحت أسرع بفضل الـ Batch Upload
            //    لكنها قد تستغرق ثانية أو أكثر حسب حجم المتجر).
            // =======================================================
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);

            send_response_and_continue_in_background('success', [
                'message' => $is_edit ? 'تم تحديث المنتج بأمان.' : 'تم إضافة المنتج بأمان.',
                'id' => $pid
            ]);

            // من هنا فصاعداً: اتصال الـ HTTP مع التاجر قد انتهى فعلياً،
            // وأي كود ينفَّذ الآن يعمل في الخلفية بهدوء دون أن ينتظره المتصفح.
            trigger_cache_rebuild($user_id, $merchant_username);
            exit();
      
        case 'force_sync_to_firebase':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            
            $m_username = $_SESSION['username'];
            $sync_count = 0;

            $stmt_m = $pdo->prepare("SELECT store_name, store_type, settings FROM users WHERE id = ?");
            $stmt_m->execute([$user_id]);
            $m_data = $stmt_m->fetch(PDO::FETCH_ASSOC);
            if ($m_data) {
                $m_data['settings'] = json_decode($m_data['settings'] ?: '{}', true);
                sync_to_firebase($m_username, 'info', null, $m_data, 'PUT');
                
                // ⭐ إجبار تحديث ملف info.json على GitHub أيضاً
                sync_merchant_info_json($pdo, $user_id, $m_username);
            }

            // تعديل الاستعلام للمزامنة من جدول المنتجات الأساسي
            $sql_prods = "SELECT p.id as global_product_id, p.name, p.description, p.image, p.options, p.discount, p.department, p.category_id, p.price, p.quantity, p.quantity_type, p.currency, p.type, u.id as merchant_id, u.username as merchant_username, u.store_name as merchant_name FROM products p JOIN users u ON p.merchant_id = u.id WHERE p.merchant_id = ? AND p.is_available = 1";
            $stmt_p = $pdo->prepare($sql_prods);
            $stmt_p->execute([$user_id]);
            $products = $stmt_p->fetchAll(PDO::FETCH_ASSOC);
            
            $fb_products = [];
            foreach ($products as $p) {
                $p['options'] = json_decode($p['options'] ?? '[]', true) ?: [];
                $pid = $p['global_product_id'];
                $fb_products[$pid] = $p;
                $sync_count++;
            }
            if (!empty($fb_products)) {
                kv_request("stores/$m_username/products", 'PUT', $fb_products);
            }

            // بدلاً من رفع الطلبات لفايربيس، نرسل إشارة للمتصفح ليقوم بسحبها من الـ API المحمي
            sync_to_firebase($m_username, "signals/orders_updated", null, time(), 'PUT');

            send_response('success', ['message' => "تم رفع $sync_count منتج وإعدادات المتجر إلى Firebase بنجاح!"]);
            break;      

        case 'get_global_catalog':
            if ($user_role !== 'merchant') {
                throw new Exception("هذه الخاصية متاحة للتجار فقط.");
            }
            $term = sanitize_input($input['term'] ?? '');

            $sql = "
                SELECT 
                    p.id, p.name, p.image, p.sizes as options, c.name as type,
                    l.id as listing_id
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                LEFT JOIN merchant_listings l ON p.id = l.global_product_id AND l.merchant_id = ?
                WHERE p.approval_status = 'approved'
            ";
            $params = [$user_id];

            if ($term) {
                $sql .= " AND (p.name LIKE ? OR p.keywords LIKE ?)";
                $like_term = "%" . escape_like_search($term) . "%";
                $params[] = $like_term;
                $params[] = $like_term;
            }

            $sql .= " ORDER BY p.name ASC LIMIT 100";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

            foreach ($products as &$product) {
                $product['is_listed'] = !empty($product['listing_id']);
                $product['options'] = json_decode($product['options'] ?? '[]', true);
                unset($product['listing_id']);
            }
            
            send_response('success', ['data' => $products]);
            break;

        case 'add_listing_from_catalog':
            if ($user_role !== 'merchant') {
                throw new Exception("هذه الخاصية متاحة للتجار فقط.");
            }
            
            $stmt_check_type = $pdo->prepare("SELECT store_name, store_type, settings FROM users WHERE id = ?");
            $stmt_check_type->execute([$user_id]);
            $u_data = $stmt_check_type->fetch(PDO::FETCH_ASSOC);
            $set = json_decode($u_data['settings'] ?: '{}', true);
            if (empty($u_data['store_name']) || empty($u_data['store_type']) || empty($set['location'])) {
                throw new Exception("REQUIRE_PROFILE_UPDATE: يرجى استكمال بيانات متجرك الأساسية في قسم الإعدادات أولاً.");
            }

            $allowed_fields = ['global_product_id', 'merchant_price', 'cost_price', 'quantity', 'quantity_type', 'is_available', 'selected_options'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $global_id = sanitize_input($safe_input['global_product_id'] ?? '');
            $merchant_price = floatval($safe_input['merchant_price'] ?? 0);
            $cost_price = floatval($safe_input['cost_price'] ?? 0);
            $quantity = intval($safe_input['quantity'] ?? 0);
            $quantity_type = in_array($safe_input['quantity_type'], ['tracked', 'unlimited']) ? $safe_input['quantity_type'] : 'tracked';
            $is_available = filter_var($safe_input['is_available'] ?? true, FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
            $selected_options_ids = $safe_input['selected_options'] ?? null;

            if (empty($global_id) || $merchant_price <= 0) {
                throw new Exception("بيانات المنتج غير مكتملة. يرجى إدخال السعر على الأقل.");
            }

            $stmt_check = $pdo->prepare("SELECT id, options, price FROM products WHERE id = ? AND approval_status = 'approved'");
            $stmt_check->execute([$global_id]);
            $global_product = $stmt_check->fetch(PDO::FETCH_ASSOC);

            if (!$global_product) {
                throw new Exception("المنتج المحدد غير موجود في الكتالوج العام أو لم تتم الموافقة عليه بعد.");
            }
            
            $price_variables = null;
            if (!empty($selected_options_ids) && is_array($selected_options_ids)) {
                $global_options = json_decode($global_product['options'] ?? '[]', true);
                $global_option_ids = array_column($global_options, 'id');
                $valid_options = array_intersect($selected_options_ids, $global_option_ids);
                if (count($valid_options) > 0) { $price_variables = json_encode(['selected_options' => $valid_options]); }
            }

            try {
                $sql = "INSERT INTO merchant_listings (merchant_id, global_product_id, merchant_price, cost_price, quantity, quantity_type, is_available, price_variables) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$user_id, $global_id, $merchant_price, $cost_price, $quantity, $quantity_type, $is_available, $price_variables]);
                send_response('success', ['message' => 'تمت إضافة المنتج إلى متجرك بنجاح.']);
            } catch (PDOException $e) {
                if ($e->errorInfo[1] == 1062) { throw new Exception("لقد قمت بإضافة هذا المنتج إلى متجرك مسبقاً."); } 
                else { throw $e; }
            }
            break;

        case 'list_products':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $term = strtolower(sanitize_input($input['term'] ?? ''));
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = max(1, min(100, (int)($input['limit'] ?? 15))); 
            $offset = ($page - 1) * $limit;
            
            $merged_products = [];
            $seen_ids = [];

            // 1. استرجاع المنتجات من TiDB Cloud (PDO) مباشرة دون الحاجة لـ D1
            try {
                $sql_tidb = "SELECT * FROM products WHERE merchant_id = ?";
                $params_tidb = [$user_id];

                if ($term) {
                    $sql_tidb .= " AND (name LIKE ? OR description LIKE ?)";
                    $search_term = "%" . escape_like_search($term) . "%";
                    $params_tidb[] = $search_term;
                    $params_tidb[] = $search_term;
                }

                $sql_tidb .= " ORDER BY updated_at DESC LIMIT $limit OFFSET $offset";
                $stmt_p = $pdo->prepare($sql_tidb);
                $stmt_p->execute($params_tidb);
                $tidb_products = $stmt_p->fetchAll(PDO::FETCH_ASSOC);

                if (is_array($tidb_products)) {
                    foreach($tidb_products as $p) {
                        $p['options'] = json_decode($p['options'] ?? '[]', true);
                        if ($user_role === 'delivery') unset($p['cost_price']);
                        $merged_products[] = $p;
                        $seen_ids[] = (string)$p['id'];
                    }
                }
            } catch (Exception $e) {
                // تجاوز الخطأ لضمان تواصل العمل
            }

            // 2. الدعم العكسي للمنتجات التي ما زالت مخزنة بنمط Listings
            try {
                $sql_mysql = "
                    SELECT p.id as global_product_id, p.name, p.mainDescription as description, p.image, p.sizes as options, p.discount,
                           c.name as type, l.merchant_price as price, l.cost_price, l.quantity, l.quantity_type, l.currency, l.is_available, l.updated_at
                    FROM merchant_listings l
                    JOIN products p ON l.global_product_id = p.id
                    LEFT JOIN categories c ON p.category_id = c.id
                    WHERE l.merchant_id = ?
                ";
                $params_mysql = [$user_id];

                if ($term) {
                    $sql_mysql .= " AND (p.name LIKE ? OR p.mainDescription LIKE ?)";
                    $search_term = "%" . escape_like_search($term) . "%";
                    $params_mysql[] = $search_term;
                    $params_mysql[] = $search_term;
                }

                $sql_mysql .= " ORDER BY l.updated_at DESC LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql_mysql);
                $stmt->execute($params_mysql);
                $legacy_products = $stmt->fetchAll(PDO::FETCH_ASSOC);

                foreach($legacy_products as $p) {
                    $pid = (string)$p['global_product_id'];
                    if (!in_array($pid, $seen_ids)) {
                        $p['id'] = $pid; 
                        $p['options'] = json_decode($p['options'] ?? '[]', true);
                        if ($user_role === 'delivery') unset($p['cost_price']);
                        $merged_products[] = $p;
                        $seen_ids[] = $pid;
                    }
                }
            } catch (Exception $e) {}

            // ترتيب زمني للنتائج المدمجة
            usort($merged_products, function($a, $b) {
                $timeA = isset($a['updated_at']) && is_numeric($a['updated_at']) ? $a['updated_at'] : 0;
                $timeB = isset($b['updated_at']) && is_numeric($b['updated_at']) ? $b['updated_at'] : 0;
                return $timeB - $timeA;
            });

            $final_products = array_slice($merged_products, 0, $limit);
            $has_more = count($final_products) >= $limit;

            send_response('success',['data' => $final_products, 'has_more' => $has_more, 'page' => $page]);
            break;

        case 'get_product':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $sql = "SELECT p.*, c.name as type FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ?"; 
            $params =[sanitize_input($input['id'])];
            if ($user_role === 'merchant' || $user_role === 'delivery') { $sql .= " AND p.merchant_id = ?"; $params[] = $user_id; }
            $stmt = $pdo->prepare($sql); $stmt->execute($params); $prod = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($prod) {
                $catPaths = get_full_category_paths($pdo);
                if (!empty($prod['category_id']) && isset($catPaths[$prod['category_id']])) {
                    $prod['type'] = $catPaths[$prod['category_id']];
                }

                if ($user_role === 'delivery') unset($prod['cost_price']);
                
                $options_data = json_decode($prod['options'] ?? '[]', true); 
                if (is_array($options_data)) { 
                    foreach($options_data as &$opt) { 
                        if (isset($opt['size_name']) && !isset($opt['name'])) { 
                            $opt['name'] = $opt['size_name']; 
                            unset($opt['size_name']); 
                        } 
                    } 
                }
                $prod['options'] = $options_data;
                send_response('success',['data' => $prod]);
            }
            throw new Exception('المنتج غير موجود.');
            break;

        case 'review_product':
            if ($user_role !== 'admin') throw new Exception("غير مصرح. هذه الصلاحية للإدارة فقط.");
            
            $pid = sanitize_input($input['id']);
            $status = sanitize_input($input['approval_status']); 
            
            if (!in_array($status,['approved', 'rejected'])) {
                throw new Exception("حالة مراجعة غير صالحة.");
            }
            
            $isAvailable = ($status === 'approved') ? 1 : 0;
            
            $stmt = $pdo->prepare("UPDATE products SET approval_status = ?, isAvailable = ? WHERE id = ?");
            $stmt->execute([$status, $isAvailable, $pid]);
            
            if($status === 'approved') {
                $pdo->prepare("UPDATE merchant_listings SET is_available = 1 WHERE global_product_id = ?")->execute([$pid]);
            }
            
            flag_cache_for_rebuild($user_id ?? null);
            send_response('success',['message' => 'تم تحديث حالة مراجعة المنتج بنجاح.']);
            break;

        case 'delete_product':
            if (!$user_id || $user_role !== 'merchant') send_response('error', ['message' => 'غير مصرح لك.'], 401);
            $product_id = sanitize_input($input['id']);
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);

            // 1. فحص أمني: هل المنتج ضمن طلب نشط حالياً عند زبون؟
            $search1 = '%"product_id":"' . $product_id . '"%'; 
            $stmt_check = $pdo->prepare("SELECT ticket_id FROM live_tickets WHERE merchant_id = ? AND status IN ('pending_merchant_approval', 'confirmed_by_store', 'accepted_by_delivery', 'out_for_delivery') AND ticket_data LIKE ? LIMIT 1");
            $stmt_check->execute([$user_id, $search1]);
            
            if ($stmt_check->fetch()) {
                throw new Exception("لا يمكنك حذف هذا المنتج حالياً لأنه موجود ضمن طلب نشط للزبائن. قم بإنهاء الطلب أو إلغائه أولاً.");
            }

            // 2. الحذف من قاعدة بيانات TiDB مباشرة
            $stmt_del = $pdo->prepare("DELETE FROM products WHERE id = ? AND merchant_id = ?");
            $stmt_del->execute([$product_id, $user_id]);

            // 🚀 3. حيلة FastCGI: إرسال الاستجابة فوراً للتاجر قبل إعادة بناء
            //    الكاش السحابي (رفع الملفات إلى GitHub) والحذف من Firebase،
            //    حتى لا ينتظر المتصفح هذه العمليات الثانوية.
            send_response_and_continue_in_background('success', ['message' => 'تم حذف المنتج نهائياً بنجاح.']);

            // من هنا فصاعداً: الاتصال مع التاجر انتهى فعلياً، والعمليات التالية
            // تعمل في الخلفية بهدوء.
            trigger_cache_rebuild($user_id, $merchant_username);

            // 4. الحذف من Firebase إن وجد
            fb_request("stores/$merchant_username/products/$product_id.json", 'DELETE');

            exit();

        case 'toggle_availability':
            if (!$user_id || $user_role !== 'merchant') send_response('error',['message' => 'غير مصرح'], 401);
            
            $product_id = sanitize_input($input['id']);
            $req_status = (int)$input['isAvailable'] ? 1 : 0;
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);

            // 1. تحديث الحالة في TiDB Cloud بأمان
            $stmt_toggle = $pdo->prepare("UPDATE products SET is_available = ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
            $stmt_toggle->execute([$req_status, time(), $product_id, $user_id]);

            // 🚀 2. حيلة FastCGI: إرسال الاستجابة فوراً ثم إعادة بناء الكاش في الخلفية
            send_response_and_continue_in_background('success', ['message' => 'تم تحديث حالة عرض المنتج (إخفاء/إظهار) بنجاح.']);

            trigger_cache_rebuild($user_id, $merchant_username);
            exit();

        case 'add_quantity':
            if (!$user_id || $user_role !== 'merchant') send_response('error',['message' => 'غير مصرح لك.'], 401);
            
            $product_id = sanitize_input($input['productId']);
            $size_id = sanitize_input($input['sizeId'] ?? null);
            $qty_to_add = (int)$input['quantity'];
            
            if ($qty_to_add <= 0) {
                throw new Exception("يجب إدخال كمية صحيحة أكبر من الصفر.");
            }
            
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);

            // 1. سحب بيانات المنتج من TiDB لضمان البيانات الحقيقية
            $stmt_p = $pdo->prepare("SELECT quantity, quantity_type, options FROM products WHERE id = ? AND merchant_id = ?");
            $stmt_p->execute([$product_id, $user_id]);
            $d1_products = $stmt_p->fetchAll(PDO::FETCH_ASSOC);

            if (empty($d1_products)) {
                throw new Exception("المنتج غير موجود أو لا تملك صلاحية التعديل عليه.");
            }
            
            $product = $d1_products[0];
            if ($product['quantity_type'] !== 'tracked') {
                throw new Exception("هذا المنتج غير محدود الكمية، لا حاجة لإضافة مخزون.");
            }

            // 2. الحساب الآمن داخل السيرفر
            if (!empty($size_id)) {
                $options = json_decode($product['options'] ?: '[]', true);
                $found = false;
                $new_total_qty = 0; 
                
                foreach ($options as &$opt) {
                    if (isset($opt['id']) && $opt['id'] === $size_id) {
                        $opt['quantity'] = (int)($opt['quantity'] ?? 0) + $qty_to_add;
                        $found = true;
                    }
                    $new_total_qty += (int)($opt['quantity'] ?? 0);
                }
                unset($opt); 
                
                if (!$found) throw new Exception("المقاس أو الخيار المحدد غير موجود ضمن هذا المنتج.");
                
                $new_options_json = json_encode($options, JSON_UNESCAPED_UNICODE);
                
                // تحديث TiDB بالمقاسات الجديدة
                $stmt_upd = $pdo->prepare("UPDATE products SET quantity = ?, options = ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                $stmt_upd->execute([$new_total_qty, $new_options_json, time(), $product_id, $user_id]);
            } else {
                // منتج عادي لا يحتوي خيارات
                $stmt_upd = $pdo->prepare("UPDATE products SET quantity = quantity + ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                $stmt_upd->execute([$qty_to_add, time(), $product_id, $user_id]);
            }

            // 🚀 3. حيلة FastCGI: إرسال الاستجابة فوراً ثم إعادة بناء الكاش في الخلفية
            send_response_and_continue_in_background('success', ['message' => 'تمت إضافة الكمية للمخزون بنجاح ✅']);

            trigger_cache_rebuild($user_id, $merchant_username);
            exit();

        case 'process_sale':
            if (!$user_id || $user_role !== 'merchant') send_response('error',['message' => 'غير مصرح'], 401);
            
            $pid = sanitize_input($input['productId']); 
            $size_id = sanitize_input($input['sizeId'] ?? null); 
            $qty_to_sell = (int)$input['quantity'];
            
            if ($qty_to_sell <= 0) throw new Exception("الكمية غير صالحة.");

            // 1. جلب بيانات المنتج من TiDB بأمان
            $stmt_sel = $pdo->prepare("SELECT * FROM products WHERE id = ? AND merchant_id = ?");
            $stmt_sel->execute([$pid, $user_id]);
            $product_res = $stmt_sel->fetchAll(PDO::FETCH_ASSOC);

            if (empty($product_res)) throw new Exception("المنتج غير موجود أو لا تملكه.");
            $product = $product_res[0];

            if ($product['quantity_type'] === 'tracked' && $product['quantity'] < $qty_to_sell) {
                throw new Exception("الكمية غير متوفرة في المخزون.");
            }

            // 2. حساب السعر الحقيقي الخالي من التلاعب
            $price = $product['price'] * (1 - (($product['discount']??0)/100)); 
            $options = json_decode($product['options'] ?? '[]', true);
            if ($size_id && is_array($options)) {
                foreach($options as $opt) {
                    if($opt['id'] == $size_id && isset($opt['custom_price'])) $price = $opt['custom_price'];
                }
            }
            
            $total = $price * $qty_to_sell; 
            $cost = ($product['cost_price']??0) * $qty_to_sell; 
            $sid = 'SALE-' . generate_uuid();
            
            // 3. خصم الكمية من TiDB بأمان (عملية ذرية)
            if ($product['quantity_type'] === 'tracked') {
                $stmt_upd = $pdo->prepare("UPDATE products SET quantity = quantity - ? WHERE id = ? AND merchant_id = ? AND quantity >= ?");
                $stmt_upd->execute([$qty_to_sell, $pid, $user_id, $qty_to_sell]);
            }
            
            // 4. تسجيل المبيعات في TiDB
            $stmt_ins = $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, cost_at_sale) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt_ins->execute([$sid, $user_id, $pid, $size_id, $qty_to_sell, $price, $total, $product['currency'], $cost]);
            
            send_response('success',['message' => 'تمت العملية وتحديث المخزون بنجاح', 'saleId' => $sid]);
            break;
            
        case 'get_returnable_sales':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $term = sanitize_input($input['term'] ?? '');
            $sql = "SELECT s.id, s.timestamp, p.name as productName, s.size_id, p.options as sizes, (s.quantity - IFNULL((SELECT SUM(quantity) FROM sales_log WHERE original_sale_id = s.id AND type = 'return'), 0)) as returnable_qty FROM sales_log s JOIN products p ON s.product_id = p.id WHERE s.type = 'sale' AND (s.quantity - IFNULL((SELECT SUM(quantity) FROM sales_log WHERE original_sale_id = s.id AND type = 'return'), 0)) > 0";
            $params =[];
            if ($user_role === 'merchant' || $user_role === 'delivery') { $sql .= " AND s.user_id = ?"; $params[] = $user_id; }
            if ($term) { 
                $sql .= " AND (s.id LIKE ? OR p.name LIKE ?)"; 
                $safe_term = "%" . escape_like_search($term) . "%"; 
                $params[] = $safe_term; 
                $params[] = $safe_term; 
            }
            $sql .= " ORDER BY s.timestamp DESC LIMIT 50";
            $stmt = $pdo->prepare($sql); $stmt->execute($params); $sales = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach($sales as &$sale) { 
                if ($sale['size_id'] && $sale['sizes']) { 
                    $options = json_decode($sale['sizes'], true); 
                    if (is_array($options)) { 
                        foreach($options as $option) { 
                            if (isset($option['id']) && $option['id'] === $sale['size_id']) { 
                                $sale['size_name'] = $option['name'] ?? ($option['size_name'] ?? ''); 
                                break; 
                            } 
                        } 
                    } 
                } 
                unset($sale['sizes']); 
            }
            send_response('success',['data' => $sales]);
            break;

        case 'update_order_status':
        case 'verify_order_generate_code':
            if ($user_role === 'merchant') {
                throw new Exception("ليس لديك الصلاحية لتغيير حالة الطلب بشكل يدوي. النظام يعتمد على قبول المندوب للطلب أولاً لتتمكن من تجهيزه.");
            }
            if ($user_role === 'delivery') {
                throw new Exception("غير مصرح لك. يرجى استخدام المسارات المخصصة لتحديث حالات التوصيل.");
            }
            
            if ($user_role !== 'admin') {
                throw new Exception("هذا الإجراء مخصص للإدارة فقط.");
            }

            $order_id = sanitize_input($input['order_id'] ?? $input['id'] ?? '');
            if (empty($order_id)) throw new Exception("معرف الطلب مفقود.");

            $message = '';
            $extra_data = [];
            $stmt = null;

            if ($action === 'update_order_status') {
                $new_status = sanitize_input($input['status'] ?? '');
                if (empty($new_status)) throw new Exception("الحالة الجديدة مفقودة.");
                
                $sql = "UPDATE live_tickets SET status = ? WHERE ticket_id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$new_status, $order_id]);
                
                if ($stmt->rowCount() === 0) {
                    $sql = "UPDATE orders SET status = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$new_status, $order_id]);
                }
                
                $message = "تم تحديث حالة الطلب من قبل الإدارة بنجاح.";
            } 
            elseif ($action === 'verify_order_generate_code') {
                $new_code = rand(1000, 9999);
                
                $sql = "UPDATE live_tickets SET delivery_code = ? WHERE ticket_id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$new_code, $order_id]);
                
                if ($stmt->rowCount() === 0) {
                    $sql = "UPDATE orders SET delivery_code = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$new_code, $order_id]);
                }
                
                $message = "تم إعادة توليد كود التسليم بنجاح.";
                $extra_data = ['new_code' => $new_code];
            }

            if ($stmt && $stmt->rowCount() > 0) { 
                send_response('success', array_merge(['message' => $message], $extra_data)); 
            } else { 
                throw new Exception('لم يتم العثور على الطلب أو أن الحالة لم تتغير.'); 
            }
            break;

        case 'merchant_approve_order':
            // 🔒 معطّل عمداً: موافقة التاجر على الطلب صارت عبر update_order_status بالـ Worker.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
    
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']);
            
            $sql = "UPDATE live_tickets SET status = 'confirmed_by_store' WHERE ticket_id = ? AND merchant_id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$order_id, $user_id]);
            
            if ($stmt->rowCount() > 0) {
                // ⭐ تعديل أمني: إرسال إشارة تحديث بدلاً من البيانات الكاملة
                $m_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);
                sync_to_firebase($m_username, "signals/orders_updated", null, time(), 'PUT');     
                update_order_tracking($m_username, $order_id, 'confirmed_by_store');
                sync_ticket_status_to_worker($order_id, 'confirmed_by_store'); // ⭐ مزامنة الحالة إلى D1
                
                send_response('success', ['message' => 'تمت الموافقة على الطلب وجاري تجهيزه.']);
            } else {
                $check = $pdo->prepare("SELECT status FROM live_tickets WHERE ticket_id = ?");
                $check->execute([$order_id]);
                if($check->fetchColumn() === 'confirmed_by_store') {
                    send_response('success', ['message' => 'الطلب قيد التجهيز بالفعل.']);
                } else {
                    throw new Exception("فشل الموافقة على الطلب. قد يكون تم إلغاؤه من قبل العميل.");
                }
            }
            break;

        case 'merchant_update_order_status':
            // 🔒 معطّل عمداً: تحديث حالة الطلب صار عبر update_order_status بالـ Worker.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            if ($user_role !== 'merchant') throw new Exception("غير مصرح.");
            $order_id = sanitize_input($input['order_id']);
            $new_status = sanitize_input($input['status']);
            
            $sql = "UPDATE live_tickets SET status = ? WHERE ticket_id = ? AND merchant_id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$new_status, $order_id, $user_id]);
            
            if ($stmt->rowCount() > 0) {
                $get_order = $pdo->prepare("SELECT ticket_data FROM live_tickets WHERE ticket_id = ?");
                $m_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);
                // تحديث جرس الإشعارات فقط
                sync_to_firebase($m_username, "signals/orders_updated", null, time(), 'PUT');
                update_order_tracking($m_username, $order_id, $new_status);
                sync_ticket_status_to_worker($order_id, $new_status); // ⭐ مزامنة الحالة إلى D1
                send_response('success',['message' => 'تم تحديث حالة الطلب بنجاح.']);
            }
            else throw new Exception("فشل تحديث الحالة.");
            break;

        case 'merchant_confirm_delivery_code':
            // 🔒 معطّل عمداً: تأكيد التسليم صار عبر confirm_delivery_code بالـ Worker.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            $ticket_id = sanitize_input($input['order_id']);
            $code = sanitize_input($input['code']);
            
            if(!$code || strlen($code) !== 4) throw new Exception("يرجى إدخال الكود المكون من 4 أرقام.");

            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT delivery_code, status, ticket_data, customer_id FROM live_tickets WHERE ticket_id = ? AND merchant_id = ? FOR UPDATE"); 
                $stmt->execute([$ticket_id, $user_id]); 
                $ticket = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$ticket) throw new Exception("الطلب غير موجود أو تم تسليمه مسبقاً.");
                if ($ticket['status'] !== 'out_for_delivery') throw new Exception("يجب أن يكون الطلب في حالة 'خرج للتوصيل' أولاً.");
                if ($ticket['delivery_code'] != $code) throw new Exception("كود التسليم غير صحيح. يرجى المراجعة مع العميل.");
                
                $ticket_data = json_decode($ticket['ticket_data'], true);
                $items = $ticket_data['items'] ?? [];
                $currency = $ticket_data['financials']['currency'] ?? 'YER';
                $grand_total = $ticket_data['financials']['grand_total'] ?? 0;

                foreach ($items as $item) {
                    $sid = 'SALE-' . generate_uuid(); 
                    $total_price = $item['price'] * $item['quantity']; 
                    $cost_at_sale = $item['cost_price'] * $item['quantity'];
                    
                    $log_stmt = $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, cost_at_sale, order_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sale', ?, ?)");
                    $log_stmt->execute([$sid, $user_id, $item['product_id'], $item['size_id'], $item['quantity'], $item['price'], $total_price, $currency, $cost_at_sale, $ticket_id]);
                }
                
                $archive_stmt = $pdo->prepare("INSERT INTO orders_archive (ticket_id, customer_id, merchant_id, final_status, total_amount, archived_data) VALUES (?, ?, ?, 'completed', ?, ?)");
                $archive_stmt->execute([$ticket_id, $ticket['customer_id'], $user_id, $grand_total, json_encode($ticket_data, JSON_UNESCAPED_UNICODE)]);

                $pdo->prepare("DELETE FROM live_tickets WHERE ticket_id = ?")->execute([$ticket_id]);
                
                $pdo->commit();

                $m_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);
                // إرسال إشارة للمتصفح بجلب البيانات المحدثة
                sync_to_firebase($m_username, "signals/orders_updated", null, time(), 'PUT');
                update_order_tracking($m_username, $ticket_id, 'completed');
                sync_ticket_status_to_worker($ticket_id, 'completed'); // ⭐ مزامنة الحالة إلى D1
                
                send_response('success',['message' => 'تم تأكيد التسليم بنجاح وتوثيق الأرباح في رصيدك!']);
                
            } catch (Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                throw $e; 
            }
            break;
             
        case 'get_financial_report':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $params =[]; $user_condition = "";
            if ($user_role === 'merchant' || $user_role === 'delivery') { $user_condition = " AND user_id = ?"; $params[] = $user_id; }
            $rev = $pdo->prepare("SELECT currency, SUM(total_price) FROM sales_log WHERE type='sale' $user_condition GROUP BY currency"); $rev->execute($params); $revenue = $rev->fetchAll(PDO::FETCH_KEY_PAIR);
            $cog = $pdo->prepare("SELECT currency, SUM(cost_at_sale) FROM sales_log WHERE type='sale' $user_condition GROUP BY currency"); $cog->execute($params); $cogs = $cog->fetchAll(PDO::FETCH_KEY_PAIR);
            $ex_sql = "SELECT currency, SUM(amount) FROM expenses WHERE 1=1"; $ex_params = ($user_role === 'merchant' || $user_role === 'delivery') ?[$user_id] :[];
            if ($user_role === 'merchant' || $user_role === 'delivery') { $ex_sql .= " AND user_id = ?"; } else { $ex_sql .= " AND user_id = (SELECT id FROM users WHERE role='admin' LIMIT 1)"; }
            $ex = $pdo->prepare($ex_sql); $ex->execute($ex_params); $expenses = $ex->fetchAll(PDO::FETCH_KEY_PAIR);
            $gross =[]; $net =[]; $currencies = array_unique(array_merge(array_keys($revenue), array_keys($cogs), array_keys($expenses)));
            foreach ($currencies as $curr) { $r = $revenue[$curr] ?? 0; $c = $cogs[$curr] ?? 0; $e = $expenses[$curr] ?? 0; $gross[$curr] = $r - $c; $net[$curr] = $gross[$curr] - $e; }
            send_response('success',['data' =>['totalRevenue' => $revenue, 'cogs' => $cogs, 'totalExpenses' => $expenses, 'grossProfit' => $gross, 'netProfit' => $net ]]);
            break;
            
        case 'get_stats':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $params =[]; $user_condition = "";
            if ($user_role === 'merchant' || $user_role === 'delivery') { $user_condition = " AND s.user_id = ?"; $params[] = $user_id; }
            $daily_sql = "SELECT DATE(s.timestamp) as date, s.currency, SUM(s.total_price) as total, COUNT(s.id) as count FROM sales_log s WHERE s.type='sale' AND s.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) $user_condition GROUP BY date, s.currency ORDER BY date DESC";
            $daily_stmt = $pdo->prepare($daily_sql); $daily_stmt->execute($params);
            
            $sales_log_sql = "SELECT s.id, s.quantity, s.total_price, s.currency, s.timestamp, p.name as productName FROM sales_log s JOIN products p ON s.product_id = p.id WHERE s.type='sale' $user_condition ORDER BY s.timestamp DESC LIMIT 20";
            $sales_log_stmt = $pdo->prepare($sales_log_sql); $sales_log_stmt->execute($params);
            
            $returns_log_sql = "SELECT s.id, s.quantity, s.total_price, s.currency, s.timestamp, p.name as productName FROM sales_log s JOIN products p ON s.product_id = p.id WHERE s.type='return' $user_condition ORDER BY s.timestamp DESC LIMIT 20";
            $returns_log_stmt = $pdo->prepare($returns_log_sql); $returns_log_stmt->execute($params);
            
            send_response('success',['data' =>[ 'daily' => $daily_stmt->fetchAll(PDO::FETCH_ASSOC), 'salesLog' => $sales_log_stmt->fetchAll(PDO::FETCH_ASSOC), 'returnsLog' => $returns_log_stmt->fetchAll(PDO::FETCH_ASSOC) ]]);
            break;
            
        case 'add_expense':
            if ($user_role !== 'admin') throw new Exception("المصروفات خاصة بالمدير فقط.");
            $stmt = $pdo->prepare("INSERT INTO expenses (user_id, expense_date, category, description, amount, currency) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$user_id, sanitize_input($input['expense_date']), sanitize_input($input['category']), sanitize_input($input['description'] ?? ''), (float)$input['amount'], sanitize_input($input['currency'])]);
            send_response('success',['message' => 'تم الحفظ']);
            break;
            
        case 'get_expenses':
            if ($user_role !== 'admin') throw new Exception("المصروفات خاصة بالمدير فقط.");
            $sql = "SELECT id, user_id, expense_date, category, description, amount, currency, created_at FROM expenses ORDER BY expense_date DESC"; $stmt = $pdo->query($sql);
            send_response('success',['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;
            
        case 'delete_expense':
            if ($user_role !== 'admin') throw new Exception("المصروفات خاصة بالمدير فقط.");
            $sql = "DELETE FROM expenses WHERE id = ?"; $stmt = $pdo->prepare($sql); $stmt->execute([sanitize_input($input['id'])]);
            if ($stmt->rowCount()) send_response('success',['message' => 'تم الحذف']);
            throw new Exception('فشل الحذف');
            break;

        case 'save_settings':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $json = json_encode($input['settings'], JSON_UNESCAPED_UNICODE);
            $pdo->prepare("INSERT INTO settings (setting_key, setting_value) VALUES ('store_settings', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)")->execute([$json]);
            send_response('success',['message' => 'تم الحفظ']);
            break;
            
        case 'get_settings':
            $stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'store_settings'");
            $val = $stmt->fetchColumn();
            send_response('success',['data' =>['store_settings' => json_decode($val ?: '{}', true)]]);
            break;
        
        case 'verify_pin':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            
            define('MAX_PIN_ATTEMPTS', 3);
            define('PIN_LOCKOUT_MINUTES', 15);

            if (isset($_SESSION['pin_lockout_until']) && time() < $_SESSION['pin_lockout_until']) {
                $remaining_time = ceil(($_SESSION['pin_lockout_until'] - time()) / 60);
                throw new Exception("محاولات كثيرة خاطئة. يرجى الانتظار {$remaining_time} دقائق.");
            }

            $pin_attempt = $input['pin'] ?? '';
            $stmt = $pdo->prepare("SELECT pin FROM users WHERE id = ? AND role = 'admin' LIMIT 1");
            $stmt->execute([$user_id]);
            $correct_pin = $stmt->fetchColumn();

            if ($correct_pin !== null && $pin_attempt === $correct_pin) {
                unset($_SESSION['pin_attempts']);
                send_response('success',['message' => 'تم التحقق بنجاح.']);
            } else {
                $_SESSION['pin_attempts'] = ($_SESSION['pin_attempts'] ?? 0) + 1;

                if ($_SESSION['pin_attempts'] >= MAX_PIN_ATTEMPTS) {
                    $_SESSION['pin_lockout_until'] = time() + (PIN_LOCKOUT_MINUTES * 60);
                    unset($_SESSION['pin_attempts']);
                    throw new Exception("تم قفل الإجراءات الحساسة لمدة " . PIN_LOCKOUT_MINUTES . " دقائق لكثرة المحاولات الخاطئة.");
                }

                throw new Exception("رمز PIN غير صحيح. المحاولة رقم " . $_SESSION['pin_attempts'] . " من " . MAX_PIN_ATTEMPTS . ".");
            }
            break;
             
        case 'update_pin':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $current = $input['current_pin']; $new = $input['new_pin']; $confirm = $input['confirm_new_pin'];
            $stmt = $pdo->prepare("SELECT pin FROM users WHERE id = ?"); $stmt->execute([$user_id]); $user_pin = $stmt->fetchColumn();
            if ($user_pin !== null && $current != $user_pin) throw new Exception("الرمز الحالي غير صحيح");
            if (strlen($new) < 4) throw new Exception("الرمز الجديد قصير جداً"); if ($new !== $confirm) throw new Exception("الرمزان الجديدان غير متطابقين");
            $pdo->prepare("UPDATE users SET pin = ? WHERE id = ?")->execute([$new, $user_id]);
            send_response('success',['message' => 'تم تحديث الرمز']);
            break;

        case 'update_admin_username':
            if ($user_role !== 'admin') send_response('error',[], 401);
            $new_username = sanitize_input($input['new_username']); $password = $input['password'];
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?"); $stmt->execute([$user_id]);
            if (!password_verify($password, $stmt->fetchColumn())) throw new Exception("كلمة المرور الحالية غير صحيحة.");
            $check = $pdo->prepare("SELECT id FROM users WHERE username = ? AND id != ?"); $check->execute([$new_username, $user_id]);
            if ($check->fetch()) throw new Exception("اسم المستخدم الجديد محجوز.");
            $pdo->prepare("UPDATE users SET username = ? WHERE id = ?")->execute([$new_username, $user_id]); $_SESSION['username'] = $new_username;
            send_response('success',['message' => 'تم تحديث اسم المستخدم. سيتم تحديث الصفحة.']);
            break;
        
        case 'update_admin_password':
        case 'update_merchant_password':
            if (!$user_id) send_response('error',[], 401);
            $current = $input['current_password']; $new = $input['new_password'];
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?"); $stmt->execute([$user_id]);
            if (!password_verify($current, $stmt->fetchColumn())) throw new Exception("كلمة المرور الحالية خاطئة.");
            if (strlen($new) < 8) throw new Exception("كلمة المرور الجديدة قصيرة جداً.");
            $hashed = password_hash($new, PASSWORD_DEFAULT);
            
            // تحديث كلمة المرور وتسجيل وقت التحديث
            try { $pdo->exec("ALTER TABLE users ADD COLUMN password_changed_at DATETIME NULL"); } catch(Exception $e){}
            $pdo->prepare("UPDATE users SET password = ?, password_changed_at = NOW() WHERE id = ?")->execute([$hashed, $user_id]);
            
            // جلب بصمة الجهاز الحالي الذي قام بتغيير الباسورد لكي لا يتم طرده
            $current_device_token = $_SESSION['current_device_token'] ?? $_COOKIE['device_token'] ?? '';
            
            // حذف جـمـيـع الأجهزة والجلسات السابقة المرتبطة بهذا التاجر باستثناء جهازه الحالي
            $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ? AND device_token != ?")->execute([$user_id, $current_device_token]);

            send_response('success',['message' => 'تم تحديث كلمة المرور بنجاح. تم طرد وتسجيل الخروج من جميع الأجهزة الأخرى فوراً.']);
            break;

        case 'get_customers':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $term = sanitize_input($input['term'] ?? '');
            
            $sql = "SELECT c.id, c.full_name, c.phone, c.address, c.is_verified, c.is_active, c.created_at, (SELECT COUNT(*) FROM orders WHERE customer_id = c.id) as order_count FROM customers c";
            $params =[];
            if ($term) { 
                $sql .= " WHERE c.full_name LIKE ? OR c.phone LIKE ?"; 
                $safe_term = "%" . escape_like_search($term) . "%"; 
                $params =[$safe_term, $safe_term]; 
            }
            $stmt = $pdo->prepare($sql); $stmt->execute($params);
            send_response('success',['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;
            
        case 'get_customer_details':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $stmt = $pdo->prepare("SELECT id, full_name, phone, address FROM customers WHERE id = ?"); $stmt->execute([sanitize_input($input['id'])]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($customer) send_response('success',['data' => $customer]);
            throw new Exception("المستخدم غير موجود");
            break;
            
        case 'update_customer_details':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");

            $allowed_fields =['id', 'full_name', 'phone', 'address'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $sql = "UPDATE customers SET full_name = ?, phone = ?, address = ? WHERE id = ?";
            $pdo->prepare($sql)->execute([
                sanitize_input($safe_input['full_name'] ?? ''), 
                sanitize_input($safe_input['phone'] ?? ''), 
                sanitize_input($safe_input['address'] ?? ''), 
                sanitize_input($safe_input['id'] ?? '')
            ]);
            send_response('success',['message' => 'تم تحديث بيانات المستخدم']);
            break;
            
        case 'toggle_customer_status':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $status_val = (int)$input['status'];
            $customer_id_to_toggle = sanitize_input($input['id']);
            $pdo->prepare("UPDATE customers SET is_active = ? WHERE id = ?")->execute([$status_val, $customer_id_to_toggle]);
            
            if ($status_val == 0) {
                $pdo->prepare("DELETE FROM auth_tokens WHERE user_id = ?")->execute([$customer_id_to_toggle]);
            }
            
            send_response('success',['message' => 'تم تحديث حالة المستخدم']);
            break;
            
        case 'admin_reset_customer_password':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $new_pass = !empty($input['new_password']) ? $input['new_password'] : bin2hex(random_bytes(4));
            $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
            $customer_id_to_reset = sanitize_input($input['id']);
            $pdo->prepare("UPDATE customers SET password = ? WHERE id = ?")->execute([$hashed, $customer_id_to_reset]);
            
            $pdo->prepare("DELETE FROM auth_tokens WHERE user_id = ?")->execute([$customer_id_to_reset]);
            
            send_response('success',['message' => 'تمت إعادة التعيين، وتم طرد العميل من كافة الأجهزة لاحتياطات الأمان.', 'new_password' => $new_pass]);
            break;

        case 'get_merchants':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $sql = "SELECT u.id, u.username, u.store_name, u.phone, u.created_at, u.is_active, u.settings, (SELECT COUNT(*) FROM products WHERE products.merchant_id = u.id) as product_count FROM users u WHERE u.role IN ('merchant', 'delivery') ORDER BY u.created_at DESC";
            $stmt = $pdo->query($sql);
            send_response('success',['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;
            
        case 'add_merchant':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");

            $allowed_fields =['username', 'store_name', 'password', 'phone', 'location'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $u = sanitize_input($safe_input['username'] ?? ''); 
            $s = sanitize_input($safe_input['store_name'] ?? ''); 
            $p = $safe_input['password'] ?? ''; 
            $phone = sanitize_input($safe_input['phone'] ?? ''); 
            $role = 'merchant'; 
            $location = sanitize_input($safe_input['location'] ?? null);
            
            if (!empty($location) && !is_valid_gps_location($location)) {
                throw new Exception("رابط موقع المتجر غير صالح أو يقع خارج النطاق الجغرافي المسموح به.");
            }
            
            $settings_json = json_encode(['location' => $location]);

            if (empty($u) || empty($s) || empty($p) || empty($phone)) throw new Exception("الرجاء ملء جميع الحقول.");
            if (strlen($p) < 8) throw new Exception("كلمة المرور يجب أن تكون 8 أحرف على الأقل.");
            $check = $pdo->prepare("SELECT id FROM users WHERE username = ?"); $check->execute([$u]);
            if ($check->fetch()) throw new Exception("اسم المستخدم موجود مسبقاً");
            $hashed_pass = password_hash($p, PASSWORD_DEFAULT);
            $pdo->prepare("INSERT INTO users (username, password, store_name, phone, role, settings) VALUES (?, ?, ?, ?, ?, ?)")->execute([$u, $hashed_pass, $s, $phone, $role, $settings_json]);
            send_response('success',['message' => 'تمت إضافة المستخدم بنجاح']);
            break;
        
        case 'update_merchant':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");

            $allowed_fields =['id', 'username', 'store_name', 'password', 'phone', 'location'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $id = sanitize_input($safe_input['id'] ?? ''); 
            $u = sanitize_input($safe_input['username'] ?? ''); 
            $s = sanitize_input($safe_input['store_name'] ?? ''); 
            $p = $safe_input['password'] ?? null; 
            $phone = sanitize_input($safe_input['phone'] ?? ''); 
            $role = 'merchant'; 
            $location = sanitize_input($safe_input['location'] ?? null);
            
            if (!empty($location) && !is_valid_gps_location($location)) {
                throw new Exception("رابط موقع المتجر غير صالح أو يقع خارج النطاق الجغرافي المسموح به.");
            }
            
            $settings_json = json_encode(['location' => $location]);

            if (empty($u) || empty($s) || empty($id) || empty($phone)) throw new Exception("بيانات غير مكتملة.");
            $check = $pdo->prepare("SELECT id FROM users WHERE username = ? AND id != ?"); $check->execute([$u, $id]); if ($check->fetch()) throw new Exception("اسم المستخدم الجديد موجود مسبقاً.");
            
            $sql = "UPDATE users SET username = ?, store_name = ?, phone = ?, role = ?, settings = ?";
            $params =[$u, $s, $phone, $role, $settings_json];
            
            if (!empty($p)) {
                if (strlen($p) < 8) throw new Exception("كلمة المرور يجب أن تكون 8 أحرف على الأقل.");
                $hashed_pass = password_hash($p, PASSWORD_DEFAULT);
                $sql .= ", password = ?";
                $params[] = $hashed_pass;
            }
            
            $sql .= " WHERE id = ?";
            $params[] = $id;

            $pdo->prepare($sql)->execute($params);
            
            if (!empty($p)) {
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?")->execute([$id]);
            }
            
            send_response('success',['message' => 'تم تحديث بيانات المستخدم']);
            break;

        case 'toggle_merchant_status':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $id = sanitize_input($input['id']); $status = (int)$input['status'];
            $pdo->prepare("UPDATE users SET is_active = ? WHERE id = ? AND role != 'admin'")->execute([$status, $id]);
            
            if ($status == 0) {
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?")->execute([$id]);
            }
            
            send_response('success',['message' => 'تم تحديث حالة المستخدم']);
            break;
            
        case 'delete_merchant':
            if ($user_role !== 'admin') throw new Exception("للمدير فقط");
            $merchant_id = sanitize_input($input['id']);
            try {
                $pdo->beginTransaction();
                $pdo->prepare("UPDATE products SET merchant_id = NULL WHERE merchant_id = ?")->execute([$merchant_id]);
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?")->execute([$merchant_id]);
                $pdo->prepare("DELETE FROM users WHERE id = ? AND role != 'admin'")->execute([$merchant_id]);
                $pdo->commit(); send_response('success',['message' => 'تم حذف المستخدم وإلغاء ربط منتجاته']);
            } catch (Exception $e) { if($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;

        case 'get_merchant_settings':
            if (!$user_id || !in_array($user_role, ['merchant', 'delivery'])) {
                send_response('error', ['message' => 'غير مصرح لك بالوصول'], 401);
            }
            // ✅ إصلاح: جلب بيانات شاملة تشمل بيانات التسجيل الأولي
            $stmt = $pdo->prepare("SELECT id, username, store_name, phone, store_type, settings, created_at FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $merchantData = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($merchantData) {
                // ✅ فك تشفير settings مع ضمان القيمة الافتراضية
                if (!empty($merchantData['settings'])) {
                    $decoded = json_decode($merchantData['settings'], true);
                    $merchantData['settings'] = is_array($decoded) ? $decoded : [];
                } else {
                    $merchantData['settings'] = [];
                }
                
                // ✅ إرجاع علم is_first_login ليعرف الفرونت أنه تسجيل أول
                $merchantData['is_first_login'] = empty($merchantData['store_name']) || $merchantData['store_name'] === $merchantData['username'];
                
                // ✅ حساب طابع زمني للكاش ليعرف الفرونت متى يجدد
                $merchantData['data_fetched_at'] = time();
                
                send_response('success', ['data' => $merchantData]);
            } else {
                throw new Exception("لم يتم العثور على بيانات الحساب.");
            }
            break;
        case 'merchant_cancel_order':
            // 🔒 معطّل عمداً: إلغاء الطلب صار عبر cancel_order بالـ Worker.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']);
            $reason = sanitize_input($input['reason'] ?? 'تم الإلغاء من قبل التاجر');
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);

            try {
                $pdo->beginTransaction();
                
                $stmt = $pdo->prepare("SELECT ticket_id, customer_id, ticket_data, status FROM live_tickets WHERE ticket_id = ? AND merchant_id = ? FOR UPDATE");
                $stmt->execute([$order_id, $user_id]);
                $ticket = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$ticket) throw new Exception("الطلب غير موجود أو تم التعامل معه مسبقاً.");

                $ticket_data = json_decode($ticket['ticket_data'], true) ?: [];
                $ticket_data['cancel_reason'] = $reason;
                $ticket_data['id'] = $order_id;
                $ticket_data['status'] = 'cancelled';

                $archive_stmt = $pdo->prepare("INSERT INTO orders_archive (ticket_id, customer_id, merchant_id, final_status, total_amount, archived_data) VALUES (?, ?, ?, 'cancelled', ?, ?)");
                $grand_total = $ticket_data['financials']['grand_total'] ?? 0;
                $archive_stmt->execute([$order_id, $ticket['customer_id'], $user_id, $grand_total, json_encode($ticket_data, JSON_UNESCAPED_UNICODE)]);

                // 1. استرجاع الكميات إلى قاعدة بيانات TiDB Cloud (PDO) مباشرة
                $items = $ticket_data['items'] ?? [];
                $inventory_changed = false;

                foreach ($items as $item) {
                    $pid = $item['product_id'];
                    $qty = (int)$item['quantity'];
                    $size_id = $item['size_id'] ?? null;
                    
                    // جلب المنتج من TiDB للتأكد من نوع الكمية وصحتها
                    $stmt_prod_check = $pdo->prepare("SELECT quantity_type, options FROM products WHERE id = ? AND merchant_id = ?");
                    $stmt_prod_check->execute([$pid, $user_id]);
                    $db_prod = $stmt_prod_check->fetch(PDO::FETCH_ASSOC);
                    
                    if ($db_prod && $db_prod['quantity_type'] === 'tracked') {
                        $inventory_changed = true;

                        if (!empty($size_id)) {
                            $options_array = json_decode($db_prod['options'] ?: '[]', true);
                            $total_remaining_qty = 0;
                            
                            foreach ($options_array as &$opt) {
                                if (isset($opt['id']) && $opt['id'] === $size_id) {
                                    $opt['quantity'] = (int)($opt['quantity'] ?? 0) + $qty;
                                }
                                $total_remaining_qty += (int)($opt['quantity'] ?? 0);
                            }
                            unset($opt);
                            
                            $stmt_upd_prod = $pdo->prepare("UPDATE products SET quantity = ?, options = ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                            $stmt_upd_prod->execute([$total_remaining_qty, json_encode($options_array, JSON_UNESCAPED_UNICODE), time(), $pid, $user_id]);
                        } else {
                            $stmt_upd_prod = $pdo->prepare("UPDATE products SET quantity = quantity + ?, updated_at = ? WHERE id = ? AND merchant_id = ?");
                            $stmt_upd_prod->execute([$qty, time(), $pid, $user_id]);
                        }
                    }
                }

                $pdo->prepare("DELETE FROM live_tickets WHERE ticket_id = ?")->execute([$order_id]);
                $pdo->commit();

                // 🚀 2. تحديث الكاش السحابي تلقائياً بعد استرجاع المخزون
                if ($inventory_changed) {
                    trigger_cache_rebuild($user_id, $merchant_username);
                }

        // 3. إرسال إشارة تنبيه للمتصفح لتحديث الواجهة عبر الـ API
                sync_to_firebase($merchant_username, "signals/orders_updated", null, time(), 'PUT');
                update_order_tracking($merchant_username, $order_id, 'cancelled');
                sync_ticket_status_to_worker($order_id, 'cancelled'); // ⭐ مزامنة الحالة إلى D1

                send_response('success', ['message' => 'تم إلغاء الطلب بنجاح وإعادة المنتجات للمخزون.']);
            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $e;
            }
            break;

        case 'worker_sync_new_order':
            // 🔒 معطّل عمداً (2026-07-22): لم يعد الـ Worker يستدعي هذا المسار، لأن
            // إنشاء/إدارة الطلبات بالكامل صار على D1 مباشرة بدون كتابة موازية على TiDB.
            send_response('error', ['message' => 'هذا الإجراء لم يعد متاحاً من هنا.'], 410);
            $sync_key_header = $_SERVER['HTTP_X_INTERNAL_KEY'] ?? '';
            $sync_expected_key = getenv('INTERNAL_SYNC_KEY') ?: ($_ENV['INTERNAL_SYNC_KEY'] ?? '');
            if (empty($sync_expected_key) || !hash_equals($sync_expected_key, $sync_key_header)) {
                send_response('error', ['message' => 'غير مصرح'], 401);
            }

            $wt_ticket_id = sanitize_input($input['ticket_id'] ?? '');
            $wt_order_group_id = sanitize_input($input['order_group_id'] ?? '');
            $wt_merchant_id = sanitize_input($input['merchant_id'] ?? '');
            $wt_customer_id = sanitize_input($input['customer_id'] ?? '');
            $wt_status = sanitize_input($input['status'] ?? 'pending_merchant_approval');
            $wt_delivery_code = (int)($input['delivery_code'] ?? 0);
            $wt_ticket_data_raw = $input['ticket_data'] ?? '{}';
            $wt_ticket_data = is_string($wt_ticket_data_raw) ? $wt_ticket_data_raw : json_encode($wt_ticket_data_raw, JSON_UNESCAPED_UNICODE);

            if (empty($wt_ticket_id) || empty($wt_merchant_id) || empty($wt_customer_id)) {
                send_response('error', ['message' => 'بيانات التذكرة ناقصة'], 400);
            }

            $stmt_wt = $pdo->prepare(
                "INSERT INTO live_tickets (ticket_id, order_group_id, merchant_id, customer_id, status, delivery_code, ticket_data)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                    ticket_data = VALUES(ticket_data),
                    status = VALUES(status)"
            );
            $stmt_wt->execute([$wt_ticket_id, $wt_order_group_id, $wt_merchant_id, $wt_customer_id, $wt_status, $wt_delivery_code, $wt_ticket_data]);

            send_response('success', ['message' => 'تمت مزامنة الطلب مع TiDB بنجاح']);
            break;

        case 'worker_sync_settings':
            // ⚠️ هذا المسار لا يُستدعى من الواجهة أبداً - فقط من الـ Worker نفسه
            // (بعد أن يحفظ إعدادات التاجر في D1) ليُبقي TiDB متزامنة لأجل
            // تطبيقي المندوب والإدارة اللذين ما زالا يقرآن من TiDB مباشرة.
            $internal_key_header = $_SERVER['HTTP_X_INTERNAL_KEY'] ?? '';
            $expected_internal_key = getenv('INTERNAL_SYNC_KEY') ?: ($_ENV['INTERNAL_SYNC_KEY'] ?? '');
            if (empty($expected_internal_key) || !hash_equals($expected_internal_key, $internal_key_header)) {
                send_response('error', ['message' => 'غير مصرح'], 401);
            }

            $sync_uid = sanitize_input($input['id'] ?? '');
            if (empty($sync_uid)) send_response('error', ['message' => 'معرف المستخدم مطلوب'], 400);

            $sync_store_name = sanitize_input($input['store_name'] ?? '');
            $sync_store_type = sanitize_input($input['store_type'] ?? '');
            $sync_settings_raw = $input['settings'] ?? '{}';
            $sync_settings_json = is_string($sync_settings_raw) ? $sync_settings_raw : json_encode($sync_settings_raw, JSON_UNESCAPED_UNICODE);

            $stmt_sync = $pdo->prepare("UPDATE users SET store_name = ?, store_type = ?, settings = ? WHERE id = ?");
            $stmt_sync->execute([$sync_store_name, $sync_store_type, $sync_settings_json, $sync_uid]);

            // ⚠️ إصلاح: ما عاد نستدعي sync_merchant_info_json هنا. هذا المسار
            // (worker_sync_settings) هدفه فقط إبقاء TiDB متزامنة لتطبيقي المندوب
            // والإدارة - كتابة info.json لواجهة المتجر العامة يتكفل بها الـ Worker
            // نفسه عبر syncStoreInfoToStorefront (بالتوازي مع هذا الطلب بالضبط).
            // الاستدعاء القديم هنا كان يكتب نفس الملف بصيغة JSON مختلفة (مسطّحة
            // بدون مفتاح "data") من مصدر غير متسلسل مع طابور الـ Worker، فيصير
            // تصادم: أي كتابة توصل GitHub متأخرة تمحو حقول الكتابة الثانية بصمت -
            // وهذا سبب ظهور اسم المتجر فقط واختفاء بقية البيانات من info.json.

            send_response('success', ['message' => 'تمت مزامنة الإعدادات مع TiDB بنجاح']);
            break;

        case 'save_merchant_settings':
            if ($user_role !== 'merchant') {
                throw new Exception("غير مصرح لك بالقيام بهذا الإجراء.");
            }
            
            $storeName = sanitize_input($input['storeName'] ?? ''); 
            $storeType = sanitize_input($input['storeType'] ?? null);
            $new_settings = $input['settings'] ?? []; 

            if (empty($storeName)) {
                throw new Exception("اسم المتجر مطلوب ولا يمكن أن يكون فارغاً.");
            }

            $stmt_curr = $pdo->prepare("SELECT settings, store_name, store_type FROM users WHERE id = ?");
            $stmt_curr->execute([$user_id]);
            $user_record = $stmt_curr->fetch(PDO::FETCH_ASSOC);
            $current_settings = json_decode($user_record['settings'] ?: '{}', true);

            $shipping_changed = (
                (isset($new_settings['free_shipping_enabled']) && $new_settings['free_shipping_enabled'] != ($current_settings['free_shipping_enabled'] ?? null)) ||
                (isset($new_settings['free_shipping_type']) && $new_settings['free_shipping_type'] != ($current_settings['free_shipping_type'] ?? null)) ||
                (isset($new_settings['free_shipping_threshold']) && $new_settings['free_shipping_threshold'] != ($current_settings['free_shipping_threshold'] ?? null))
            );

            if ($shipping_changed) {
                $stmt_check_orders = $pdo->prepare("SELECT COUNT(*) FROM live_tickets WHERE merchant_id = ?");
                $stmt_check_orders->execute([$user_id]);
                $active_orders_count = $stmt_check_orders->fetchColumn();

                if ($active_orders_count > 0) {
                    throw new Exception("عذراً، لا يمكن تغيير سياسة التوصيل حالياً بسبب وجود " . $active_orders_count . " طلبات نشطة قيد التنفيذ. يرجى إكمالها أو أرشفتها أولاً.");
                }
            }

            $final_settings = array_merge($current_settings, $new_settings);
            
            if (empty($final_settings['location'])) $final_settings['location'] = $current_settings['location'] ?? null;
            if (empty($final_settings['phone'])) $final_settings['phone'] = $current_settings['phone'] ?? ($user_record['phone'] ?? null);

            $sql_update = "UPDATE users SET store_name = ?, store_type = ?, settings = ? WHERE id = ?";
            $stmt_update = $pdo->prepare($sql_update);

            // ⭐ تعديل أمني: استعلام مجهز لتأمين جلب اسم المستخدم للتاجر
            $merchant_username = $_SESSION['username'] ?? get_username_by_id($pdo, $user_id);
            $fb_settings = [
                'store_name' => $storeName,
                'store_type' => $storeType ?: $user_record['store_type'],
                'settings' => $final_settings
            ];
            $json_settings = json_encode($final_settings, JSON_UNESCAPED_UNICODE);
            
            // استدعاء الدالة لتوليد ملف info.json ورفعه مع المانيفست
            // 1. أولاً: نقوم بتحديث قاعدة البيانات بالبيانات الجديدة
            $stmt_update->execute([
                $storeName, 
                $storeType ?: $user_record['store_type'], 
                $json_settings, 
                $user_id
            ]);

            // 2. ثانياً: نستدعي الدالة لتقرأ البيانات الجديدة من القاعدة وترفعها لـ GitHub
            sync_merchant_info_json($pdo, $user_id, $merchant_username);

            send_response('success', [
                'message' => 'تم حفظ الإعدادات وتحديث المتجر بنجاح ✅',
                'updated_settings' => $final_settings
            ]);
            break;        

        case 'get_categories':
            $sql = "SELECT name FROM categories WHERE (parent_id IS NULL OR parent_id = 0) AND (user_id IS NULL OR user_id IN (SELECT id FROM users WHERE role = 'admin')) ORDER BY name ASC";
            $cats = $pdo->query($sql)->fetchAll(PDO::FETCH_COLUMN);
            $defaults = ['إلكترونيات', 'أزياء', 'منزل'];
            send_response('success',['data' => array_values(array_unique(array_merge($defaults, $cats)))]);
            break;
            
        case 'get_categories_tree':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            try {
                // ✅ كل تاجر يستلم فقط فئاته الخاصة (user_id = هو) + الفئات العامة المشتركة (user_id = NULL)
                $tree = build_category_tree($pdo, $user_id);
                send_response('success',['data' => $tree]);
            } catch (PDOException $e) {
                send_response('success',['data' => []]);
            }
            break;
            
        case 'create_category':
            // ⚠️ ملاحظة: لوحة التاجر لم تعد تستدعي هذا المسار عند إضافة منتج جديد —
            // إنشاء الفئات (بما فيها الفئات المتداخلة) أصبح يُؤجَّل ويُنفَّذ فقط داخل
            // save_product عند نشر المنتج فعلياً، لتفادي تراكم فئات فارغة في قاعدة البيانات.
            // يبقى هذا المسار متاحاً لأي استخدام إداري/مستقبلي آخر.
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $name = sanitize_input($input['name'] ?? '');
            $parent_id = intval($input['parent_id'] ?? 0);
            
            if (empty($name)) throw new Exception('اسم الفئة مطلوب');
            
            // تحقق أن الفئة الأب (إن وُجدت) تعود لنفس التاجر أو فئة عامة، منعاً لأي تلاعب
            if ($parent_id > 0) {
                $stmt_p = $pdo->prepare("SELECT COUNT(*) FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                $stmt_p->execute([$parent_id, $user_id]);
                if (!$stmt_p->fetchColumn()) $parent_id = 0;
            }
            
            try {
                $new_id = resolve_or_create_category($pdo, $name, $parent_id, $user_id);
                send_response('success',['message' => 'تم إنشاء الفئة بنجاح', 'id' => $new_id]);
            } catch (PDOException $e) {
                throw new Exception('فشل إنشاء الفئة: ' . $e->getMessage());
            }
            break;
            
        case 'update_category':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $id = intval($input['id'] ?? 0);
            $name = sanitize_input($input['name'] ?? '');
            $parent_id = intval($input['parent_id'] ?? 0);
            
            if (empty($name)) throw new Exception('اسم الفئة مطلوب');
            if ($id <= 0) throw new Exception('معرّف الفئة غير صحيح');
            
            try {
                $stmt = $pdo->prepare("UPDATE categories SET name = ?, parent_id = ? WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                $stmt->execute([$name, $parent_id, $id, $user_id]);
                send_response('success',['message' => 'تم تحديث الفئة بنجاح']);
            } catch (PDOException $e) {
                throw new Exception('فشل تحديث الفئة');
            }
            break;
            
        case 'delete_category':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $id = intval($input['id'] ?? 0);
            
            if ($id <= 0) throw new Exception('معرّف الفئة غير صحيح');
            
            try {
                // التحقق من عدم وجود منتجات أو فئات فرعية
                $check_prods = $pdo->prepare("SELECT COUNT(*) FROM products WHERE category_id = ?");
                $check_prods->execute([$id]);
                if ($check_prods->fetchColumn() > 0) throw new Exception('لا يمكن حذف فئة تحتوي على منتجات');
                
                $check_children = $pdo->prepare("SELECT COUNT(*) FROM categories WHERE parent_id = ?");
                $check_children->execute([$id]);
                if ($check_children->fetchColumn() > 0) throw new Exception('لا يمكن حذف فئة تحتوي على فئات فرعية');
                
                $stmt = $pdo->prepare("DELETE FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)");
                $stmt->execute([$id, $user_id]);
                send_response('success',['message' => 'تم حذف الفئة بنجاح']);
            } catch (PDOException $e) {
                throw new Exception('فشل حذف الفئة');
            }
            break;

        case 'get_delivery_agent_stats':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            
            $earnings_stmt = $pdo->prepare("SELECT currency, SUM(delivery_fee) as total FROM orders WHERE delivery_agent_id = ? AND status = 'completed' GROUP BY currency");
            $earnings_stmt->execute([$user_id]);
            $raw_earnings = $earnings_stmt->fetchAll(PDO::FETCH_KEY_PAIR);

            $total_earnings =[]; $commission_rate = 0.80; 
            foreach($raw_earnings as $currency => $total_fee) { $total_earnings[$currency] = $total_fee * $commission_rate; }
            $completed_stmt = $pdo->prepare("SELECT COUNT(*) FROM orders WHERE delivery_agent_id = ? AND status = 'completed'");
            $completed_stmt->execute([$user_id]);
            $total_completed = (int)$completed_stmt->fetchColumn();

            $daily_stmt = $pdo->prepare("SELECT DATE(created_at) as date, COUNT(*) as count FROM orders WHERE delivery_agent_id = ? AND status = 'completed' AND created_at >= CURDATE() - INTERVAL 7 DAY GROUP BY date ORDER BY date ASC");
            $daily_stmt->execute([$user_id]);
            
            // ⭐ تصحيح أمني وبرمجي: استبدال المتغير المتسبب في خطأ بـ $daily_stmt الصحيح لجلب البيانات
            $daily_stats = $daily_stmt->fetchAll(PDO::FETCH_ASSOC);
            
            send_response('success',[ 'data' =>[ 'total_completed' => $total_completed, 'total_earnings' => $total_earnings, 'daily_stats' => $daily_stats ] ]);
            break;

        case 'get_available_orders':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            
            $stmt_check = $pdo->prepare("SELECT store_name FROM users WHERE id = ?");
            $stmt_check->execute([$user_id]);
            if (empty($stmt_check->fetchColumn())) {
                throw new Exception("REQUIRE_PROFILE_UPDATE: يرجى استكمال بياناتك في الإعدادات لتتمكن من استلام الطلبات.");
            }

            $page = max(1, intval($input['page'] ?? 1)); 
            $limit = max(1, min(50, intval($input['limit'] ?? 10))); 
            $offset = ($page - 1) * $limit;
            
            $sql = "SELECT ticket_id as id, status, created_at, ticket_data 
                    FROM live_tickets 
                    WHERE status = 'pending_delivery_acceptance' AND delivery_agent_id IS NULL 
                    ORDER BY created_at ASC LIMIT :limit OFFSET :offset";

            $stmt = $pdo->prepare($sql); 
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT); 
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT); 
            $stmt->execute(); 
            $tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $orders = [];
            foreach ($tickets as $t) {
                $data = json_decode($t['ticket_data'], true);
                if (!is_array($data)) continue;
                $orders[] = [
                    'id' => $t['id'],
                    'total_amount' => $data['financials']['grand_total'] ?? 0,
                    'currency' => $data['financials']['currency'] ?? 'YER',
                    'delivery_fee' => $data['financials']['delivery_fee'] ?? 0,
                    'status' => $t['status'],
                    'created_at' => $t['created_at'],
                    'customer_name' => $data['customer']['name'] ?? 'عميل',
                    'merchant_name' => $data['merchant']['name'] ?? 'متجر'
                ];
            }

            send_response('success',[ 'data' => $orders, 'total_orders' => count($orders), 'current_page' => $page, 'limit' => $limit ]);
            break;

        case 'get_my_orders':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $page = max(1, intval($input['page'] ?? 1)); 
            $limit = max(1, min(50, intval($input['limit'] ?? 10))); 
            $offset = ($page - 1) * $limit;
            
            $sql = "SELECT ticket_id as id, status, created_at, ticket_data 
                    FROM live_tickets 
                    WHERE delivery_agent_id = :user_id 
                    ORDER BY CASE status WHEN 'accepted_by_delivery' THEN 1 WHEN 'out_for_delivery' THEN 2 ELSE 3 END, created_at DESC 
                    LIMIT :limit OFFSET :offset";

            $stmt = $pdo->prepare($sql); 
            $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT); 
            $stmt->bindParam(':limit', $limit, PDO::PARAM_INT); 
            $stmt->bindParam(':offset', $offset, PDO::PARAM_INT); 
            $stmt->execute(); 
            $tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $orders = [];
            foreach ($tickets as $t) {
                $data = json_decode($t['ticket_data'], true);
                if (!is_array($data)) continue;
                $orders[] = [
                    'id' => $t['id'],
                    'total_amount' => $data['financials']['grand_total'] ?? 0,
                    'currency' => $data['financials']['currency'] ?? 'YER',
                    'delivery_fee' => $data['financials']['delivery_fee'] ?? 0,
                    'delivery_address_text' => $data['customer']['address_text'] ?? '',
                    'delivery_gps_link' => $data['customer']['gps_link'] ?? '',
                    'status' => $t['status'],
                    'created_at' => $t['created_at'],
                    'customer_name' => $data['customer']['name'] ?? 'عميل',
                    'customer_phone' => $data['customer']['phone'] ?? '',
                    'merchant_name' => $data['merchant']['name'] ?? 'متجر',
                    'items' => $data['items'] ?? []
                ];
            }
            send_response('success',[ 'data' => $orders, 'total_orders' => count($orders), 'current_page' => $page, 'limit' => $limit ]);
            break;

        case 'accept_order':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            
            $stmt_check = $pdo->prepare("SELECT store_name FROM users WHERE id = ?");
            $stmt_check->execute([$user_id]);
            if (empty($stmt_check->fetchColumn())) {
                throw new Exception("REQUIRE_PROFILE_UPDATE: يرجى استكمال بياناتك في الإعدادات أولاً.");
            }

            $active_orders_stmt = $pdo->prepare("SELECT COUNT(*) FROM live_tickets WHERE delivery_agent_id = ? AND status IN ('accepted_by_delivery', 'out_for_delivery')");
            $active_orders_stmt->execute([$user_id]);
            if ((int)$active_orders_stmt->fetchColumn() >= DELIVERY_AGENT_MAX_ORDERS) {
                throw new Exception("لا يمكنك قبول طلبات جديدة. لديك طلبات غير مكتملة.");
            }
            
            $order_id = sanitize_input($input['order_id']);
            try {
                $pdo->beginTransaction();
                
                $stmt = $pdo->prepare("SELECT status, delivery_agent_id, ticket_data FROM live_tickets WHERE ticket_id = ? FOR UPDATE"); 
                $stmt->execute([$order_id]); 
                $ticket = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$ticket) throw new Exception("الطلب غير موجود.");
                if ($ticket['status'] !== 'pending_delivery_acceptance' && $ticket['status'] !== 'confirmed') {
                    throw new Exception("عذراً، هذا الطلب تم قبوله من مندوب آخر أو لم يعد متاحاً.");
                }
                if ($ticket['delivery_agent_id'] !== null) {
                    throw new Exception("عذراً، هذا الطلب مرتبط بمندوب آخر.");
                }
                
                $data = json_decode($ticket['ticket_data'], true);
                if (!is_array($data)) $data = [];
                
                // ⭐ تعديل أمني: جلب الاسم الرسمي للمندوب من قاعدة البيانات مباشرة لتفادي تزوير الجلسات
                $delivery_agent_name = $_SESSION['store_name'] ?? get_store_name_by_id($pdo, $user_id);
                
                $data['delivery_agent'] = [
                    'id' => $user_id,
                    'name' => $delivery_agent_name
                ];
                $new_json = json_encode($data, JSON_UNESCAPED_UNICODE);

                $update_stmt = $pdo->prepare("UPDATE live_tickets SET delivery_agent_id = ?, status = 'accepted_by_delivery', ticket_data = ? WHERE ticket_id = ?");
                $update_stmt->execute([$user_id, $new_json, $order_id]);
                
                $pdo->commit();
                send_response('success',['message' => 'تم قبول الطلب بنجاح! أصبح الآن في قائمة طلباتك.']);
            } catch (Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                throw $e; 
            }
            break;

        case 'update_delivery_order_status':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']); 
            $new_status = sanitize_input($input['status']);
            
            if ($new_status !== 'out_for_delivery') {
                throw new Exception("إجراء غير صالح. لإكمال الطلب استخدم تأكيد التسليم بالكود.");
            }

            $sql = "UPDATE live_tickets SET status = ? WHERE ticket_id = ? AND delivery_agent_id = ?";
            $stmt = $pdo->prepare($sql); 
            $stmt->execute([$new_status, $order_id, $user_id]);
            
            if ($stmt->rowCount() > 0) {
                send_response('success',['message' => 'تم تحديث حالة الطلب.']);
            } else {
                throw new Exception("فشل تحديث الحالة. قد لا تملك هذا الطلب.");
            }
            break;

        case 'respond_to_cancellation':
            if (!$customer_id) throw new Exception("يجب تسجيل الدخول كعميل لتنفيذ هذا الإجراء.");
            $order_id = sanitize_input($input['order_id']);
            $response_action = sanitize_input($input['response_action']);
            
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT id, status, delivery_agent_id FROM orders WHERE id = ? AND customer_id = ? FOR UPDATE");
                $stmt->execute([$order_id, $customer_id]);
                $order = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$order) throw new Exception("الطلب غير موجود.");
                if ($order['status'] !== 'cancellation_requested_by_agent') throw new Exception("لا يوجد طلب إلغاء معلق لهذا الطلب.");

                if ($response_action === 'approve') {
                    $items_stmt = $pdo->prepare("SELECT product_id, size_id, quantity FROM order_items WHERE order_id = ?");
                    $items_stmt->execute([$order_id]);
                    $items = $items_stmt->fetchAll(PDO::FETCH_ASSOC);

                    foreach ($items as $item) {
                        $prod_stmt = $pdo->prepare("SELECT options, quantity_type FROM products WHERE id = ? FOR UPDATE");
                        $prod_stmt->execute([$item['product_id']]);
                        $prod = $prod_stmt->fetch(PDO::FETCH_ASSOC);

                        if ($prod && $prod['quantity_type'] === 'tracked') {
                            if ($item['size_id'] && $prod['options']) {
                                $options = json_decode($prod['options'], true);
                                if (is_array($options)) {
                                    foreach ($options as &$option) {
                                        if (isset($option['id']) && $option['id'] === $item['size_id']) {
                                            $option['quantity'] += $item['quantity'];
                                            break;
                                        }
                                    }
                                }
                                $new_options_json = json_encode($options, JSON_UNESCAPED_UNICODE);
                                $pdo->prepare("UPDATE products SET quantity = quantity + ?, options = ? WHERE id = ?")
                                    ->execute([$item['quantity'], $new_options_json, $item['product_id']]);
                            } else {
                                $pdo->prepare("UPDATE products SET quantity = quantity + ? WHERE id = ?")
                                    ->execute([$item['quantity'], $item['product_id']]);
                            }
                        }
                    }
                    $pdo->prepare("UPDATE orders SET status = 'cancelled' WHERE id = ?")->execute([$order_id]);
                    $msg = "تم الموافقة على الإلغاء بنجاح. عادت المنتجات للمخزون.";
                } else {
                    $pdo->prepare("UPDATE orders SET status = 'accepted_by_delivery', cancel_reason = NULL WHERE id = ?")->execute([$order_id]);
                    $msg = "تم رفض الإلغاء. المندوب ملزم بتوصيل الطلب حالياً.";
                }

                $pdo->commit();
                send_response('success',['message' => $msg]);
            } catch(Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                throw $e; 
            }
            break;
            
        case 'confirm_delivery_with_code':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']); 
            $code = sanitize_input($input['code']);
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT delivery_code, status, delivery_fee FROM orders WHERE id = ? AND delivery_agent_id = ? FOR UPDATE"); 
                $stmt->execute([$order_id, $user_id]); 
                $order = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$order) throw new Exception("الطلب غير موجود أو لا تملكه.");
                if ($order['status'] !== 'out_for_delivery') throw new Exception("يجب أن يكون الطلب في حالة 'خرج للتوصيل' أولاً.");
                if ($order['delivery_code'] != $code) throw new Exception("كود التسليم غير صحيح. يرجى المراجعة مع العميل.");
                
                $pdo->prepare("UPDATE orders SET status = 'completed' WHERE id = ?")->execute([$order_id]);
                
                $items_stmt = $pdo->prepare("SELECT oi.*, p.cost_price FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?");
                $items_stmt->execute([$order_id]);
                
                foreach ($items_stmt->fetchAll(PDO::FETCH_ASSOC) as $item) {
                    $sid = 'SALE-' . generate_uuid(); 
                    $total = $item['price'] * $item['quantity']; 
                    $cost = $item['cost_price'] * $item['quantity'];
                    
                    $log_stmt = $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, cost_at_sale, order_id) VALUES (?, ?, ?, ?, ?, ?, ?, (SELECT currency FROM orders WHERE id = ?), 'sale', ?, ?)");
                    $log_stmt->execute([$sid, $item['user_id'], $item['product_id'], $item['size_id'], $item['quantity'], $item['price'], $total, $order_id, $cost, $order_id]);
                }
                
                $pdo->commit();
                send_response('success',['message' => 'تم تأكيد التسليم بنجاح!']);
            } catch (Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                throw $e; 
            }
            break;
            
        case 'update_agent_location':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $lat = filter_var($input['lat'], FILTER_VALIDATE_FLOAT); 
            $lng = filter_var($input['lng'], FILTER_VALIDATE_FLOAT);
            if ($lat === false || $lng === false) throw new Exception("إحداثيات غير صالحة.");
            $location_json = json_encode(['lat' => $lat, 'lng' => $lng]);
            try { 
                $pdo->exec("ALTER TABLE users ADD COLUMN last_active_at DATETIME NULL AFTER last_location"); 
            } catch (Exception $e) {}
            
            $stmt = $pdo->prepare("UPDATE users SET last_location = ?, last_active_at = NOW() WHERE id = ?"); 
            $stmt->execute([$location_json, $user_id]);
            send_response('success',['message' => 'تم تحديث الموقع']);
            break;

        case 'get_agents_locations':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $stmt = $pdo->prepare("SELECT id, store_name, last_location, last_active_at FROM users WHERE role = 'delivery' AND is_active = 1 AND id != ? AND last_location IS NOT NULL"); 
            $stmt->execute([$user_id]); 
            $agents = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($agents as &$agent) {
                $agent['last_location'] = json_decode($agent['last_location'], true);
                $last_active_timestamp = !empty($agent['last_active_at']) ? strtotime($agent['last_active_at']) : 0;
                $agent['is_online'] = (time() - $last_active_timestamp) < 300;
                unset($agent['last_active_at']);
            }
            send_response('success',['data' => $agents]);
            break;

        case 'get_full_route_details':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']);
            $stmt_order = $pdo->prepare("SELECT o.merchant_id, o.delivery_gps_link, o.delivery_address_text, c.full_name as customer_name FROM orders o JOIN customers c ON o.customer_id = c.id WHERE o.id = ? AND o.delivery_agent_id = ?"); 
            $stmt_order->execute([$order_id, $user_id]); 
            $order = $stmt_order->fetch(PDO::FETCH_ASSOC);

            if (!$order) throw new Exception("الطلب غير موجود أو غير مخصص لك.");
            
            $stmt_merchant = $pdo->prepare("SELECT store_name, settings FROM users WHERE id = ?"); 
            $stmt_merchant->execute([$order['merchant_id']]); 
            $merchant = $stmt_merchant->fetch(PDO::FETCH_ASSOC);

            $merchant_settings = json_decode($merchant['settings'] ?: '{}', true);
            $merchant_location_url = $merchant_settings['location'] ?? null;

            $merchant_coords = extract_coords_from_url($merchant_location_url); 
            $customer_coords = extract_coords_from_url($order['delivery_gps_link']);

            $customer_street = 'غير محدد';
            if (strpos($order['delivery_address_text'], '| التفاصيل:') !== false) {
                $parts = explode('| التفاصيل:', $order['delivery_address_text']);
                $customer_street = trim($parts[1]);
            }

            if (!$merchant_coords) throw new Exception("تعذر تحديد موقع التاجر. يرجى التواصل مع الإدارة.");
            if (!$customer_coords) throw new Exception("تعذر تحديد موقع الزبون.");

            send_response('success',['data' =>[
                'merchant_location' => $merchant_coords, 
                'merchant_name' => $merchant['store_name'], 
                'customer_location' => $customer_coords, 
                'customer_name' => $order['customer_name'],
                'customer_street' => $customer_street 
            ]]);
            break;

        default:
            throw new Exception('الإجراء المطلوب غير معروف: ' . sanitize_input($action));
    }

} catch (PDOException $e) {
    error_log("Database Error in API: " . $e->getMessage());
    // ⭐ إصلاح أمني: عدم إرجاع رسالة الخطأ الخام لقاعدة البيانات للعميل
    // (كانت تُسرّب تفاصيل داخلية مثل أسماء الجداول والأعمدة). التفاصيل الكاملة تُسجَّل فقط في اللوق أعلاه.
    send_response('error',['message' => 'حدث خطأ في قاعدة البيانات. يرجى المحاولة لاحقاً.'], 500);
} catch (Throwable $e) {
    $msg = $e->getMessage();
    if (strpos($msg, 'SQLSTATE') !== false || strpos($msg, 'PDO') !== false || strpos($msg, '/') !== false || strpos($msg, '\\') !== false || strpos($msg, 'on line') !== false) {
        error_log("System Error in API: " . $msg);
        $msg = 'حدث خطأ غير متوقع. يرجى المحاولة لاحقاً.';
        $code = 500;
    } else {
        $code = (strpos($msg, 'تغيرت الجلسة') !== false || strpos($msg, 'غير مصرح') !== false || strpos($msg, 'يجب تسجيل الدخول') !== false) ? 401 : 400;
    }
    
    if (strpos($msg, 'REQUIRE_PROFILE_UPDATE:') !== false) {
        $code = 403;
        $msg = str_replace('REQUIRE_PROFILE_UPDATE:', '', $msg);
    }
    
    send_response('error',['message' => trim($msg)], $code);
}
?>
