
<?php
// =======================================================
// ملف API الشامل (النسخة المتطورة أمنياً - الجدار الأمني 10.5)
// ⭐ تم التحديث لدعم نظام المتاجر المتعددة (Multi-Vendor) ⭐
// ⭐ التحديث الجديد: 
// 1. دعم المزامنة اللحظية للمنتجات بدون تحديث الصفحة.
// 2. إجبار المندوب والتاجر على إكمال الإعدادات الأساسية (موقع، نوع المحل).
// 3. منع تجهيز الطلبات حتى يتم قبولها من قبل مندوب.
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
    file_put_contents($log_file, $log_message, FILE_APPEND);
    
    return $result;
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

// 1. الجدار الناري الصارم: تحديد النطاقات المسموحة فقط (Zero-Resource Filter)
$allowed_origins =[
    'http://vay.rf.gd',       // استضافتك الحالية (بدون HTTPS)
    'https://vay.rf.gd',      // استضافتك الحالية (مع HTTPS)
    'https://nalsh.netlify.app' // استضافة Netlify الخاصة بك (تأكد من الرابط)
];

// السماح لبيئة التطوير المحلية (Localhost) إذا كنت تبرمج على جهازك
$allowed_origins[] = 'http://localhost';
$allowed_origins[] = 'http://127.0.0.1';

$request_origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
$matched_origin = '';

// فحص مصدر الطلب
if (!empty($request_origin)) {
    foreach ($allowed_origins as $origin) {
        if (strpos($request_origin, $origin) === 0) { // يطابق البداية
            $matched_origin = $origin;
            break;
        }
    }
} else {
    // إذا كان الطلب من نفس السيرفر (نفس النطاق) يتم قبوله
    $matched_origin = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'];
}

// ⛔ القطع الفوري: إذا كان المصدر غير مصرح له، أنهِ العملية فوراً (استهلاك صفر للسيرفر)
if (empty($matched_origin)) {
    http_response_code(403);
    die(json_encode(['status' => 'error', 'message' => 'Access Denied: Request from an unauthorized source.']));
}

// 2. السماح للطلبات الموثوقة فقط
header("Access-Control-Allow-Origin: $matched_origin");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-TOKEN");
header("Access-Control-Allow-Credentials: true");

// إنهاء الطلبات التمهيدية (Preflight) الخاصة بـ Netlify فوراً
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}
// =======================================================
// 2. إجبار استخدام HTTPS (تفعيل التشفير)
// =======================================================
        // 2. إجبار استخدام HTTPS (تفعيل التشفير)
        $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? '';

        if ($protocol !== 'https' && strpos($host, 'localhost') === false && strpos($host, '127.0.0.1') === false) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'يتطلب هذا الـ API اتصالاً آمناً (HTTPS).']);
    exit();
}

header("X-Frame-Options: DENY"); 
header("X-XSS-Protection: 1; mode=block"); 
header("X-Content-Type-Options: nosniff"); 
header("Strict-Transport-Security: max-age=31536000; includeSubDomains"); 
header("Content-Security-Policy: default-src 'none';"); 
// =======================================================

// =======================================================
// 2. الدوال المساعدة والإعدادات
// =======================================================

define('CACHE_DIR', __DIR__ . '/../cache/');
define('CACHE_FILE', CACHE_DIR . 'products.json');
define('CACHE_TTL', 300); 

define('OTP_COOLDOWN_SECONDS', 120); 

define('DELIVERY_AGENT_MAX_ORDERS', 5);
define('ORDER_ACCEPT_TIMEOUT_SECONDS', 1800); 

define('APP_SECRET_KEY', 'Nalsh_Secure_App_State_Key_2026_!@#$99'); 

define('ALLOWED_DELIVERY_CENTER_LAT', 15.3694); 
define('ALLOWED_DELIVERY_CENTER_LNG', 44.1910);
define('MAX_ALLOWED_DELIVERY_RADIUS_KM', 30); 

define('MIN_ALLOWED_LAT', 12.0000);
define('MAX_ALLOWED_LAT', 19.0000);
define('MIN_ALLOWED_LNG', 41.0000);
define('MAX_ALLOWED_LNG', 54.0000);

define('MAX_PRICE_INCREASE_PERCENTAGE', 20); // 20%

function generate_signed_token($payload, $expiry_minutes = 5) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload['exp'] = time() + ($expiry_minutes * 60);
    $base64UrlHeader = str_replace(['+', '/', '='],['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='],['-', '_', ''], base64_encode(json_encode($payload)));
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, APP_SECRET_KEY, true);
    $base64UrlSignature = str_replace(['+', '/', '='],['-', '_', ''], base64_encode($signature));
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}
// =======================================================
// دالة إرسال الكاش إلى Netlify (الجسر الذكي)
// =======================================================
function sendJsonToNetlify($filename, $jsonContent, $folder = null) {
    // استبدل هذا الرابط برابط Netlify Function الخاص بك
    $netlify_function_url = 'https://YOUR_SITE.netlify.app/.netlify/functions/update-cache';
    $secret_key = 'Nalsh-To-Netlify-Bridge-!@#$9876'; // نفس المفتاح السري

    $payload = json_encode([
        'filename' => $filename,
        'content'  => $jsonContent,
        'folder'   => $folder
    ]);

    $ch = curl_init($netlify_function_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($payload),
        'X-Auth-Token: ' . $secret_key
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10); // وقت انتظار 10 ثواني

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // تسجيل أي خطأ في سجلات السيرفر للمراجعة
    if ($http_code !== 200) {
        error_log("Netlify Sync Error for $filename: HTTP $http_code - " . $response);
    }
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

function send_response($status, $data =[], $http_code = 200) {
    if (ob_get_length()) ob_clean();
    http_response_code($http_code);
    echo json_encode(array_merge(['status' => $status], $data), JSON_UNESCAPED_UNICODE);
    exit();
}

function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    $data = trim($data ?? '');
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
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

    $parsed_url = parse_url($url);
    if (!$parsed_url || empty($parsed_url['scheme']) || empty($parsed_url['host'])) {
        return false;
    }

    $scheme = strtolower($parsed_url['scheme']);
    if (!in_array($scheme,['http', 'https'])) {
        return false;
    }

    $host = $parsed_url['host'];
    
    if (preg_match('/^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])$/i', $host)) {
        return false;
    }

    $ip = gethostbyname($host);
    if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
        return false; 
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
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

function calculate_delivery_fee($distance_km) {
    $base_fee = 1000;
    $base_distance_km = 5;
    $fee_per_km_extra = 150;
    $rounding_factor = 50;
    if ($distance_km <= $base_distance_km) {
        $total_fee = $base_fee;
    } else {
        $extra_distance = $distance_km - $base_distance_km;
        $total_fee = $base_fee + ($extra_distance * $fee_per_km_extra);
    }
    return ceil($total_fee / $rounding_factor) * $rounding_factor;
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
            $placeholders = implode(',', array_fill(0, count($order_ids_to_reset), '?'));
            $reset_stmt = $pdo->prepare("UPDATE orders SET delivery_agent_id = NULL, status = 'pending_delivery_acceptance', accepted_at = NULL, exclusive_agent_id = NULL, dispatch_queue = NULL, exclusive_until = NULL WHERE id IN ($placeholders)");
            $reset_stmt->execute($order_ids_to_reset);
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
    // هذه الدالة تم استبدال منطقها بنظام Polling الذكي للحفاظ على استقرار السيرفر
    // سيتم استخدام مسار check_store_updates بدلاً عنها
    return;
}

function get_full_category_paths($pdo) {
    try {
        $stmt = $pdo->query("SELECT id, name, parent_id FROM categories");
        $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $catMap =[];
        foreach ($categories as $cat) {
            $catMap[$cat['id']] = $cat;
        }
        $paths =[];
        foreach ($catMap as $id => $cat) {
            $path =[];
            $curr = $id;
            $depth = 0; 
            while ($curr && isset($catMap[$curr]) && $depth < 10) {
                array_unshift($path, $catMap[$curr]['name']);
                $curr = $catMap[$curr]['parent_id'];
                $depth++;
            }
            $paths[$id] = implode(' > ', $path);
        }
        return $paths;
    } catch (Exception $e) {
        return[];
    }
}
// دالة الرفع الذري إلى Firebase (تحديث منتج واحد فقط دون التأثير على الباقي)
// دالة الرفع السريعة لفايربيس (بدون انتظار الاستجابة - Fire and Forget)
function patchFirebaseNode($path, $data) {
    $url = FIREBASE_URL . $path . ".json?auth=" . FIREBASE_SECRET;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // ⭐ السر هنا: وضعنا وقت الانتظار ثانية واحدة كحد أقصى! (لا يعلق السيرفر أبداً)
    curl_setopt($ch, CURLOPT_TIMEOUT, 1); 
    curl_exec($ch);
    curl_close($ch);
}
// ⭐ نظام الإشارات الذكي: لا تبني الملفات الثقيلة، فقط ضع علامة أن هناك تغيير!
function flag_cache_for_rebuild($merchant_id = null) {
    $signal_dir = __DIR__ . '/../cache/signals';
    if (!is_dir($signal_dir)) { @mkdir($signal_dir, 0777, true); }
    
    // إشارة لتحديث الكاش الرئيسي
    @touch($signal_dir . '/rebuild_main.flag');
    
    // إشارة لتحديث كاش التاجر إذا لزم الأمر
    if ($merchant_id) {
        @touch($signal_dir . '/rebuild_m_' . $merchant_id . '.flag');
    }
}
// دالة الحذف من Firebase
function deleteFirebaseNode($path) {
    $url = FIREBASE_URL . $path . ".json?auth=" . FIREBASE_SECRET;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($ch);
    curl_close($ch);
}
// ⭐ إصلاح: تم حذف التعريف المكرر للدالة من هنا

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && ($error['type'] === E_ERROR || $error['type'] === E_PARSE)) {
        if (ob_get_length()) ob_clean();
        http_response_code(500); 
        echo json_encode(['status' => 'error', 'message' => 'حدث خطأ داخلي في الخادم. يرجى المحاولة لاحقاً.']);
    }
});


// =======================================================
// 3. الاتصال بقاعدة البيانات ومعالجة الطلب
// =======================================================
try {
    require_once __DIR__ . '/../includes/nalsh-user-admin-name.php';

    // ==========================================
    // ⭐ الإصلاح الجذري: قراءة المدخلات في البداية
    // ==========================================
    $input =[];
    if (!empty(file_get_contents('php://input'))) {
        $input = json_decode(file_get_contents('php://input'), true) ?:[];
    }
    $input = array_merge($_POST, $_GET, $input);
    $action = $input['action'] ?? '';

    // ⭐ نظام حماية API المعتمد على التوكن
    $user_id = null;
    $user_role = null;

    $exempted_actions =[
        // مسارات الشركاء
        'login', 'check_phone', 'verify_new_device_otp', 'resend_device_otp', 'select_role', 
        'register_init', 'register_verify', 'recover_init', 'recover_check_otp', 'recover_set_password',
        
        // مسارات العملاء
        'get_initial_data', 'check_store_updates', 'get_public_products', 'public_search_products', 
        'get_categories', 'get_departments', 'auth_request_otp', 'auth_verify_otp', 'check_customer_session',
        'get_user_data', 'add_to_cart_db', 'remove_from_cart_db', 'update_cart_qty_db', 'toggle_favorite_db', 
        'create_order', 'get_user_orders', 'update_customer_profile', 'logout_customer', 'respond_to_cancellation'
    ];

    if (!in_array($action, $exempted_actions)) {
        
        $auth_header = null;
        if (isset($_SERVER['Authorization'])) {
            $auth_header = trim($_SERVER['Authorization']);
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = trim($_SERVER['HTTP_AUTHORIZATION']);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            if (isset($requestHeaders['Authorization'])) {
                $auth_header = trim($requestHeaders['Authorization']);
            }
        }
        
        // الدعم المطلق: إذا قامت الاستضافة بحذف الهيدر، سنقرأه الآن بنجاح!
        if (!$auth_header && isset($input['auth_token'])) {
            $auth_header = 'Bearer ' . $input['auth_token'];
        }

        if (!$auth_header) {
            send_response('error',['message' => 'تم حظر التوكن من قبل الاستضافة'], 401);
        }
    list($type, $token) = explode(' ', $auth_header, 2);

    if (strcasecmp($type, 'Bearer') !== 0 || empty($token)) {
        send_response('error', ['message' => 'Invalid token format'], 401);
    }
    
    $token_parts = explode('.', $token);
    if (count($token_parts) !== 3) {
        send_response('error', ['message' => 'Invalid token structure'], 401);
    }

    list($header_encoded, $payload_encoded, $signature_encoded) = $token_parts;
    
    $signature = base64_decode($signature_encoded);
    $expected_signature = hash_hmac('sha256', "$header_encoded.$payload_encoded", APP_SECRET_KEY, true);

    if (!hash_equals($expected_signature, $signature)) {
        send_response('error', ['message' => 'Invalid token signature'], 401);
    }
    
    $payload = json_decode(base64_decode($payload_encoded), true);

    if ($payload === null || !isset($payload['exp']) || $payload['exp'] < time()) {
        send_response('error', ['message' => 'Token expired'], 401);
    }
    
    // تم التحقق بنجاح! الآن يمكننا استخدام بيانات المستخدم بأمان
    $user_id = $payload['user_id'];
    $user_role = $payload['role'];
    $_SESSION['user_id'] = $payload['user_id']; // للحفاظ على التوافقية مع بعض الدوال القديمة
    $_SESSION['role'] = $payload['role'];
    $_SESSION['store_name'] = $payload['store_name'];
    $_SESSION['username'] = $payload['username'];
}

// ... (باقي الملف يبدأ من switch ($action))
    if (!isset($pdo) || !$pdo) {
        throw new Exception("فشل الاتصال بقاعدة البيانات.");
    }

    $is_secure_cookie = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    // السماح بالعمل على localhost بدون HTTPS أثناء التطوير
    if (strpos($_SERVER['HTTP_HOST'], 'localhost') !== false || strpos($_SERVER['HTTP_HOST'], '127.0.0.1') !== false) {
        $is_secure_cookie = false;
    }
    
    // التحقق من الجداول وبنائها إذا لم تكن موجودة
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `store_type` VARCHAR(100) NULL DEFAULT NULL COMMENT 'e.g., restaurant, mall, grocery' AFTER `settings`;"); } catch (PDOException $e) {}
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `merchant_listings` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `merchant_id` INT NOT NULL,
            `global_product_id` VARCHAR(255) NOT NULL,
            `merchant_price` DECIMAL(10, 2) NOT NULL,
            `cost_price` DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
            `quantity` INT(11) NOT NULL DEFAULT 0,
            `quantity_type` ENUM('tracked', 'unlimited') NOT NULL DEFAULT 'tracked',
            `is_available` TINYINT(1) NOT NULL DEFAULT 1,
            `price_variables` JSON NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX (`merchant_id`),
            INDEX (`global_product_id`),
            UNIQUE KEY `merchant_product_unique` (`merchant_id`, `global_product_id`)
        ) ENGINE=InnoDB;");
    } catch (PDOException $e) {}

    try { $pdo->exec("ALTER TABLE `products` ADD COLUMN `base_price` DECIMAL(10, 2) NOT NULL DEFAULT 0.00 AFTER `price`;"); } catch (PDOException $e) {}
    try { $pdo->exec("ALTER TABLE orders ADD COLUMN cancel_reason TEXT NULL AFTER status"); } catch (PDOException $e) {}
    try { $pdo->exec("ALTER TABLE products ADD COLUMN approval_status ENUM('pending', 'approved', 'rejected') DEFAULT 'approved' AFTER isAvailable"); } catch (PDOException $e) {}
    try { $pdo->exec("ALTER TABLE users ADD COLUMN employer_id INT NULL DEFAULT NULL AFTER role"); } catch (PDOException $e) {}
    
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `merchant_agent_links` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `merchant_id` INT NOT NULL,
            `agent_id` INT NOT NULL,
            `status` ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY `unique_link` (`merchant_id`, `agent_id`),
            INDEX (`agent_id`),
            INDEX (`merchant_id`)
        ) ENGINE=InnoDB;");
    } catch (PDOException $e) {}

    try { $pdo->exec("ALTER TABLE orders ADD COLUMN exclusive_until DATETIME NULL AFTER accepted_at"); } catch (PDOException $e) {}
    try { $pdo->exec("ALTER TABLE orders ADD COLUMN exclusive_agent_id INT NULL AFTER exclusive_until"); } catch (PDOException $e) {}
    try { $pdo->exec("ALTER TABLE orders ADD COLUMN dispatch_queue TEXT NULL AFTER exclusive_agent_id"); } catch (PDOException $e) {}
    // إنشاء جداول نظام التذاكر الذكية (Shadow Tickets)
    // إنشاء جداول نظام التذاكر الذكية (Shadow Tickets)
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS `live_tickets` (
            `ticket_id` VARCHAR(50) PRIMARY KEY,
            `order_group_id` VARCHAR(50) NOT NULL,
            `merchant_id` INT NOT NULL,
            `delivery_agent_id` INT NULL,
            `customer_id` INT NOT NULL,
            `status` VARCHAR(50) NOT NULL DEFAULT 'pending_delivery_acceptance',
            `delivery_code` VARCHAR(10) NULL,
            `ticket_data` LONGTEXT NOT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX (`merchant_id`), INDEX (`delivery_agent_id`), INDEX (`customer_id`), INDEX (`status`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        $pdo->exec("CREATE TABLE IF NOT EXISTS `orders_archive` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `ticket_id` VARCHAR(50),
            `customer_id` INT,
            `merchant_id` INT,
            `final_status` VARCHAR(50),
            `total_amount` DECIMAL(10,2),
            `archived_data` LONGTEXT,
            `archived_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    } catch (PDOException $e) { error_log("Failed to create ticket tables: " . $e->getMessage()); }

    // إضافة ترقيع إجباري في حال كانت الجداول موجودة مسبقاً بشكل خاطئ
    try { $pdo->exec("ALTER TABLE `live_tickets` ADD COLUMN `delivery_code` VARCHAR(10) NULL AFTER `status`"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE `live_tickets` ADD COLUMN `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE `live_tickets` ADD COLUMN `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE `live_tickets` MODIFY COLUMN `ticket_data` LONGTEXT NOT NULL"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE `orders_archive` MODIFY COLUMN `archived_data` LONGTEXT"); } catch (Exception $e) {}

    // =======================================================
    // ⭐ إدارة الجلسات الصارمة
    // =======================================================
    $idle_timeout = 1800; // 30 دقيقة خمول
    $absolute_timeout = 86400; // 24 ساعة

    if (isset($_SESSION['user_id']) || isset($_SESSION['customer_id'])) {
        if (!isset($_SESSION['session_created_at'])) {
            $_SESSION['session_created_at'] = time();
        } elseif (time() - $_SESSION['session_created_at'] > $absolute_timeout) {
            session_unset(); 
            session_destroy();
            setcookie('device_token', '', time() - 3600, '/');
            setcookie('remember_me_customer', '', time() - 3600, '/');
            send_response('error',['message' => 'انتهت صلاحية الجلسة لأسباب أمنية (تجاوزت 24 ساعة). يرجى تسجيل الدخول مجدداً.'], 401);
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

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token_from_session = $_SESSION['csrf_token'] ?? null;
        $token_from_header = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        
        // إذا كانت الجلسة فارغة (مستخدم جديد لم يسجل دخول)، نقوم بتوليد توكن جديد له
        // فحص التطابق فقط للعمليات الحساسة
        if (empty($token_from_session) || empty($token_from_header) || !hash_equals((string)$token_from_session, (string)$token_from_header)) {
            $exempt_actions =[
                'auth_request_otp', 'auth_verify_otp', 'check_customer_session', 'get_initial_data',
                'login', 'check_phone', 'select_role', 'verify_new_device_otp',
                'register_init', 'register_verify', 'recover_init', 'recover_check_otp', 'recover_set_password'
            ];
            
            if (!in_array($action, $exempt_actions) && (isset($_SESSION['user_id']) || isset($_SESSION['customer_id']))) {
                // ⭐ الحل السحري: نرسل المفتاح الصحيح للواجهة لتتمكن من تصحيح نفسها وإعادة الإرسال
                header('X-New-CSRF-Token: ' . $token_from_session);
                send_response('error', [
                    'message' => 'انتهت صلاحية الصفحة. يرجى تحديث الصفحة (Refresh).', 
                    'error_type' => 'csrf_mismatch'
                ], 403);
            }
        }
    }

    if (empty($_SESSION['customer_id']) && isset($_COOKIE['remember_me_customer'])) {
        list($selector, $validator) = explode(':', $_COOKIE['remember_me_customer']);
        if ($selector && $validator) {
            $stmt = $pdo->prepare("SELECT * FROM auth_tokens WHERE selector = ? AND expires >= NOW()");
            $stmt->execute([$selector]);
            $token_data = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($token_data) {
                $hashed_validator_from_cookie = hash('sha256', $validator);
                if (hash_equals($token_data['hashed_validator'], $hashed_validator_from_cookie)) {
                    $stmt_cust = $pdo->prepare("SELECT id, full_name, is_active FROM customers WHERE id = ?");
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

    $user_role = $_SESSION['role'] ?? null;
    $user_id = $_SESSION['user_id'] ?? null;
    $customer_id = $_SESSION['customer_id'] ?? null;

    if ($user_id && in_array($user_role,['merchant', 'delivery', 'admin'])) {
        $current_device_token = $_COOKIE['device_token'] ?? null;
        if ($current_device_token) {
            $stmt_check_dev = $pdo->prepare("SELECT id FROM trusted_devices WHERE user_id = ? AND device_token = ?");
            $stmt_check_dev->execute([$user_id, $current_device_token]);
            if (!$stmt_check_dev->fetchColumn()) {
                session_unset(); session_destroy();
                setcookie('device_token', '', time() - 3600, '/');
                send_response('error',['message' => 'تم إنهاء هذه الجلسة عن بعد أو تم تغيير بيانات الأمان. يرجى تسجيل الدخول مجدداً.'], 401);
            }
        }
    }

    if ($customer_id) {
        $stmt_check_cust = $pdo->prepare("SELECT is_active FROM customers WHERE id = ?");
        $stmt_check_cust->execute([$customer_id]);
        if ($stmt_check_cust->fetchColumn() == 0) {
            session_unset(); session_destroy();
            setcookie('remember_me_customer', '', time() - 3600, '/');
            send_response('error',['message' => 'تم إنهاء الجلسة أو حظر الحساب. يرجى مراجعة الإدارة.'], 401);
        }
    }

    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if (strpos($referer, '/admin/') !== false && $user_id && $user_role !== 'admin') {
        send_response('error',['message' => 'تم تسجيل الدخول بحساب آخر في نافذة مختلفة. يرجى إعادة تسجيل الدخول كمدير.'], 401);
    }
    if (strpos($referer, 'merchant-dashboard') !== false && $user_id && $user_role !== 'merchant') {
        send_response('error',['message' => 'تغيرت الجلسة في نافذة أخرى. يرجى إعادة تسجيل الدخول.'], 401);
    }
    if (strpos($referer, 'delivery-dashboard') !== false && $user_id && $user_role !== 'delivery') {
        send_response('error',['message' => 'تغيرت الجلسة في نافذة أخرى. يرجى إعادة تسجيل الدخول.'], 401);
    }

    $MACRO_DEVICE_ID = "0d8f9740-a59a-4828-97a3-65cf42aaae9e"; 
    $MACRO_WEBHOOK_NAME = "send_otp";

    // =======================================================
    // 4. توجيه الطلبات (API Router)
    // =======================================================

    switch ($action) {
    case 'upload_image':
            if (!$user_id || !in_array($user_role, ['merchant', 'admin'])) {
                send_response('error', ['message' => 'غير مصرح'], 401);
            }
            $base64_image = $input['image_data'] ?? '';
            if (empty($base64_image)) throw new Exception("الصورة فارغة");

            $keys = IMGBB_KEYS;
            $random_key = $keys[array_rand($keys)];

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://api.imgbb.com/1/upload?key=" . $random_key);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, ['image' => $base64_image]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($ch);
            curl_close($ch);

            $result = json_decode($response, true);
            if ($result && isset($result['data']['url'])) {
                send_response('success', [
                    'url' => $result['data']['url'],
                    'delete_url' => $result['data']['delete_url'] // نرسل رابط الحذف لنحفظه
                ]);
            } else {
                throw new Exception("فشل رفع الصورة للسيرفر السحابي");
            }
            break;
// في ملف api.php أضف هذه الحالة
// ⭐ مسار التحميل الشامل للتطبيق (SPA Initialization)
        case 'get_initial_data':
            // 1. جلب الإعدادات
            $stmt_settings = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'store_settings'");
            $settings = json_decode($stmt_settings->fetchColumn() ?: '{}', true);

            // 2. جلب المتاجر
            $sql_merchants = "SELECT id, store_name, username FROM users WHERE role = 'merchant' AND is_active = 1";
            $merchants = $pdo->query($sql_merchants)->fetchAll(PDO::FETCH_ASSOC);

            // 3. جلب المنتجات (نفس استعلامك الممتاز)
            $sql_all = "
                SELECT
                    p.id, p.name, p.mainDescription, p.image, p.sizes, p.discount, p.department, p.keywords,
                    l.id as listing_id, l.merchant_price as price, l.quantity, l.quantity_type,
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

            // معالجة البيانات
            foreach ($products as &$product) {
                $product['options'] = json_decode($product['sizes'] ?? '[]', true) ?: [];
                unset($product['sizes']);
                $product['price'] = floatval($product['price']);
                $product['discount'] = floatval($product['discount']);
                $product['quantity'] = intval($product['quantity']);
                $product['department'] = $product['department'] ?? 'عام';
                $product['user_id'] = $product['merchant_id'] ?? null;
            }
            
            // ⭐⭐⭐ هذا هو سطر الإصلاح الحاسم ⭐⭐⭐
            unset($product); // قطع الارتباط بآخر عنصر لمنع تلف البيانات

            send_response('success', [
                'settings' => $settings,
                'merchants' => $merchants,
                'products' => $products,
                'contact_whatsapp' => $settings['whatsappNumber'] ?? '967770094456'
            ]);
            break;
        // ⭐ مسار جديد: فحص حالة استكمال الإعدادات الأساسية للتاجر والمندوب
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

        // ⭐ مسار جديد: دعم التحديث اللحظي للواجهة بدون Refresh
        case 'check_store_updates':
            // جلب أحدث تاريخ تعديل في جدول عروض المنتجات
            $last_update = $pdo->query("SELECT MAX(updated_at) FROM merchant_listings WHERE is_available = 1")->fetchColumn();
            send_response('success', ['latest_update' => $last_update]);
            break;

        case 'get_public_products':
            $page = max(1, intval($input['page'] ?? 1));
            $limit = max(1, min(50, intval($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $category = sanitize_input($input['category'] ?? null);
            $merchant_id = sanitize_input($input['merchant_id'] ?? null); // ⭐ دعم التاجر

            $where_clauses =[
                "l.is_available = 1",
                "(l.quantity > 0 OR l.quantity_type = 'unlimited')",
                "p.approval_status = 'approved'",
                "p.isAvailable = 1"
            ];
            $params =[];

            // فلترة بالقسم
            if ($category) {
                if (is_numeric($category)) {
                    $where_clauses[] = "p.category_id = :category";
                    $params[':category'] = $category;
                } else {
                    $where_clauses[] = "(c.name = :category OR p.department = :category)";
                    $params[':category'] = $category;
                }
            }
            
            // ⭐ فلترة بمتجر معين
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

            $check_stmt = $pdo->prepare(
                "SELECT request_time FROM rate_limits 
                 WHERE (ip_address = :ip OR phone_number = :phone) AND request_time > NOW() - INTERVAL :cooldown SECOND 
                 ORDER BY request_time DESC LIMIT 1"
            );
            $check_stmt->execute([':ip' => $ip_address, ':phone' => $phone, ':cooldown' => OTP_COOLDOWN_SECONDS]);
            $last_request = $check_stmt->fetch(PDO::FETCH_ASSOC);

            if ($last_request) {
                $time_passed = time() - strtotime($last_request['request_time']);
                $time_left = OTP_COOLDOWN_SECONDS - $time_passed;
                if ($time_left > 0) {
                    throw new Exception("لقد طلبت كوداً مؤخراً. يرجى الانتظار $time_left ثانية.");
                }
            }

            $otp = rand(100000, 999999);
            $message = "كود التحقق الخاص بك هو: {$otp}\nلا تشاركه مع أحد.";

            $stmt = $pdo->prepare("SELECT id, is_active, full_name FROM customers WHERE phone = ?");
            $stmt->execute([$phone]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($customer) {
                if ($customer['is_active'] == 0) throw new Exception('عذراً، هذا الرقم محظور من استخدام المتجر.');
                $pdo->prepare("UPDATE customers SET otp_code = ? WHERE id = ?")->execute([$otp, $customer['id']]);

                try {
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message, status) VALUES (?, ?, 'pending')")->execute([$phone, $message]);
                } catch (PDOException $e) {}

            } else {
                $random_pass = password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT);
                $default_name = "عميل " . substr($phone, -4);
                
                try { $pdo->exec("ALTER TABLE customers ADD COLUMN otp_code VARCHAR(10) NULL AFTER phone"); } catch(Exception $e){}
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
                $stmt->execute([$default_name, $phone, $random_pass, $otp]);

                try {
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message, status) VALUES (?, ?, 'pending')")->execute([$phone, $message]);
                } catch (PDOException $e) {}
            }

            $token_payload =[
                'purpose' => 'customer_login',
                'phone' => $phone,
                'otp' => $otp,
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 5);
            setcookie('state_token', $state_token, time() + 300, '/', '', $is_secure_cookie, true);
            
            $pdo->prepare("INSERT INTO rate_limits (ip_address, phone_number) VALUES (?, ?)")->execute([$ip_address, $phone]);

            send_response('success',['message' => 'تم إرسال كود التحقق بنجاح.', 'otp' => 'sent', 'phone' => $phone, 'cooldown' => OTP_COOLDOWN_SECONDS]);
            break;

        case 'auth_verify_otp':
            $otp_input = sanitize_input($input['otp'] ?? '');
            $token = $_COOKIE['state_token'] ?? '';
            
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

            $stmt_update = $pdo->prepare("UPDATE customers SET otp_code = NULL, is_verified = 1 WHERE id = ? AND otp_code = ?");
            $stmt_update->execute([$cust['id'], $otp_input]);

            if ($stmt_update->rowCount() > 0 || $otp_input == $payload['otp']) {
    
    $pdo->prepare("UPDATE customers SET otp_code = NULL, is_verified = 1 WHERE id = ?")->execute([$cust['id']]);

    $is_new_user = (strpos($cust['full_name'], 'عميل') === 0);

    // ================== ⭐ بداية الإصلاح ⭐ ==================
    
    // 1. تجديد الجلسة لمنع اختطافها وضمان حفظها فوراً
    session_regenerate_id(true); 

    // تم إزالة دوال الجلسة المعقدة لضمان استقرار الدخول في الاستضافات المجانية
    $_SESSION['customer_id'] = $cust['id'];
    $_SESSION['customer_name'] = $cust['full_name'];
    $_SESSION['loggedin'] = true;
    // 2. إغلاق الجلسة فوراً لضمان حفظ البيانات قبل الرد
    session_write_close();
    
    // ================== ⭐ نهاية الإصلاح ⭐ ==================
    
    setcookie('state_token', '', time() - 3600, '/');

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
            'samesite' => 'Strict'
        ]);
    } catch (PDOException $token_error) {}
    
    send_response('success',['message' => 'تم تسجيل الدخول بنجاح!', 'customer' =>['full_name' => $cust['full_name'], 'phone' => $phone], 'needs_profile_update' => $is_new_user]);
} else {
    $payload['attempts']++;
    if ($payload['attempts'] >= 3) {
        $pdo->prepare("UPDATE customers SET otp_code = NULL WHERE id = ?")->execute([$cust['id']]);
        setcookie('state_token', '', time() - 3600, '/');
        throw new Exception("لقد تجاوزت حد المحاولات الخاطئة (3 محاولات). يرجى طلب كود جديد.");
    }
    $new_token = generate_signed_token($payload, 5);
    setcookie('state_token', $new_token, time() + 300, '/', '', $is_secure_cookie, true);
    throw new Exception('كود التحقق خاطئ. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
}
break; // <-- وهذه هي الـ break; المفقودة التي تم إضافتها في الحل السابق
        case 'check_customer_session':
            if ($customer_id) {
                $stmt = $pdo->prepare("SELECT full_name, phone, address, is_verified FROM customers WHERE id = ?");
                $stmt->execute([$customer_id]);
                $customer_data = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($customer_data) {
                    $is_new_user = (strpos($customer_data['full_name'], 'عميل') === 0);
                    send_response('success',['loggedIn' => true, 'customer' => $customer_data, 'requires_otp' => false, 'needs_profile_update' => $is_new_user]);
                }else { unset($_SESSION['customer_id'], $_SESSION['customer_name']); send_response('success',['loggedIn' => false]); }
            } else {
                $token = $_COOKIE['state_token'] ?? '';
                $pending_phone = null;
                if (!empty($token)) {
                    try {
                        $payload = verify_signed_token($token, 'customer_login');
                        $pending_phone = $payload['phone'];
                    } catch (Exception $e) {
                        setcookie('state_token', '', time() - 3600, '/');
                    }
                }

                if ($pending_phone) {
                    $check_stmt = $pdo->prepare("SELECT request_time FROM rate_limits WHERE phone_number = ? ORDER BY request_time DESC LIMIT 1");
                    $check_stmt->execute([$pending_phone]);
                    $last_req = $check_stmt->fetch(PDO::FETCH_ASSOC);
                    $time_left = 0;
                    if ($last_req) {
                        $time_passed = time() - strtotime($last_req['request_time']);
                        $time_left = max(0, OTP_COOLDOWN_SECONDS - $time_passed);
                    }
                    send_response('success',['loggedIn' => false, 'requires_otp' => true, 'pending_phone' => $pending_phone, 'cooldown' => $time_left]);
                } else { send_response('success',['loggedIn' => false]); }
            }
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

        case 'logout_customer':
            if (isset($_COOKIE['remember_me_customer'])) {
                list($selector) = explode(':', $_COOKIE['remember_me_customer']);
                if ($selector) $pdo->prepare("DELETE FROM auth_tokens WHERE selector = ?")->execute([$selector]);
                setcookie('remember_me_customer', '',[
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => $is_secure_cookie,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);
            }
            unset($_SESSION['customer_id'], $_SESSION['customer_name']);
            setcookie('state_token', '', time() - 3600, '/'); 
            if (!isset($_SESSION['user_id'])) session_destroy();
            send_response('success');
            break;

        case 'get_user_data':
            if (!$customer_id) send_response('error',['message' => 'غير مسجل دخول'], 401);
            $sql = "SELECT c.id, c.product_id, c.size_id, c.quantity, p.name, p.price, p.discount, p.image, p.sizes FROM user_cart c JOIN products p ON c.product_id = p.id WHERE c.customer_id = ?";
            $stmt = $pdo->prepare($sql); $stmt->execute([$customer_id]); $cart_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($cart_items as &$item) {
                if ($item['size_id'] && $item['sizes']) {
                    $options_data = json_decode($item['sizes'], true);
                    if (is_array($options_data)) {
                        foreach ($options_data as $option) {
                            if (isset($option['id']) && $option['id'] === $item['size_id']) {
                                $item['size_name'] = $option['name'] ?? ($option['size_name'] ?? ''); $item['size_image'] = $option['image']; break;
                            }
                        }
                    }
                } unset($item['sizes']);
            }
            $fav = $pdo->prepare("SELECT product_id FROM user_favorites WHERE customer_id = ?"); 
            $fav->execute([$customer_id]);
            send_response('success',['cart' => $cart_items, 'favorites' => $fav->fetchAll(PDO::FETCH_COLUMN)]);
            break;

        case 'add_to_cart_db':
            if (!$customer_id) send_response('error',['message' => 'يجب تسجيل الدخول أولاً'], 401);

            $listing_id = intval($input['listing_id'] ?? 0);
            $quantity = max(1, intval($input['quantity'] ?? 1));
            $size_id = sanitize_input($input['sizeId'] ?? null);

            if ($listing_id <= 0) {
                throw new Exception("معرّف المنتج غير صالح.");
            }
            
            $stmt_listing = $pdo->prepare(
                "SELECT merchant_id, global_product_id, quantity as stock, quantity_type 
                 FROM merchant_listings 
                 WHERE id = ? AND is_available = 1"
            );
            $stmt_listing->execute([$listing_id]);
            $listing = $stmt_listing->fetch(PDO::FETCH_ASSOC);

            if (!$listing) {
                throw new Exception("هذا المنتج غير متاح للبيع من هذا التاجر حالياً.");
            }

            $merchant_id = $listing['merchant_id'];
            $global_product_id = $listing['global_product_id'];

            try { 
                $pdo->exec("ALTER TABLE `user_cart` ADD COLUMN `listing_id` INT(11) NULL AFTER `product_id`, ADD COLUMN `merchant_id` INT(11) NULL AFTER `user_id`, ADD UNIQUE KEY `customer_item_unique` (`customer_id`, `listing_id`, `size_id`);"); 
            } catch (PDOException $e) {}
            try { $pdo->exec("UPDATE user_cart SET merchant_id = user_id WHERE merchant_id IS NULL AND user_id IS NOT NULL;"); } catch (PDOException $e) {}

            $stmt_cart_qty = $pdo->prepare("SELECT quantity FROM user_cart WHERE customer_id = ? AND listing_id = ? AND (size_id <=> ?)");
            $stmt_cart_qty->execute([$customer_id, $listing_id, $size_id]);
            $current_cart_qty = (int)$stmt_cart_qty->fetchColumn();
            
            if ($listing['quantity_type'] === 'tracked' && ($current_cart_qty + $quantity) > $listing['stock']) {
                throw new Exception("عذراً، الكمية المطلوبة غير متوفرة في المخزون لهذا المنتج.");
            }

            $sql = "INSERT INTO user_cart (customer_id, product_id, listing_id, user_id, merchant_id, size_id, quantity) 
                    VALUES (?, ?, ?, ?, ?, ?, ?) 
                    ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)";
            
            $stmt_insert = $pdo->prepare($sql);
            $stmt_insert->execute([$customer_id, $global_product_id, $listing_id, $merchant_id, $merchant_id, $size_id, $quantity]);

            send_response('success',['message' => 'تمت الإضافة للسلة']);
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
            if (!$customer_id) send_response('error',['message' => 'يجب تسجيل الدخول أولاً لإتمام الطلب.'], 401);
            
            $idempotency_key = sanitize_input($input['idempotency_key'] ?? '');
            if (!empty($idempotency_key)) {
                // ⭐ الإصلاح هنا: إجبار السيرفر على إنشاء جدول الحماية حتى لا ينهار بصمت!
                $pdo->exec("CREATE TABLE IF NOT EXISTS `idempotency_keys` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `key_token` VARCHAR(128) NOT NULL UNIQUE,
                    `response_data` TEXT NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

                try {
                    $stmt_check_key = $pdo->prepare("SELECT response_data FROM idempotency_keys WHERE key_token = ?");
                    $stmt_check_key->execute([$idempotency_key]);
                    $existing_response = $stmt_check_key->fetchColumn();
                    
                    if ($existing_response !== false) {
                        if ($existing_response === 'processing') {
                            send_response('success',['message' => 'طلبك قيد المعالجة حالياً، يرجى الانتظار...']);
                        }
                        $decoded_response = json_decode($existing_response, true);
                        send_response('success', $decoded_response ?:['message' => 'تم استلام طلبك بنجاح (تأكيد مكرر).']);
                    }
                    
                    $pdo->prepare("INSERT INTO idempotency_keys (key_token, response_data) VALUES (?, 'processing')")->execute([$idempotency_key]);
                } catch (PDOException $e) {
                    // إذا كان الخطأ فعلاً بسبب أن العميل ضغط مرتين (Duplicate entry) نوقفه
                    if ($e->getCode() == 23000) {
                        send_response('success',['message' => 'تم استلام طلبك بنجاح (تم تجاهل الطلب المكرر).']);
                    }
                }
            }

            $allowed_customer_keys =['name', 'address', 'gps'];
            $allowed_customer_keys =['name', 'address', 'gps'];
            $c_data = filter_allowed_keys($input['customer'] ??[], $allowed_customer_keys);
            
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
            if (mb_strlen($details_part, 'UTF-8') > 255) {
                $details_part = mb_substr($details_part, 0, 252, 'UTF-8') . '...';
            }
            $details_part = sanitize_input($details_part);

            $stmt_cust = $pdo->prepare("SELECT full_name, address FROM customers WHERE id = ?");
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
            if (empty($final_address) || strpos($final_address, 'http') === false || (strpos($final_address, 'التفاصيل:') === false && strlen($final_address) < 20)) throw new Exception("الرجاء تحديد عنوان التوصيل الدقيق على الخريطة وكتابة وصف للموقع (مثل المعالم البارزة) 📍");
            
            $customer_coords = extract_coords_from_url($customer_gps_link);
            if (!$customer_coords) {
                throw new Exception("الرجاء تحديد موقع دقيق على الخريطة لتتمكن من إتمام الطلب.");
            }

            $dist_from_center = calculate_distance(ALLOWED_DELIVERY_CENTER_LAT, ALLOWED_DELIVERY_CENTER_LNG, $customer_coords['lat'], $customer_coords['lng']);

            if ($dist_from_center > MAX_ALLOWED_DELIVERY_RADIUS_KM) {
                throw new Exception("عذراً، موقعك يقع خارج نطاق التغطية المسموح لخدمة التوصيل (الحد الأقصى للتغطية: " . MAX_ALLOWED_DELIVERY_RADIUS_KM . " كم عن مركز المدينة).");
            }

            try {
                $pdo->beginTransaction();

                // ⭐ جلب السلة من التخزين المحلي للعميل (المرسلة في الـ Payload)
                $cart_items = $input['local_cart'] ?? [];

                // التأكد من أن السلة مصفوفة صالحة
                if (!is_array($cart_items)) {
                    $cart_items = [];
                }

                if (empty($cart_items)) {
                    throw new Exception('سلة المشتريات فارغة أو تم إرسال الطلب بالفعل!');
                }

                $MIN_CART_VALUE = 1000; 
                $MAX_QTY_PER_ITEM = 50; 
                $MAX_TOTAL_QTY = 200;   

                $actual_cart_total = 0;
                $total_requested_qty = 0;

                $grouped_by_merchant = [];
                foreach ($cart_items as $item) {
                    $grouped_by_merchant[$item['merchant_id']][] = $item;
                }

                foreach ($cart_items as &$c_item) {
                    $qty = (int)$c_item['qty'];

                    if ($qty <= 0) throw new Exception("الكمية المطلوبة لأحد المنتجات غير صالحة.");
                    if ($qty > $MAX_QTY_PER_ITEM) throw new Exception("عذراً، لا يمكنك طلب أكثر من {$MAX_QTY_PER_ITEM} وحدة من نفس المنتج لمنع التلاعب.");

                    $total_requested_qty += $qty;

                    $stmt_check_price = $pdo->prepare(
                        "SELECT l.merchant_price, p.discount 
                         FROM merchant_listings l JOIN products p ON l.global_product_id = p.id
                         WHERE l.id = ?");
                    $stmt_check_price->execute([$c_item['listing_id']]);
                    $p_data = $stmt_check_price->fetch(PDO::FETCH_ASSOC);

                    if ($p_data) {
                        $real_price = $p_data['merchant_price'] * (1 - ($p_data['discount'] / 100));
                        $actual_cart_total += ($real_price * $qty);
                    } else {
                        throw new Exception("أحد المنتجات في السلة غير موجود أو تم حذفه.");
                    }
                }
                unset($c_item);

                if ($total_requested_qty > $MAX_TOTAL_QTY) {
                    throw new Exception("تجاوزت الحد الأقصى لإجمالي المنتجات المسموح بها في الطلب الواحد ({$MAX_TOTAL_QTY} قطعة).");
                }

                if ($actual_cart_total < $MIN_CART_VALUE) {
                    throw new Exception("عذراً، الحد الأدنى لإتمام الطلب هو {$MIN_CART_VALUE}. قيمة منتجاتك الحالية: " . number_format($actual_cart_total) . ".");
                }

                $auto_assign_agent_id = null;
                $direct_status = 'pending_delivery_acceptance';

                $owner_ids = array_keys($grouped_by_merchant);
                if (count($owner_ids) === 1 && $owner_ids[0] !== null) {
                    $owner_id = $owner_ids[0];
                    $stmt_owner_role = $pdo->prepare("SELECT role FROM users WHERE id = ?");
                    $stmt_owner_role->execute([$owner_id]);
                    $owner_role = $stmt_owner_role->fetchColumn();

                    if ($owner_role === 'delivery') {
                        $auto_assign_agent_id = $owner_id;
                        $direct_status = 'accepted_by_delivery';
                    }
                }
                
                $total_delivery_fee = 1500; 
                $merchant_locations =[];

                foreach (array_keys($grouped_by_merchant) as $m_id) {
                    $stmt_merchant_loc = $pdo->prepare("SELECT settings FROM users WHERE id = ?");
                    $stmt_merchant_loc->execute([$m_id]);
                    $merchant_settings = json_decode($stmt_merchant_loc->fetchColumn() ?: '{}', true);
                    $m_coords = extract_coords_from_url($merchant_settings['location'] ?? null);
                    if ($m_coords) {
                        $merchant_locations[$m_id] = $m_coords;
                    }
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
                    
                    $extra_stops = count($grouped_by_merchant) - 1;
                    $total_delivery_fee = $calculated_base_fee + ($extra_stops * 300);
                } else {
                    $total_delivery_fee = 1500 + ((count($grouped_by_merchant) - 1) * 500);
                }

                $fee_per_order = ceil(($total_delivery_fee / count($grouped_by_merchant)) / 50) * 50;
                
                $pdo->prepare("UPDATE customers SET full_name = ?, address = ? WHERE id = ?")->execute([$final_name, $final_address, $customer_id]);
                
                $new_order_group_id = 'GRP-' . generate_uuid();

                foreach ($grouped_by_merchant as $merchant_id => $items) {
                    $currency = 'YER';
                    
                    // بناء نظام تذاكر الظل (Shadow Tickets) للطلبات الجديدة
                    $delivery_code = rand(1000, 9999);
                    $final_status = ($direct_status === 'accepted_by_delivery') ? 'accepted_by_delivery' : 'pending_merchant_approval'; // يتم إرساله للتاجر أولاً
                    $ticket_id = 'TCK-' . generate_uuid();
                    $order_items_array = [];
                    $total_products_price = 0;

                    foreach ($items as $item) {
                        $listing_stmt = $pdo->prepare(
                            "SELECT l.*, p.name as product_name, p.image as product_image, p.sizes, p.discount
                            FROM merchant_listings l
                            JOIN products p ON l.global_product_id = p.id
                            WHERE l.id = ? AND l.is_available = 1 FOR UPDATE"
                        );
                        $listing_stmt->execute([$item['listing_id']]);
                        $listing = $listing_stmt->fetch(PDO::FETCH_ASSOC);
                        
                        if (!$listing) throw new Exception("المنتج {$item['name']} لم يعد متوفراً من هذا التاجر.");

                        $qty = (int)$item['qty'];
                        if ($listing['quantity_type'] === 'tracked') {
                            if ($listing['quantity'] < $qty) throw new Exception("الكمية المطلوبة من {$listing['product_name']} غير كافية في مخزون التاجر.");
                            // خصم الكمية من المخزون
                            $pdo->prepare("UPDATE merchant_listings SET quantity = quantity - ? WHERE id = ?")->execute([$qty, $listing['id']]);
                        }
                        
                        $base_price = (float)$listing['merchant_price'];
                        $option_info = null;
                        $item_image = $listing['product_image'];
                        $item_option_id = $item['size_id'] ?? null;

                        if ($item_option_id && !empty($listing['sizes'])) {
                            $options_array = json_decode($listing['sizes'], true);
                            if (is_array($options_array)) {
                                foreach ($options_array as $opt) {
                                    if (isset($opt['id']) && $opt['id'] === $item_option_id) {
                                        $option_info = $opt['name'] ?? null;
                                        if (isset($opt['custom_price']) && $opt['custom_price'] !== null && $opt['custom_price'] !== '') {
                                            $base_price = (float)$opt['custom_price'];
                                        }
                                        if (!empty($opt['image'])) $item_image = $opt['image'];
                                        break;
                                    }
                                }
                            }
                        }

                        $final_secure_price = $base_price * (1 - ((float)$listing['discount'] / 100));
                        $total_products_price += ($final_secure_price * $qty);
                        
                        // تعبئة بيانات المنتج داخل التذكرة
                        $order_items_array[] = [
                            'product_id' => $listing['global_product_id'],
                            'listing_id' => $listing['id'],
                            'size_id' => $item_option_id,
                            'product_name' => $listing['product_name'],
                            'size_info' => $option_info,
                            'quantity' => $qty,
                            'price' => $final_secure_price,
                            'cost_price' => $listing['cost_price'],
                            'image' => $item_image
                        ];
                    }

                    // تجميع التذكرة النهائية (JSON)
                    $stmt_m = $pdo->prepare("SELECT store_name FROM users WHERE id = ?"); $stmt_m->execute([$merchant_id]); $merchant_name_query = $stmt_m->fetchColumn();
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
                            'name' => $merchant_name_query ?: 'المتجر'
                        ],
                        'financials' => [
                            'products_total' => $total_products_price,
                            'delivery_fee' => $fee_per_order,
                            'grand_total' => $total_products_price + $fee_per_order,
                            'currency' => $currency
                        ],
                        'items' => $order_items_array
                    ];

                    $json_data = json_encode($ticket_payload, JSON_UNESCAPED_UNICODE);

                    // إنشاء التذكرة وإرسالها لجدول الطلبات النشطة مباشرة
                    $stmt = $pdo->prepare("INSERT INTO live_tickets (ticket_id, order_group_id, merchant_id, delivery_agent_id, customer_id, status, delivery_code, ticket_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([
                        $ticket_id, $new_order_group_id, $merchant_id, $auto_assign_agent_id, 
                        $customer_id, $final_status, $delivery_code, $json_data
                    ]);
                    // إرسال إشارة صفرية للتاجر بتحديث وقت الملف
// إرسال إشارة صفرية للتاجر بتحديث وقت الملف (مع ضمان وجود المجلد)
                    $signal_dir = __DIR__ . '/cache/signals';
                    if (!is_dir($signal_dir)) { @mkdir($signal_dir, 0755, true); }
                    @touch($signal_dir . '/m_' . $merchant_id . '.txt');
                    
                } // نهاية الحلقة التكرارية للتجار

                // تفريغ سلة العميل بعد اعتماد الطلب
                try { try { $pdo->prepare("DELETE FROM user_cart WHERE customer_id = ?")->execute([$customer_id]); } catch(Exception $e) {} } catch(Exception $e) {}
                
                $pdo->commit();

                // تحديث كاش المنتجات
                // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
if ($user_role === 'merchant') { // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null); }
                $success_msg = $auto_assign_agent_id ? 'تم استلام طلبك وتخصيص المندوب!' : 'تم استلام طلبك وبانتظار موافقة التاجر لتجهيزه!';
                $response_data = ['orderGroupId' => $new_order_group_id, 'message' => $success_msg];
                
                if (!empty($idempotency_key)) {
                    $pdo->prepare("UPDATE idempotency_keys SET response_data = ? WHERE key_token = ?")
                        ->execute([json_encode($response_data, JSON_UNESCAPED_UNICODE), $idempotency_key]);
                }
                @file_put_contents(__DIR__ . '/../last_update.txt', time());
                send_response('success', $response_data);
            } catch (Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                
                if (!empty($idempotency_key)) {
                    try { $pdo->prepare("DELETE FROM idempotency_keys WHERE key_token = ?")->execute([$idempotency_key]); } catch (Exception $ex) {}
                }
                
                throw new Exception($e->getMessage()); 
            }
            break;

      case 'get_orders':
            if (!$user_id) send_response('error',['message' => 'غير مصرح لك بالوصول'], 401);
            $filter = sanitize_input($input['filter'] ?? 'active'); 
            
            $orders = []; // تجهيز مصفوفة فارغة للحماية

            try {
                if ($filter === 'active') { 
                    $sql = "SELECT ticket_id as id, order_group_id, status, created_at, delivery_code, delivery_agent_id, ticket_data 
                            FROM live_tickets WHERE merchant_id = ? ORDER BY created_at DESC";
                    $stmt = $pdo->prepare($sql); 
                    $stmt->execute([$user_id]); 
                    $tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    foreach ($tickets as $t) {
                        $data = json_decode($t['ticket_data'], true);
                        if (!is_array($data)) $data = []; // حماية إضافية
                        
                        // فحص ذكي لوجود البيانات داخل الـ JSON لمنع انهيار الـ PHP
                        $fin = isset($data['financials']) && is_array($data['financials']) ? $data['financials'] : [];
                        $cust = isset($data['customer']) && is_array($data['customer']) ? $data['customer'] : [];
                        $merch = isset($data['merchant']) && is_array($data['merchant']) ? $data['merchant'] : [];
                        $agent = isset($data['delivery_agent']) && is_array($data['delivery_agent']) ? $data['delivery_agent'] : [];

                        $orders[] = [
                            'id' => $t['id'] ?? '',
                            'order_group_id' => $t['order_group_id'] ?? '',
                            'total_amount' => $fin['grand_total'] ?? 0,
                            'currency' => $fin['currency'] ?? 'YER',
                            'delivery_fee' => $fin['delivery_fee'] ?? 0,
                            'delivery_address_text' => $cust['address_text'] ?? 'عنوان غير محدد',
                            'delivery_gps_link' => $cust['gps_link'] ?? '',
                            'status' => $t['status'] ?? 'pending',
                            'created_at' => $t['created_at'] ?? '',
                            'delivery_code' => $t['delivery_code'] ?? '',
                            'delivery_agent_id' => $t['delivery_agent_id'] ?? null,
                            'customer_name' => $cust['name'] ?? 'عميل',
                            'customer_phone' => $cust['phone'] ?? '',
                            'merchant_name' => $merch['name'] ?? 'متجر',
                            'delivery_agent_name' => $agent['name'] ?? 'جاري البحث...',
                            'items' => isset($data['items']) && is_array($data['items']) ? $data['items'] : [],
                            'is_agent_assigned' => ($t['delivery_agent_id'] !== null),
                            'can_be_prepared' => (!in_array($t['status'] ?? '', ['pending_delivery_acceptance', 'pending_verification']))
                        ];
                    }
                } else { 
                    $sql = "SELECT ticket_id as id, final_status as status, archived_at as created_at, archived_data, total_amount 
                            FROM orders_archive WHERE merchant_id = ? ORDER BY archived_at DESC";
                    $stmt = $pdo->prepare($sql); 
                    $stmt->execute([$user_id]); 
                    $archives = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    foreach ($archives as $arc) {
                        $data = json_decode($arc['archived_data'], true);
                        if (!is_array($data)) $data = [];
                        
                        $fin = isset($data['financials']) && is_array($data['financials']) ? $data['financials'] : [];
                        $cust = isset($data['customer']) && is_array($data['customer']) ? $data['customer'] : [];
                        $merch = isset($data['merchant']) && is_array($data['merchant']) ? $data['merchant'] : [];

                        $orders[] = [
                            'id' => $arc['id'] ?? '',
                            'order_group_id' => $data['order_group_id'] ?? $arc['id'],
                            'total_amount' => $arc['total_amount'] ?? 0,
                            'currency' => $fin['currency'] ?? 'YER',
                            'delivery_fee' => $fin['delivery_fee'] ?? 0,
                            'delivery_address_text' => $cust['address_text'] ?? '',
                            'status' => $arc['status'] ?? 'completed',
                            'created_at' => $arc['created_at'] ?? '',
                            'customer_name' => $cust['name'] ?? 'عميل',
                            'customer_phone' => $cust['phone'] ?? '',
                            'merchant_name' => $merch['name'] ?? 'متجر',
                            'items' => isset($data['items']) && is_array($data['items']) ? $data['items'] : [],
                            'is_agent_assigned' => false,
                            'can_be_prepared' => false
                        ];
                    }
                }
                send_response('success',['data' => $orders]);
            } catch (Exception $e) {
                error_log("API Error in get_orders: " . $e->getMessage());
                send_response('success',['data' => []]); // إرسال مصفوفة فارغة بدلاً من الخطأ لمنع انهيار الواجهة
            }
            break;

        case 'get_user_orders':
            if (!$customer_id) send_response('error',[], 401);
            
            $grouped_orders = [];
            $processed_ticket_ids = []; 

            try {
                // 1. التذاكر النشطة
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
                        'merchant_id' => $t['merchant_id'] ?? $merch['id'] ?? null, // ✅ إصلاح هام
                        'merchant_name' => $merch['name'] ?? 'متجر',
                        'customer_phone' => $cust['phone'] ?? '',
                        'delivery_agent_name' => $agent_name,
                        'delivery_agent_phone' => $agent_phone,
                        'is_private_agent' => $is_private,
                        'items' => isset($data['items']) && is_array($data['items']) ? array_values($data['items']) : [] // ✅ إصلاح المصفوفات
                    ];

                    $group_id = $t['order_group_id'] ?? $t['id'];
                    if (!isset($grouped_orders[$group_id])) { 
                        $grouped_orders[$group_id] = ['group_id' => $group_id, 'created_at' => $t['created_at'], 'sub_orders' => []]; 
                    }
                    $grouped_orders[$group_id]['sub_orders'][] = $order;
                }

                // 2. التذاكر المؤرشفة
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
                        'merchant_id' => $arc['merchant_id'] ?? $merch['id'] ?? null, // ✅ إصلاح هام
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

                // 3. الطلبات القديمة (إن وجدت)
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
                            'merchant_id' => $lo['merchant_id'] ?? null, // ✅ إصلاح هام
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
            $otp = rand(100000, 999999);
            try { $pdo->exec("ALTER TABLE customers ADD COLUMN otp_code VARCHAR(10) NULL AFTER phone"); } catch (Exception $e) { }
            $pdo->prepare("UPDATE customers SET otp_code = ? WHERE id = ?")->execute([$otp, $customer_id_for_otp]);
            $stmt = $pdo->prepare("SELECT phone, full_name FROM customers WHERE id = ?"); $stmt->execute([$customer_id_for_otp]); $cust = $stmt->fetch(PDO::FETCH_ASSOC);
            $phone = preg_replace('/[^0-9]/', '', $cust['phone']);
            if (strpos($phone, '967') === 0 && strlen($phone) >= 12) $phone = substr($phone, 3);
            elseif (strpos($phone, '00967') === 0) $phone = substr($phone, 5);
            elseif (strpos($phone, '0') === 0 && strlen($phone) == 10) $phone = substr($phone, 1);
            $message = "مرحباً {$cust['full_name']}\nكود التفعيل الخاص بك هو: {$otp}\nلا تشاركه مع أحد.";
            $url = "https://trigger.macrodroid.com/" . $MACRO_DEVICE_ID . "/" . $MACRO_WEBHOOK_NAME . "?phone=" . urlencode($phone) . "&msg=" . urlencode($message);
            $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_TIMEOUT, 6); 
            $curl_result = curl_exec($ch); $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
            $smsMsg = ($httpcode == 200 && $curl_result !== false) ? "، جاري إرسال الـ SMS من هاتفك" : "، (ملاحظة: يبدو أن سيرفر الإرسال/الجوال متوقف، لن يتم إرسال SMS)";
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
        
        case 'login':
            try { $pdo->exec("ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0 AFTER password"); } catch (Exception $e) {}
            try { $pdo->exec("ALTER TABLE users ADD COLUMN lockout_until DATETIME NULL AFTER failed_login_attempts"); } catch (Exception $e) {}

            $max_attempts = 5;
            $lockout_time_minutes = 15;
            $identifier = sanitize_input($input['phone'] ?? '');
            $password = $input['password'] ?? '';

            $is_phone = (bool)preg_match('/^[0-9]+$/', $identifier);
            if ($is_phone) {
                $stmt = $pdo->prepare("SELECT id, username, password, store_name, role, is_active, phone, failed_login_attempts, lockout_until FROM users WHERE phone = ? AND role IN ('merchant', 'delivery')");
            } else {
                $stmt = $pdo->prepare("SELECT id, username, password, store_name, role, is_active, phone, failed_login_attempts, lockout_until FROM users WHERE username = ? AND role IN ('merchant', 'delivery')");
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
                $placeholders = implode(',', array_fill(0, count($account_ids), '?'));

                $pdo->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id IN ($placeholders)")->execute($account_ids);

                $stmt_check = $pdo->prepare("SELECT MAX(failed_login_attempts) FROM users WHERE id IN ($placeholders)");
                $stmt_check->execute($account_ids);
                $current_attempts = $stmt_check->fetchColumn();

                if ($current_attempts >= $max_attempts) {
                    $pdo->prepare("UPDATE users SET lockout_until = DATE_ADD(NOW(), INTERVAL $lockout_time_minutes MINUTE) WHERE id IN ($placeholders)")->execute($account_ids);
                    throw new Exception("تم قفل الحساب تحديداً لمدة 15 دقيقة بسبب تجاوز 5 محاولات فاشلة.");
                }

                $attempts_left = $max_attempts - $current_attempts;
                throw new Exception("بيانات الدخول غير صحيحة. تبقى لك {$attempts_left} محاولات قبل قفل الحساب.");
            }

            $successful_ids = array_column($valid_logins, 'id');
            $placeholders_success = implode(',', array_fill(0, count($successful_ids), '?'));
            $pdo->prepare("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id IN ($placeholders_success)")->execute($successful_ids);

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
                $otp = rand(100000, 999999);
                
                $token_payload =[
                    'purpose' => 'new_device_login',
                    'phone' => $phone_to_check,
                    'valid_logins' => $valid_logins,
                    'otp' => $otp,
                    'attempts' => 0
                ];
                $state_token = generate_signed_token($token_payload, 5);
                setcookie('state_token', $state_token, time() + 300, '/', '', $is_secure_cookie, true);
                
                $message = "رمز التحقق لتسجيل الدخول من جهاز جديد هو: {$otp}";
                try {
                    $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone_to_check, $message]);
                } catch(PDOException $e) {}
                
                send_response('new_device_otp_required',['message' => 'تم اكتشاف محاولة دخول من جهاز جديد. يرجى إدخال رمز التحقق المرسل لجوالك.']);
            }

         // ... (داخل case 'login':)

if (count($valid_logins) === 1) {
    $user = $valid_logins[0];

    // ⭐ بداية التعديل: إنشاء وإرسال التوكن بدلاً من الجلسة
    $payload = [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'store_name' => $user['store_name'],
        'role' => $user['role'],
        'exp' => time() + (60 * 60 * 8) // صلاحية لمدة 8 ساعات
    ];
    
    // تشفير التوكن
    $header_encoded = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload_encoded = base64_encode(json_encode($payload));
    $signature = hash_hmac('sha256', "$header_encoded.$payload_encoded", APP_SECRET_KEY, true);
    $signature_encoded = base64_encode($signature);
    
    $token = "$header_encoded.$payload_encoded.$signature_encoded";

    $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.html' : 'delivery-dashboard.html';
    
    // إرسال التوكن مع رابط الانتقال
    send_response('success',['token' => $token, 'redirect' => $redirect]);
    // ⭐ نهاية التعديل

} else {
    // ... (باقي الكود لاختيار الدور يبقى كما هو)    
                $selection_data =[];
                foreach ($valid_logins as $account) {
                    $selection_data[$account['role']] =[
                        'id' => $account['id'],
                        'name' => $account['store_name'] ?: $account['username']
                    ];
                }
                $_SESSION['login_selection_data'] = $selection_data;
                send_response('role_selection_required',['accounts' => $selection_data]);
            }
            break;
            
        case 'verify_new_device_otp':
            $otp_input = $input['otp'] ?? '';
            $token = $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'new_device_login');
            } catch (Exception $e) {
                throw new Exception($e->getMessage());
            }
            
            if ($otp_input != $payload['otp']) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', time() - 3600, '/');
                    throw new Exception("تم إلغاء العملية لتجاوز عدد المحاولات (3 محاولات). يرجى تسجيل الدخول من جديد.");
                }
                $new_token = generate_signed_token($payload, 5);
                setcookie('state_token', $new_token, time() + 300, '/', '', $is_secure_cookie, true);
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
                'domain' => '',
                'secure' => $is_secure_cookie,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
            
            setcookie('state_token', '', time() - 3600, '/'); 
            
            if (count($valid_logins) === 1) {
                $user = $valid_logins[0];
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['store_name'] = $user['store_name'];
                $_SESSION['loggedin'] = true;
                $_SESSION['role'] = $user['role'];
                $_SESSION['device_token'] = $new_device_token;
                
                // إنشاء التوكن
                $payload =['user_id' => $user['id'], 'username' => $user['username'], 'store_name' => $user['store_name'], 'role' => $user['role'], 'exp' => time() + (60 * 60 * 8)];
                $header_encoded = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
                $payload_encoded = base64_encode(json_encode($payload));
                $signature = hash_hmac('sha256', "$header_encoded.$payload_encoded", APP_SECRET_KEY, true);
                $token = "$header_encoded.$payload_encoded." . base64_encode($signature);
                
                $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.php' : 'delivery-dashboard.php';
                send_response('success',['token' => $token, 'redirect' => $redirect]);
            } else {
                $selection_data =[];
                foreach ($valid_logins as $account) {
                    $selection_data[$account['role']] =[
                        'id' => $account['id'],
                        'name' => $account['store_name'] ?: $account['username']
                    ];
                }
                $_SESSION['login_selection_data'] = $selection_data;
                send_response('role_selection_required',['accounts' => $selection_data]);
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
            
            // إنشاء التوكن
            $payload = ['user_id' => $user['id'], 'username' => $user['username'], 'store_name' => $user['store_name'], 'role' => $user['role'], 'exp' => time() + (60 * 60 * 8)];
            $header_encoded = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
            $payload_encoded = base64_encode(json_encode($payload));
            $signature = hash_hmac('sha256', "$header_encoded.$payload_encoded", APP_SECRET_KEY, true);
            $token = "$header_encoded.$payload_encoded." . base64_encode($signature);
            
            $redirect = ($user['role'] === 'merchant') ? 'merchant-dashboard.php' : 'delivery-dashboard.php';
            send_response('success',['token' => $token, 'redirect' => $redirect]);
            break;
        
        case 'register_init':
            $allowed_fields =['phone', 'role', 'name', 'username', 'password'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $phone = preg_replace('/[^0-9]/', '', $safe_input['phone'] ?? '');
            $role = in_array($safe_input['role'] ?? '',['merchant', 'delivery']) ? $safe_input['role'] : null;
            $name = sanitize_input($safe_input['name'] ?? '');
            $username = sanitize_input($safe_input['username'] ?? '');
            $password = $safe_input['password'] ?? null;
            
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
            
            $otp = rand(100000, 999999);
            $hashed_pass = password_hash($password, PASSWORD_DEFAULT);
            
            $token_payload =[
                'purpose' => 'registration',
                'username' => $username,
                'password' => $hashed_pass,
                'store_name' => $name,
                'phone' => $phone,
                'role' => $role,
                'otp' => $otp,
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 10);
            setcookie('state_token', $state_token, time() + 600, '/', '', $is_secure_cookie, true);

            $message = "كود تفعيل حساب الشريك الخاص بك هو: {$otp}";
            $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone, $message]);
            send_response('success_otp_sent');
            break;
        
        case 'register_verify':
            $otp = $input['otp'] ?? '';
            $token = $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'registration');
            } catch (Exception $e) {
                throw new Exception($e->getMessage());
            }

            if ($otp != $payload['otp']) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', time() - 3600, '/');
                    throw new Exception("تم تجاوز المحاولات (3 محاولات). يرجى طلب كود جديد.");
                }
                $new_token = generate_signed_token($payload, 10);
                setcookie('state_token', $new_token, time() + 600, '/', '', $is_secure_cookie, true);
                throw new Exception('رمز التحقق غير صحيح. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
            }

            $stmt = $pdo->prepare("INSERT INTO users (username, password, store_name, phone, role, is_active) VALUES (?, ?, ?, ?, ?, 1)");
            $stmt->execute([$payload['username'], $payload['password'], $payload['store_name'], $payload['phone'], $payload['role']]);
            
            setcookie('state_token', '', time() - 3600, '/'); 
            send_response('success',['message' => 'تم تفعيل حسابك بنجاح! يمكنك الآن تسجيل الدخول.']);
            break;
            
        case 'add_internal_role':
            if (!$user_id || !in_array($user_role,['merchant', 'delivery'])) {
                send_response('error',['message' => 'غير مصرح'], 401);
            }
            
            $allowed_fields =['password', 'store_name', 'username'];
            $safe_input = filter_allowed_keys($input, $allowed_fields);

            $password = $safe_input['password'] ?? '';
            $new_role = ($user_role === 'merchant') ? 'delivery' : 'merchant';
            $new_name = sanitize_input($safe_input['store_name'] ?? '');
            $new_username = sanitize_input($safe_input['username'] ?? '');
            
            if (!preg_match('/^[a-z][a-z0-9_.]{4,19}$/', $new_username)) {
                throw new Exception("اسم المستخدم غير صالح. يجب أن يبدأ بحرف، ويحتوي على حروف إنجليزية صغيرة وأرقام فقط، وطوله بين 5 و 20 حرفاً.");
            }
            
            $stmt_pass = $pdo->prepare("SELECT password, phone FROM users WHERE id = ?");
            $stmt_pass->execute([$user_id]);
            $current_user_data = $stmt_pass->fetch(PDO::FETCH_ASSOC);
            
            if (!$current_user_data || !password_verify($password, $current_user_data['password'])) {
                throw new Exception("كلمة المرور الحالية غير صحيحة.");
            }
            
            $phone = $current_user_data['phone'];
            
            $stmt_check_role = $pdo->prepare("SELECT id FROM users WHERE phone = ? AND role = ?");
            $stmt_check_role->execute([$phone, $new_role]);
            if ($stmt_check_role->fetch()) {
                throw new Exception("لديك حساب بهذا الدور مسبقاً.");
            }
            
            $stmt_check_username = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt_check_username->execute([$new_username]);
            if ($stmt_check_username->fetch()) {
                throw new Exception("اسم المستخدم هذا محجوز بالفعل. اختر اسماً آخر.");
            }
            
            $hashed_pass = $current_user_data['password']; 
            $stmt_insert = $pdo->prepare("INSERT INTO users (username, password, store_name, phone, role, is_active, settings) VALUES (?, ?, ?, ?, ?, 1, ?)");
            $stmt_insert->execute([$new_username, $hashed_pass, $new_name, $phone, $new_role, '{"location": null}']);
            
            send_response('success',['message' => 'تم إنشاء الحساب الإضافي بنجاح! يمكنك التبديل بين حساباتك عند تسجيل الدخول القادم.']);
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

        // =======================================================
        
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
        
            $otp = rand(100000, 999999);
            
            $token_payload =[
                'purpose' => 'password_recovery_otp',
                'phone' => $phone,
                'otp' => $otp,
                'attempts' => 0
            ];
            $state_token = generate_signed_token($token_payload, 10);
            setcookie('state_token', $state_token, time() + 600, '/', '', $is_secure_cookie, true);
            
            $message = "كود استعادة كلمة المرور الخاص بك هو: {$otp}";
            $pdo->prepare("INSERT INTO sms_queue (phone_number, message) VALUES (?, ?)")->execute([$phone, $message]);
            send_response('success');
            break;
        
        case 'recover_check_otp':
            $phone = preg_replace('/[^0-9]/', '', $input['phone'] ?? '');
            $otp_input = $input['otp'] ?? '';
            $token = $_COOKIE['state_token'] ?? '';
            
            try {
                $payload = verify_signed_token($token, 'password_recovery_otp');
            } catch (Exception $e) {
                throw new Exception($e->getMessage() . " يرجى طلب كود استعادة جديد.");
            }

            if ($phone !== $payload['phone']) {
                throw new Exception("بيانات غير متطابقة.");
            }

            if ($otp_input != $payload['otp']) {
                $payload['attempts']++;
                if ($payload['attempts'] >= 3) {
                    setcookie('state_token', '', time() - 3600, '/');
                    throw new Exception("تم تجاوز المحاولات (3 محاولات). يرجى طلب كود استعادة جديد.");
                }
                $new_token = generate_signed_token($payload, 10);
                setcookie('state_token', $new_token, time() + 600, '/', '', $is_secure_cookie, true);
                throw new Exception('رمز التحقق غير صحيح. تبقى لك ' . (3 - $payload['attempts']) . ' محاولات.');
            }

            $token_payload =[
                'purpose' => 'password_reset',
                'phone' => $phone
            ];
            $reset_token = generate_signed_token($token_payload, 10);
            setcookie('state_token', $reset_token, time() + 600, '/', '', $is_secure_cookie, true);
            
            send_response('success');
            break;
        
        case 'recover_set_password':
            $token = $_COOKIE['state_token'] ?? '';
            
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
            }
            
            setcookie('state_token', '', time() - 3600, '/'); 
            send_response('success');
            break;
        
        case 'logout':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);

            if (isset($_COOKIE['device_token'])) {
                $device_token = $_COOKIE['device_token'];
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ? AND device_token = ?")->execute([$user_id, $device_token]);
                setcookie('device_token', '',[
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => $is_secure_cookie,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);
            }
            
            // ⭐ الحل الذكي: حذف بيانات التاجر/المندوب فقط
            unset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['store_name'], $_SESSION['role'], $_SESSION['device_token']);
            
            // لا ندمر الجلسة بالكامل إلا إذا كان حساب العميل غير موجود أيضاً
            if (empty($_SESSION['customer_id'])) {
                $_SESSION =[];
                if (ini_get("session.use_cookies")) {
                    $params = session_get_cookie_params();
                    setcookie(session_name(), '',['expires' => time() - 42000, 'path' => $params["path"], 'domain' => $params["domain"], 'secure' => $params["secure"], 'httponly' => $params["httponly"], 'samesite' => 'Strict']);
                }
                session_destroy();
            }
            
            send_response('success',['message' => 'تم تسجيل الخروج بنجاح.']);
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
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            // ⭐ فحص اكتمال الملف الشخصي للتاجر
            if ($user_role === 'merchant') {
                $stmt_check_type = $pdo->prepare("SELECT store_name, store_type, settings FROM users WHERE id = ?");
                $stmt_check_type->execute([$user_id]);
                $u_data = $stmt_check_type->fetch(PDO::FETCH_ASSOC);
                $set = json_decode($u_data['settings'] ?: '{}', true);
                if (empty($u_data['store_name']) || empty($u_data['store_type']) || empty($set['location'])) {
                    throw new Exception("REQUIRE_PROFILE_UPDATE: يرجى استكمال بيانات متجرك (الاسم، نوع النشاط، والموقع على الخريطة) في قسم الإعدادات لتتمكن من إضافة المنتجات.");
                }
            }

            $idempotency_key = sanitize_input($input['idempotency_key'] ?? '');
            if (empty($idempotency_key)) { $idempotency_key = 'auto_prod_' . md5(json_encode($input) . $user_id . floor(time() / 15)); }

            if (!empty($idempotency_key)) {
                $stmt_check_key = $pdo->prepare("SELECT response_data FROM idempotency_keys WHERE key_token = ?"); $stmt_check_key->execute([$idempotency_key]);
                $existing_response = $stmt_check_key->fetchColumn();
                if ($existing_response !== false) {
                    if ($existing_response === 'processing') { send_response('success',['message' => 'جاري حفظ المنتج حالياً، يرجى الانتظار...']); }
                    $decoded_response = json_decode($existing_response, true);
                    send_response('success', $decoded_response ?:['message' => 'تم حفظ المنتج بنجاح (تأكيد مكرر).']);
                }
                try { $pdo->prepare("INSERT INTO idempotency_keys (key_token, response_data) VALUES (?, 'processing')")->execute([$idempotency_key]); } catch (PDOException $e) { send_response('success',['message' => 'تم حفظ المنتج بنجاح (تم تجاهل الطلب المكرر).']); }
            }

            try {
                $pdo->beginTransaction();
                
                $cost_price = floatval($input['cost_price'] ?? 0);
                $sell_price = floatval($input['price'] ?? 0);
                if ($sell_price <= 0) throw new Exception('سعر البيع يجب أن يكون رقماً موجباً.');
                
                $pid = !empty($input['id']) ? sanitize_input($input['id']) : null;
                $is_edit = !empty($pid);
                
                // 🛑 الجدار الأمني: التحقق من ملكية المنتج
                if ($is_edit && $user_role === 'merchant') {
                    $check_ownership = $pdo->prepare("SELECT id FROM merchant_listings WHERE global_product_id = ? AND merchant_id = ?");
                    $check_ownership->execute([$pid, $user_id]);
                    if (!$check_ownership->fetch()) {
                        error_log("🚨 محاولة اختراق: التاجر ID $user_id حاول تعديل المنتج $pid الذي لا يملكه!");
                        throw new Exception("عملية مرفوضة: أنت لا تملك صلاحية تعديل هذا المنتج.");
                    }
                }

                if ($is_edit && $user_role === 'merchant') {
                    $stmt_base_price = $pdo->prepare("SELECT base_price FROM products WHERE id = ?");
                    $stmt_base_price->execute([$pid]);
                    $base_price = (float)$stmt_base_price->fetchColumn();

                    if ($base_price > 0) {
                        $max_allowed_price = $base_price * (1 + (MAX_PRICE_INCREASE_PERCENTAGE / 100));
                        if ($sell_price > $max_allowed_price) {
                            throw new Exception("السعر يتجاوز الحد المسموح. أقصى سعر لهذا المنتج هو: " . round($max_allowed_price));
                        }
                    }

                    $allowed_fields_for_merchant = ['quantity_type', 'quantity', 'isAvailable'];
                    $safe_input = filter_allowed_keys($input, $allowed_fields_for_merchant);

                    $quantity_type = sanitize_input($safe_input['quantity_type'] ?? 'tracked');
                    $quantity = max(0, intval($safe_input['quantity'] ?? 0));
                    $is_available = (!empty($input['isAvailable']) || isset($_POST['isAvailable']) || $input['isAvailable'] === 'on' || $input['isAvailable'] === 'true') ? 1 : 0;

                    $sql_listing_update = "UPDATE merchant_listings SET merchant_price = ?, cost_price = ?, quantity = ?, quantity_type = ?, is_available = ? WHERE global_product_id = ? AND merchant_id = ?";
                    $stmt_listing = $pdo->prepare($sql_listing_update);
                    $stmt_listing->execute([$sell_price, $cost_price, $quantity, $quantity_type, $is_available, $pid, $user_id]);

                    $message = 'تم تحديث عرض المنتج بنجاح.';
                    $node_id = $pdo->query("SELECT id FROM merchant_listings WHERE global_product_id='$pid'")->fetchColumn();
                    $final_global_id = $pid;

                } else {
                    $discount_percent = floatval($input['discount'] ?? 0);
                    if ($sell_price <= $cost_price) throw new Exception('سعر البيع يجب أن يكون أعلى من سعر التكلفة.');
                    $final_price = $sell_price * (1 - ($discount_percent / 100));
                    if ($final_price < $cost_price) throw new Exception('الخصم كبير جداً، السعر بعد الخصم لا يمكن أن يكون أقل من التكلفة.');

                    $img = sanitize_input($input['existing_image'] ?? '');
                    if (isset($_FILES['image_file']) && $_FILES['image_file']['error'] === UPLOAD_ERR_OK) {
                        $validation_result = validate_image_upload($_FILES['image_file']);
                        if ($validation_result !== true) { throw new Exception("خطأ في صورة المنتج الرئيسية: " . $validation_result); }
                        $extension = strtolower(pathinfo($_FILES['image_file']['name'], PATHINFO_EXTENSION));
                        $new_filename = 'p-' . uniqid() . bin2hex(random_bytes(8)) . '.' . $extension;
                        if (move_uploaded_file($_FILES['image_file']['tmp_name'], UPLOAD_DIR . $new_filename)) { $img = UPLOAD_DIR . $new_filename; } 
                        else { throw new Exception("فشل نقل الصورة الرئيسية للمنتج."); }
                    } elseif (!empty($input['image_url'])) { 
                        if (is_safe_image_url($input['image_url'])) { $img = sanitize_input($input['image_url']); } 
                        else { throw new Exception("رابط الصورة الرئيسية غير صالح أمنياً."); }
                    }
                    
                    $quantity_type = sanitize_input($input['quantity_type'] ?? 'tracked');
                    if (!in_array($quantity_type, ['tracked', 'unlimited'])) $quantity_type = 'tracked';
                    
                    $listing_total_quantity = ($quantity_type === 'unlimited') ? 9999 : (int)($input['quantity'] ?? 0);
                    $is_available = (!empty($input['isAvailable']) || isset($_POST['isAvailable']) || $input['isAvailable'] === 'on' || $input['isAvailable'] === 'true') ? 1 : 0;
                    
                    $approval_status = 'approved'; 
                    $category_id = sanitize_input($input['category_id'] ?? null);
                    $new_category_name = sanitize_input($input['category'] ?? null); 
                    $parent_category_id = sanitize_input($input['parent_category_id'] ?? null); 
                    
                    if (empty($category_id) && !empty($new_category_name)) {
                        $stmt_find_cat = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND (parent_id = ? OR (? IS NULL AND parent_id IS NULL))");
                        $stmt_find_cat->execute([$new_category_name, $parent_category_id, $parent_category_id]);
                        $existing_cat_id = $stmt_find_cat->fetchColumn();
                        if ($existing_cat_id) {
                            $category_id = $existing_cat_id;
                        } else {
                            $stmt_create_cat = $pdo->prepare("INSERT INTO categories (name, parent_id, user_id) VALUES (?, ?, ?)");
                            $stmt_create_cat->execute([$new_category_name, $parent_category_id, $user_id]);
                            $category_id = $pdo->lastInsertId();
                        }
                    }

                    $sizes_json = !empty($input['sizes']) ? $input['sizes'] : null;

                    if ($is_edit) { 
                        $sql_product = "UPDATE products SET name=?, mainDescription=?, price=?, base_price=?, discount=?, isAvailable=?, image=?, approval_status=?, category_id=?, sizes=? WHERE id=?";
                        $fields_product = [ sanitize_input($input['name']), sanitize_input($input['mainDescription']), $sell_price, $sell_price, $discount_percent, $is_available, $img, $approval_status, $category_id, $sizes_json, $pid ];
                        $pdo->prepare($sql_product)->execute($fields_product);
                        
                        $sql_listing = "UPDATE merchant_listings SET merchant_price = ?, cost_price = ?, quantity = ?, quantity_type = ?, is_available = ? WHERE global_product_id = ? AND merchant_id = ?";
                        $pdo->prepare($sql_listing)->execute([$sell_price, $cost_price, $listing_total_quantity, $quantity_type, $is_available, $pid, $user_id]);
                        $message = 'تم تحديث عرض المنتج بنجاح.';
                        $node_id = $pdo->query("SELECT id FROM merchant_listings WHERE global_product_id='$pid'")->fetchColumn();
                        $final_global_id = $pid;

                    } else { 
                        $pnum = ($pdo->query("SELECT MAX(CAST(product_number AS UNSIGNED)) FROM products")->fetchColumn() ?: 0) + 1;
                        $new_pid = 'prod_' . generate_uuid();

                        $sql_product = "INSERT INTO products (name, mainDescription, price, base_price, discount, isAvailable, image, approval_status, product_number, id, user_id, category_id, sizes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                        $pdo->prepare($sql_product)->execute([ sanitize_input($input['name']), sanitize_input($input['mainDescription']), $sell_price, $sell_price, $discount_percent, $is_available, $img, $approval_status, $pnum, $new_pid, $user_id, $category_id, $sizes_json ]);

                        $sql_listing = "INSERT INTO merchant_listings (merchant_id, global_product_id, merchant_price, cost_price, quantity, quantity_type, is_available) VALUES (?, ?, ?, ?, ?, ?, ?)";
                        $pdo->prepare($sql_listing)->execute([$user_id, $new_pid, $sell_price, $cost_price, $listing_total_quantity, $quantity_type, $is_available]);
                        $message = 'تم حفظ المنتج بنجاح.';
                        $node_id = $pdo->lastInsertId();
                        $final_global_id = $new_pid;
                    }
                }
                
                $pdo->commit(); // 🛑 نغلق معاملة قاعدة البيانات هنا مرة واحدة فقط
                
                // ⭐ التحديث الذري في Firebase
                $safe_username = $_SESSION['username'] ?? 'store';
                $safe_store_name = $_SESSION['store_name'] ?? 'المتجر';
                $department_val = $new_category_name ?? '';
                $sizes_val = $sizes_json ?? '[]';
                $discount_val = isset($discount_percent) ? $discount_percent : 0;
                
                $firebase_product = [
                    'id' => $final_global_id,
                    'name' => sanitize_input($input['name']),
                    'mainDescription' => sanitize_input($input['mainDescription']),
                    'price' => $sell_price,
                    'discount' => $discount_val,
                    'image' => $img ?? '',
                    'type' => $department_val,
                    'department' => $department_val,
                    'listing_id' => $node_id,
                    'quantity' => $is_edit ? $quantity : $listing_total_quantity,
                    'quantity_type' => $quantity_type,
                    'merchant_id' => $user_id,
                    'merchant_name' => $safe_store_name,
                    'currency' => 'YER',
                    'is_available' => $is_available,
                    'approval_status' => 'approved',
                    'options' => json_decode($sizes_val, true) ?: [],
                    'updated_at' => time()
                ];

                // الرفع لفايربيس
                patchFirebaseNode("global/products/" . $node_id, $firebase_product);
                patchFirebaseNode("stores/" . $safe_username . "/products/" . $node_id, $firebase_product);

                $response_data = ['message' => $message];
                if (!empty($idempotency_key)) { 
                    $pdo->prepare("UPDATE idempotency_keys SET response_data = ? WHERE key_token = ?")->execute([json_encode($response_data, JSON_UNESCAPED_UNICODE), $idempotency_key]); 
                }

                send_response('success', $response_data);

            } catch (Exception $e) { 
                if ($pdo->inTransaction()) $pdo->rollBack(); 
                if (!empty($idempotency_key)) { try { $pdo->prepare("DELETE FROM idempotency_keys WHERE key_token = ?")->execute([$idempotency_key]); } catch (Exception $ex) {} }
                throw $e; 
            }
            break;

        case 'get_global_catalog':
            if ($user_role !== 'merchant') {
                throw new Exception("هذه الخاصية متاحة للتجار فقط.");
            }
            $term = sanitize_input($input['term'] ?? '');

            $sql = "
                SELECT 
                    p.id, p.name, p.image, p.sizes, c.name as type,
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
                $product['options'] = json_decode($product['sizes'] ?? '[]', true);
                unset($product['sizes']);
                unset($product['listing_id']);
            }
            
            send_response('success', ['data' => $products]);
            break;

        case 'add_listing_from_catalog':
            if ($user_role !== 'merchant') {
                throw new Exception("هذه الخاصية متاحة للتجار فقط.");
            }
            
            // ⭐ فحص اكتمال الملف الشخصي للتاجر
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

            $stmt_check = $pdo->prepare("SELECT id, sizes, base_price FROM products WHERE id = ? AND approval_status = 'approved'");
            $stmt_check->execute([$global_id]);
            $global_product = $stmt_check->fetch(PDO::FETCH_ASSOC);

            if (!$global_product) {
                throw new Exception("المنتج المحدد غير موجود في الكتالوج العام أو لم تتم الموافقة عليه بعد.");
            }

            $base_price = (float)$global_product['base_price'];
            if ($base_price > 0) {
                $max_allowed_price = $base_price * (1 + (MAX_PRICE_INCREASE_PERCENTAGE / 100));
                if ($merchant_price > $max_allowed_price) {
                    throw new Exception("السعر يتجاوز الحد المسموح. أقصى سعر مسموح به لهذا المنتج هو: " . round($max_allowed_price), 400);
                }
            }
            
            $price_variables = null;
            if (!empty($selected_options_ids) && is_array($selected_options_ids)) {
                $global_options = json_decode($global_product['sizes'] ?? '[]', true);
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
        case 'search_products':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $term = sanitize_input($input['term'] ?? '');
            $page = max(1, intval($input['page'] ?? 1));
            
            // ⭐ حماية السيرفر: لوحة التحكم تجلب 100 منتج فقط كحد أقصى في كل صفحة (وليس الملايين دفعة واحدة)
            $limit = ($action === 'search_products') ? 20 : 100;
            $offset = ($page - 1) * $limit;
            
            $where = []; 
            $params = [];

            // ⭐ محرك البحث الصاروخي: تم استبدال LIKE البطيء بـ MATCH السريع جداً
            if ($term) {
                $where[] = "MATCH(p.name, p.keywords, p.mainDescription) AGAINST(? IN BOOLEAN MODE)";
                $params[] = $term . '*';
            }

            if ($user_role === 'admin') {
                $where_sql = count($where) > 0 ? 'WHERE ' . implode(' AND ', $where) : '';
                $sql = "
                    SELECT 
                        p.id, p.name, p.mainDescription, p.image, p.sizes, p.approval_status, p.isAvailable as is_available, c.name as type,
                        l.id as listing_id, 
                        COALESCE(l.merchant_price, p.price) as price,
                        l.cost_price, 
                        l.quantity, 
                        l.quantity_type, 
                        COALESCE(u.store_name, 'الإدارة') as merchant_name
                    FROM products p
                    LEFT JOIN merchant_listings l ON p.id = l.global_product_id
                    LEFT JOIN users u ON l.merchant_id = u.id
                    LEFT JOIN categories c ON p.category_id = c.id
                    {$where_sql}
                    ORDER BY p.created_at DESC 
                    LIMIT $limit OFFSET $offset
                ";
            } else { 
                $where[] = "l.merchant_id = ?";
                $params[] = $user_id;
                $where_sql = 'WHERE ' . implode(' AND ', $where);
                
                $sql = "
                    SELECT 
                        p.id, p.name, p.mainDescription, p.image, p.sizes, p.approval_status, c.name as type, p.id as global_product_id,
                        l.id as listing_id, l.merchant_price as price, l.cost_price, l.quantity, l.quantity_type, l.is_available
                    FROM merchant_listings l
                    JOIN products p ON l.global_product_id = p.id
                    LEFT JOIN categories c ON p.category_id = c.id
                    {$where_sql}
                    ORDER BY l.created_at DESC 
                    LIMIT $limit OFFSET $offset
                ";
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $catPaths = get_full_category_paths($pdo);
            
            foreach ($products as &$prod) { 
                $options_data = json_decode($prod['sizes'] ?? '[]', true); 
                if (is_array($options_data)) { 
                    foreach($options_data as &$opt) { 
                        if (isset($opt['size_name']) && !isset($opt['name'])) { 
                            $opt['name'] = $opt['size_name']; unset($opt['size_name']); 
                        } 
                    } 
                } 
                $prod['options'] = $options_data; 
                unset($prod['sizes']); 
                
                if (!empty($prod['category_id']) && isset($catPaths[$prod['category_id']])) {
                    $prod['type'] = $catPaths[$prod['category_id']];
                }

                if ($user_role === 'delivery') {
                    unset($prod['cost_price']); 
                }
            }
            send_response('success',['data' => $products]);
            break;
            
            
     
          case 'public_search_products':
            $term = sanitize_input($input['term'] ?? '');
            $page = max(1, intval($input['page'] ?? 1));
            
            // تحديد الحجم بـ 20 منتج فقط لتخفيف الضغط (15 كيلوبايت كحد أقصى للرد)
            $limit = 20; 
            $offset = ($page - 1) * $limit;
            
            $where =["l.is_available = 1", "p.approval_status = 'approved'", "p.isAvailable = 1", "(l.quantity > 0 OR l.quantity_type = 'unlimited')"];
            $params =[];

            if (!empty($term)) {
                $where[] = "MATCH(p.name, p.keywords, p.mainDescription) AGAINST(? IN BOOLEAN MODE)";
                $params[] = $term . '*';
            }

            $where_sql = implode(' AND ', $where);

            // استعلام ذكي وجزئي: لا نجلب الوصف الكامل لتخفيف حجم الـ JSON
            $sql = "
                SELECT 
                    p.id, p.name, SUBSTRING(p.mainDescription, 1, 100) as mainDescription, p.image, p.sizes, p.discount, p.department, c.name as type,
                    l.id as listing_id, l.merchant_price as price, l.quantity, l.quantity_type,
                    u.id as merchant_id, COALESCE(u.store_name, u.username) as merchant_name
                FROM merchant_listings l
                JOIN products p ON l.global_product_id = p.id
                JOIN users u ON l.merchant_id = u.id
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE $where_sql
                ORDER BY l.updated_at DESC
                LIMIT $limit OFFSET $offset
            ";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($products as &$prod) { 
                $options_data = json_decode($prod['sizes'] ?? '[]', true); 
                $prod['options'] = is_array($options_data) ? $options_data : []; 
                unset($prod['sizes']); 
            }
            unset($prod);
            
            send_response('success', ['data' => $products]);
            break;

        case 'get_product':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $sql = "SELECT p.*, c.name as type FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ?"; 
            $params =[sanitize_input($input['id'])];
            if ($user_role === 'merchant' || $user_role === 'delivery') { $sql .= " AND p.user_id = ?"; $params[] = $user_id; }
            $stmt = $pdo->prepare($sql); $stmt->execute($params); $prod = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($prod) {
                $catPaths = get_full_category_paths($pdo);
                if (!empty($prod['category_id']) && isset($catPaths[$prod['category_id']])) {
                    $prod['type'] = $catPaths[$prod['category_id']];
                }

                if ($user_role === 'delivery') unset($prod['cost_price']);
                
                $options_data = json_decode($prod['sizes'] ?? '[]', true); if (is_array($options_data)) { foreach($options_data as &$opt) { if (isset($opt['size_name']) && !isset($opt['name'])) { $opt['name'] = $opt['size_name']; unset($opt['size_name']); } } }
                $prod['options'] = $options_data; unset($prod['sizes']);
                send_response('success',['data' => $prod]);
            }
            throw new Exception('المنتج غير موجود.');
            break;

        case 'delete_product':
            if (!$user_id) send_response('error', ['message' => 'غير مصرح'], 401);
            $product_id = sanitize_input($input['id']);
            // جلب بيانات المنتج
            $stmt = $pdo->prepare("SELECT p.delete_url, l.id as listing_id, l.merchant_id, u.username FROM products p JOIN merchant_listings l ON p.id = l.global_product_id JOIN users u ON l.merchant_id = u.id WHERE p.id = ?");
            $stmt->execute([$product_id]);
            $prod_info = $stmt->fetch(PDO::FETCH_ASSOC);

            // 🛑 الجدار الأمني للحذف
            if ($user_role === 'merchant' && $prod_info['merchant_id'] != $user_id) {
                error_log("🚨 محاولة اختراق: التاجر ID $user_id حاول حذف المنتج $product_id الذي لا يملكه!");
                throw new Exception('مرفوض: لا تملك صلاحية حذف هذا المنتج.');
            }
            // 1. جلب رابط الحذف ومعرف العرض والتاجر
            $stmt = $pdo->prepare("SELECT p.delete_url, l.id as listing_id, l.merchant_id, u.username FROM products p JOIN merchant_listings l ON p.id = l.global_product_id JOIN users u ON l.merchant_id = u.id WHERE p.id = ?");
            $stmt->execute([$product_id]);
            $prod_info = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$prod_info) throw new Exception('المنتج غير موجود.');
            
            if ($user_role === 'merchant' && $prod_info['merchant_id'] != $user_id) {
                throw new Exception('لا تملك صلاحية الحذف.');
            }

            // 2. حذف الصورة من ImgBB نهائياً لتوفير المساحة
            if (!empty($prod_info['delete_url'])) {
                $ch = curl_init($prod_info['delete_url']);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_exec($ch);
                curl_close($ch);
            }

            // 3. الحذف من قاعدة البيانات
            $pdo->beginTransaction();
            try {
                $pdo->prepare("DELETE FROM merchant_listings WHERE global_product_id = ?")->execute([$product_id]);
                $pdo->prepare("DELETE FROM products WHERE id = ?")->execute([$product_id]);
                $pdo->commit();
            } catch (Exception $e) {
                $pdo->rollBack();
                throw new Exception('فشل الحذف من قاعدة البيانات.');
            }

            // 4. الحذف من Firebase (تحديث ذري للحذف)
            if ($prod_info['listing_id']) {
                $listing_id = $prod_info['listing_id'];
                $merchant_username = $prod_info['username'];
                deleteFirebaseNode("global/products/" . $listing_id);
                deleteFirebaseNode("stores/" . $merchant_username . "/products/" . $listing_id);
            }

            send_response('success', ['message' => 'تم حذف المنتج والصورة نهائياً.']);
            break;

        case 'toggle_availability':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $pid = sanitize_input($input['id']);
            $req_status = (int)$input['isAvailable'];
            
            if ($user_role === 'merchant' || $user_role === 'delivery') { 
                $stmt_check = $pdo->prepare("SELECT p.approval_status FROM products p JOIN merchant_listings l ON p.id = l.global_product_id WHERE p.id = ? AND l.merchant_id = ?");
                $stmt_check->execute([$pid, $user_id]);
                $prod_info = $stmt_check->fetch(PDO::FETCH_ASSOC);
                
                if (!$prod_info) throw new Exception("لا تملك صلاحية تعديل هذا المنتج.");

                
                $stmt = $pdo->prepare("UPDATE merchant_listings SET is_available = ? WHERE global_product_id = ? AND merchant_id = ?");
                $stmt->execute([$req_status, $pid, $user_id]);
            }
            
            if($user_role === 'admin') {
                $stmt_check = $pdo->prepare("SELECT approval_status FROM products WHERE id = ?");
                $stmt_check->execute([$pid]);
                $prod_info = $stmt_check->fetch(PDO::FETCH_ASSOC);
                
                $extra_sql = "";
                $params =[$req_status];
                if ($req_status === 1 && $prod_info['approval_status'] !== 'approved') {
                    $extra_sql = ", approval_status = 'approved'";
                }
                $params[] = $pid;
                $sql = "UPDATE products SET isAvailable = ? $extra_sql WHERE id = ?";
                $stmt = $pdo->prepare($sql); 
                $stmt->execute($params);
            }
            
            if (isset($stmt) && $stmt->rowCount() > 0) {
                // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
if ($user_role === 'merchant') { // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null); }
                send_response('success',['message' => 'تم تحديث حالة المنتج']);
            }
            throw new Exception('فشل تحديث الحالة أو لم يحدث تغيير.');
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
            
            // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
if ($user_role === 'merchant') { // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null); }
            send_response('success',['message' => 'تم تحديث حالة مراجعة المنتج بنجاح.']);
            break;

        case 'add_quantity':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $pid = sanitize_input($input['productId']);
            $qty = (int)$input['quantity'];
            
            if (!in_array($user_role, ['merchant', 'admin'])) throw new Exception("غير مصرح لك.");

            $sql = "UPDATE merchant_listings SET quantity = quantity + ? WHERE global_product_id = ? AND merchant_id = ?";
            $params = [$qty, $pid, $user_id];
            
            if ($user_role === 'admin' && isset($input['merchant_id'])) {
                $params[2] = sanitize_input($input['merchant_id']);
            }
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

            if($stmt->rowCount() > 0) {
                 // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
if ($user_role === 'merchant') { // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null); }
                send_response('success',['message' => 'تمت إضافة المخزون']);
            } else {
                throw new Exception('فشل تحديث المخزون. تأكد من أنك تملك هذا المنتج.');
            }
            break;

        case 'process_sale':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $pid = sanitize_input($input['productId']); $size_id = sanitize_input($input['sizeId'] ?? null); $qty_to_sell = (int)$input['quantity'];
            try {
                $pdo->beginTransaction();
                $sql_listing = "SELECT l.*, p.name as product_name, p.discount FROM merchant_listings l JOIN products p ON l.global_product_id = p.id WHERE l.global_product_id = ? AND l.merchant_id = ? FOR UPDATE";
                $stmt_listing = $pdo->prepare($sql_listing); $stmt_listing->execute([$pid, $user_id]); $listing = $stmt_listing->fetch(PDO::FETCH_ASSOC);
                
                if (!$listing) throw new Exception("المنتج غير موجود أو لا تملكه.");

                if ($listing['quantity_type'] === 'tracked') {
                    if ($listing['quantity'] < $qty_to_sell) throw new Exception("الكمية الإجمالية غير متوفرة.");
                    
                    $pdo->prepare("UPDATE merchant_listings SET quantity = quantity - ? WHERE id = ?")->execute([$qty_to_sell, $listing['id']]);
                }
                $price = $listing['merchant_price'] * (1 - ($listing['discount']/100)); $total = $price * $qty_to_sell; $cost = $listing['cost_price'] * $qty_to_sell; 
                
                $sid = 'SALE-' . generate_uuid();
                $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, cost_at_sale) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sale', ?)")->execute([$sid, $user_id, $pid, $size_id, $qty_to_sell, $price, $total, $listing['currency'], $cost]);
                $pdo->commit();
                // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
// بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);

                $remaining_qty_stmt = $pdo->prepare("SELECT quantity FROM merchant_listings WHERE id = ?"); $remaining_qty_stmt->execute([$listing['id']]);
                send_response('success',['message' => 'تمت العملية', 'saleId' => $sid, 'quantityLeft' => $remaining_qty_stmt->fetchColumn()]);
            } catch (Exception $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;
            
        case 'process_return':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $saleId = sanitize_input($input['saleId']); $qty = (int)$input['quantity'];
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT * FROM sales_log WHERE id = ? AND type = 'sale' FOR UPDATE"); $stmt->execute([$saleId]); $orig_sale = $stmt->fetch(PDO::FETCH_ASSOC); if(!$orig_sale) throw new Exception('الفاتورة الأصلية غير موجودة');
                
                if ($user_role === 'merchant' || $user_role === 'delivery') {
                    if ($orig_sale['user_id'] != $user_id) throw new Exception("لا تملك صلاحية إرجاع هذه الفاتورة.");
                }

                $returned_qty_stmt = $pdo->prepare("SELECT SUM(quantity) FROM sales_log WHERE original_sale_id = ?"); $returned_qty_stmt->execute([$saleId]); $returned_qty = $returned_qty_stmt->fetchColumn() ?: 0;
                if (($returned_qty + $qty) > $orig_sale['quantity']) throw new Exception('كمية المرتجع أكبر من المسموح به.');
                
                $pdo->prepare("UPDATE merchant_listings SET quantity = quantity + ? WHERE global_product_id = ? AND merchant_id = ?")->execute([$qty, $orig_sale['product_id'], $orig_sale['user_id']]);
                
                $return_id = 'RET-' . generate_uuid(); 
                $total_refund = $orig_sale['price_per_item'] * $qty;
                $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, original_sale_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'return', ?)")->execute([$return_id, $user_id, $orig_sale['product_id'], $orig_sale['size_id'], $qty, $orig_sale['price_per_item'], $total_refund, $orig_sale['currency'], $saleId]);
                $pdo->commit(); 
                // بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
// أضف هذا السطر أسفلها:
// بدلاً من بناء الكاش الذي يدمر السيرفر، نضع إشارة فقط
flag_cache_for_rebuild($user_id ?? null);
                send_response('success',['message' => 'تم تسجيل المرتجع']);
            } catch (Exception $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;

        case 'get_invoice_details':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $sql = "SELECT s.id, s.quantity, s.price_per_item, s.total_price, s.currency, s.type, s.timestamp, s.size_id, p.name as productName, p.sizes FROM sales_log s JOIN products p ON s.product_id = p.id WHERE s.id = ?";
            $params =[sanitize_input($input['id'])];
            if ($user_role === 'merchant' || $user_role === 'delivery') { $sql .= " AND s.user_id = ?"; $params[] = $user_id; }
            $stmt = $pdo->prepare($sql); $stmt->execute($params); $sale = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($sale) {
                if ($sale['size_id'] && $sale['sizes']) { $options = json_decode($sale['sizes'], true); if(is_array($options)) { foreach($options as $option) { if (isset($option['id']) && $option['id'] === $sale['size_id']) { $sale['size_name'] = $option['name'] ?? ($option['size_name'] ?? ''); break; } } } }
                unset($sale['sizes']);
                $settings = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'store_settings'")->fetchColumn();
                $storeName = json_decode($settings, true)['storeName'] ?? 'المتجر';
                send_response('success',['data' =>['sale' => $sale, 'storeName' => $storeName]]);
            }
            throw new Exception("الفاتورة غير موجودة");
            break;
            
        case 'get_returnable_sales':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            $term = sanitize_input($input['term'] ?? '');
            $sql = "SELECT s.id, s.timestamp, p.name as productName, s.size_id, p.sizes, (s.quantity - IFNULL((SELECT SUM(quantity) FROM sales_log WHERE original_sale_id = s.id AND type = 'return'), 0)) as returnable_qty FROM sales_log s JOIN products p ON s.product_id = p.id WHERE s.type = 'sale' AND (s.quantity - IFNULL((SELECT SUM(quantity) FROM sales_log WHERE original_sale_id = s.id AND type = 'return'), 0)) > 0";
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
            foreach($sales as &$sale) { if ($sale['size_id'] && $sale['sizes']) { $options = json_decode($sale['sizes'], true); if (is_array($options)) { foreach($options as $option) { if (isset($option['id']) && $option['id'] === $sale['size_id']) { $sale['size_name'] = $option['name'] ?? ($option['size_name'] ?? ''); break; } } } } unset($sale['sizes']); }
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
            // ... (بقية كود هذه الحالة) ...
            if ($stmt->rowCount() > 0) { send_response('success', array_merge(['message' => $message], $extra_data)); } 
            else { throw new Exception('لم يتم العثور على الطلب أو حالته لا تسمح بهذا الإجراء.'); }
            break;
            
      case 'merchant_update_order_status':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح.");
            $order_id = sanitize_input($input['order_id']);
            $new_status = sanitize_input($input['status']);
            
            $sql = "UPDATE live_tickets SET status = ? WHERE ticket_id = ? AND merchant_id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$new_status, $order_id, $user_id]);
            
            if ($stmt->rowCount() > 0) send_response('success',['message' => 'تم تحديث حالة الطلب بنجاح.']);
            else throw new Exception("فشل تحديث الحالة.");
            break;
            
        case 'merchant_approve_order':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح.");
            $order_id = sanitize_input($input['order_id']); 
            
            $sql = "UPDATE live_tickets SET status = 'confirmed_by_store' WHERE ticket_id = ? AND merchant_id = ?";
            $stmt = $pdo->prepare($sql); 
            $stmt->execute([$order_id, $user_id]);
            @file_put_contents(__DIR__ . '/../last_update.txt', time());
            if ($stmt->rowCount() > 0) send_response('success',['message' => 'تمت الموافقة وتجهيز الطلب بنجاح.']);
            else throw new Exception("فشل تحديث الحالة.");
            break;

        case 'merchant_confirm_delivery_code':
            if ($user_role !== 'merchant') throw new Exception("غير مصرح لك.");
            $ticket_id = sanitize_input($input['order_id']); // المتغير القادم من الواجهة اسمه order_id لكنه يمثل ticket_id
            $code = sanitize_input($input['code']);
            
            if(!$code || strlen($code) !== 4) throw new Exception("يرجى إدخال الكود المكون من 4 أرقام.");

            try {
                // نبدأ معاملة (Transaction) لضمان عدم حدوث أي خطأ في الحسابات
                $pdo->beginTransaction();
                
                // 1. جلب التذكرة وقفلها برمجياً حتى تنتهي العملية
                $stmt = $pdo->prepare("SELECT delivery_code, status, ticket_data, customer_id FROM live_tickets WHERE ticket_id = ? AND merchant_id = ? FOR UPDATE"); 
                $stmt->execute([$ticket_id, $user_id]); 
                $ticket = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$ticket) throw new Exception("الطلب غير موجود أو تم تسليمه مسبقاً.");
                if ($ticket['status'] !== 'out_for_delivery') throw new Exception("يجب أن يكون الطلب في حالة 'خرج للتوصيل' أولاً.");
                if ($ticket['delivery_code'] != $code) throw new Exception("كود التسليم غير صحيح. يرجى المراجعة مع العميل.");
                
                // 2. استخراج بيانات المنتجات من الـ JSON المخزن
                $ticket_data = json_decode($ticket['ticket_data'], true);
                $items = $ticket_data['items'] ?? [];
                $currency = $ticket_data['financials']['currency'] ?? 'YER';
                $grand_total = $ticket_data['financials']['grand_total'] ?? 0;

                // 3. تسجيل المبيعات وحساب الأرباح في جدول sales_log
                foreach ($items as $item) {
                    $sid = 'SALE-' . generate_uuid(); 
                    $total_price = $item['price'] * $item['quantity']; 
                    $cost_at_sale = $item['cost_price'] * $item['quantity'];
                    
                    $log_stmt = $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, cost_at_sale, order_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sale', ?, ?)");
                    $log_stmt->execute([
                        $sid, 
                        $user_id, 
                        $item['product_id'], 
                        $item['size_id'], 
                        $item['quantity'], 
                        $item['price'], 
                        $total_price, 
                        $currency, 
                        $cost_at_sale, 
                        $ticket_id // نستخدم معرف التذكرة كمرجع للطلب
                    ]);
                }
                
                // 4. أرشفة الطلب نهائياً
                $archive_stmt = $pdo->prepare("INSERT INTO orders_archive (ticket_id, customer_id, merchant_id, final_status, total_amount, archived_data) VALUES (?, ?, ?, 'completed', ?, ?)");
                $archive_stmt->execute([
                    $ticket_id,
                    $ticket['customer_id'],
                    $user_id,
                    $grand_total,
                    json_encode($ticket_data, JSON_UNESCAPED_UNICODE)
                ]);

                // 5. تدمير تذكرة الظل من الجدول الحي (تخفيف الضغط)
                $pdo->prepare("DELETE FROM live_tickets WHERE ticket_id = ?")->execute([$ticket_id]);
                
                // اعتماد جميع العمليات
                $pdo->commit();
                
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
            $sql = "SELECT id, user_id, expense_date, category, description, amount, currency, created_at FROM expenses ORDER BY expense_date DESC"; $stmt = $pdo->prepare($sql); $stmt->execute();
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
            $pdo->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([$hashed, $user_id]);
            
            $current_device_token = $_COOKIE['device_token'] ?? '';
            $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ? AND device_token != ?")->execute([$user_id, $current_device_token]);

            send_response('success',['message' => 'تم تحديث كلمة المرور بنجاح. تم تسجيل الخروج من الأجهزة الأخرى.']);
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
            $sql = "SELECT u.id, u.username, u.store_name, u.phone, u.created_at, u.is_active, u.settings, (SELECT COUNT(*) FROM products WHERE products.user_id = u.id) as product_count FROM users u WHERE u.role IN ('merchant', 'delivery') ORDER BY u.created_at DESC";
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
                $pdo->prepare("UPDATE products SET user_id = NULL WHERE user_id = ?")->execute([$merchant_id]);
                $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?")->execute([$merchant_id]);
                $pdo->prepare("DELETE FROM users WHERE id = ? AND role != 'admin'")->execute([$merchant_id]);
                $pdo->commit(); send_response('success',['message' => 'تم حذف المستخدم وإلغاء ربط منتجاته']);
            } catch (Exception $e) { if($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;

        case 'get_merchant_settings':
            if ($user_role !== 'merchant') throw new Exception("للتاجر فقط");
            $stmt = $pdo->prepare("SELECT store_name, settings, store_type FROM users WHERE id = ?"); 
            $stmt->execute([$user_id]); 
            $data = $stmt->fetch(PDO::FETCH_ASSOC);
            $data['settings'] = json_decode($data['settings'] ?? '{}', true); 
            send_response('success',['data' => $data]);
            break;

        case 'save_merchant_settings':
            if ($user_role !== 'merchant') throw new Exception("للتاجر فقط");
            
            $storeName = sanitize_input($input['storeName'] ?? ''); 
            $storeType = sanitize_input($input['storeType'] ?? null);
            $phone = sanitize_input($input['social']['phone'] ?? ''); 
            $location_url = sanitize_input($input['settings']['location'] ?? null);

            if (!empty($location_url) && !is_valid_gps_location($location_url)) {
                 throw new Exception("رابط الموقع الجغرافي غير صالح أو خارج النطاق المسموح.");
            }
            
            $settings_array = ['phone' => $phone, 'location' => $location_url];
            $settings_json = json_encode($settings_array, JSON_UNESCAPED_UNICODE);

            $pdo->prepare("UPDATE users SET store_name = ?, settings = ?, store_type = ? WHERE id = ?")->execute([$storeName, $settings_json, $storeType, $user_id]);
            $_SESSION['store_name'] = $storeName;
            send_response('success',['message' => 'تم حفظ الإعدادات بنجاح']);
            break;

        case 'get_categories':
            $cats = $pdo->query("SELECT name FROM categories WHERE parent_id IS NULL OR parent_id = 0 ORDER BY name ASC")->fetchAll(PDO::FETCH_COLUMN);
            $defaults =['إلكترونيات', 'أزياء', 'منزل'];
            send_response('success',['data' => array_values(array_unique(array_merge($defaults, $cats)))]);
            break;
            
        case 'get_departments':
            $cat_id = sanitize_input($input['category_id'] ?? '');
            if (empty($cat_id)) {
                $cat_name = sanitize_input($input['category'] ?? '');
                $stmt_cat = $pdo->prepare("SELECT id FROM categories WHERE name = ? LIMIT 1");
                $stmt_cat->execute([$cat_name]);
                $cat_id = $stmt_cat->fetchColumn();
            }
            
            $depts =[];
            if ($cat_id) {
                $stmt = $pdo->prepare("SELECT name FROM categories WHERE parent_id = ? ORDER BY name ASC");
                $stmt->execute([$cat_id]);
                $depts = $stmt->fetchAll(PDO::FETCH_COLUMN);
            }
            send_response('success',['data' => $depts]);
            break;
            
        case 'get_categories_tree':
            if (!$user_id) send_response('error',['message' => 'غير مصرح'], 401);
            
            $sql = "SELECT id, name, parent_id FROM categories";
            $params =[];
            
            if ($user_role !== 'admin') { 
                $sql .= " WHERE user_id = ?";
                $params[] = $user_id;
            }
            $sql .= " ORDER BY parent_id ASC, name ASC";
            
            try {
                $stmt = $pdo->prepare($sql); 
                $stmt->execute($params); 
                $flat_categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                $tree =[];
                $mapped =[];
                
                foreach ($flat_categories as &$cat) {
                    $cat['children'] =[];
                    $mapped[$cat['id']] = &$cat;
                }
                unset($cat);
                
                foreach ($flat_categories as &$cat) {
                    $parent_id = $cat['parent_id'];
                    if (empty($parent_id) || $parent_id == 0) {
                        $tree[] = &$cat;
                    } else {
                        if (isset($mapped[$parent_id])) {
                            $mapped[$parent_id]['children'][] = &$cat;
                        } else {
                            $tree[] = &$cat;
                        }
                    }
                }
                unset($cat);
                
                send_response('success',['data' => $tree]);
            } catch (PDOException $e) {
                if (strpos($e->getMessage(), 'Base table or view not found') !== false) {
                    send_response('success',['data' => []]);
                } else {
                    throw $e;
                }
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
            $daily_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
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
            
            // قراءة الطلبات المتاحة من جدول التذاكر
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
                $orders[] = [
                    'id' => $t['id'],
                    'total_amount' => $data['financials']['grand_total'],
                    'currency' => $data['financials']['currency'],
                    'delivery_fee' => $data['financials']['delivery_fee'],
                    'status' => $t['status'],
                    'created_at' => $t['created_at'],
                    'customer_name' => $data['customer']['name'],
                    'merchant_name' => $data['merchant']['name']
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
                $orders[] = [
                    'id' => $t['id'],
                    'total_amount' => $data['financials']['grand_total'],
                    'currency' => $data['financials']['currency'],
                    'delivery_fee' => $data['financials']['delivery_fee'],
                    'delivery_address_text' => $data['customer']['address_text'],
                    'delivery_gps_link' => $data['customer']['gps_link'],
                    'status' => $t['status'],
                    'created_at' => $t['created_at'],
                    'customer_name' => $data['customer']['name'],
                    'customer_phone' => $data['customer']['phone'],
                    'merchant_name' => $data['merchant']['name'],
                    'items' => $data['items'] // تفاصيل المنتجات داخل JSON
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
            if ((int)$active_orders_stmt->fetchColumn() >= DELIVERY_AGENT_MAX_ORDERS) throw new Exception("لا يمكنك قبول طلبات جديدة. لديك طلبات غير مكتملة.");
            
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
                
                // إضافة بيانات المندوب لداخل الـ JSON
                $data = json_decode($ticket['ticket_data'], true);
                $data['delivery_agent'] = [
                    'id' => $user_id,
                    'name' => $_SESSION['store_name'] ?? $_SESSION['username']
                ];
                $new_json = json_encode($data, JSON_UNESCAPED_UNICODE);

                // التحديث السريع
                $update_stmt = $pdo->prepare("UPDATE live_tickets SET delivery_agent_id = ?, status = 'accepted_by_delivery', ticket_data = ? WHERE ticket_id = ?");
                $update_stmt->execute([$user_id, $new_json, $order_id]);
                
                $pdo->commit();
                send_response('success',['message' => 'تم قبول الطلب بنجاح! أصبح الآن في قائمة طلباتك.']);
            } catch (Exception $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
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
            
            if ($stmt->rowCount() > 0) send_response('success',['message' => 'تم تحديث حالة الطلب.']);
            else throw new Exception("فشل تحديث الحالة. قد لا تملك هذا الطلب.");
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
                        $prod_stmt = $pdo->prepare("SELECT sizes, quantity_type FROM products WHERE id = ? FOR UPDATE");
                        $prod_stmt->execute([$item['product_id']]);
                        $prod = $prod_stmt->fetch(PDO::FETCH_ASSOC);

                        if ($prod && $prod['quantity_type'] === 'tracked') {
                            if ($item['size_id'] && $prod['sizes']) {
                                $options = json_decode($prod['sizes'], true);
                                if (is_array($options)) {
                                    foreach ($options as &$option) {
                                        if (isset($option['id']) && $option['id'] === $item['size_id']) {
                                            $option['quantity'] += $item['quantity'];
                                            break;
                                        }
                                    }
                                }
                                $new_options_json = json_encode($options, JSON_UNESCAPED_UNICODE);
                                $pdo->prepare("UPDATE products SET quantity = quantity + ?, sizes = ? WHERE id = ?")
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
            } catch(Exception $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;
            
        case 'confirm_delivery_with_code':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $order_id = sanitize_input($input['order_id']); $code = sanitize_input($input['code']);
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT delivery_code, status, delivery_fee FROM orders WHERE id = ? AND delivery_agent_id = ? FOR UPDATE"); 
                $stmt->execute([$order_id, $user_id]); $order = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$order) throw new Exception("الطلب غير موجود أو لا تملكه.");
                if ($order['status'] !== 'out_for_delivery') throw new Exception("يجب أن يكون الطلب في حالة 'خرج للتوصيل' أولاً.");
                if ($order['delivery_code'] != $code) throw new Exception("كود التسليم غير صحيح. يرجى المراجعة مع العميل.");
                $pdo->prepare("UPDATE orders SET status = 'completed' WHERE id = ?")->execute([$order_id]);
                
                $items_stmt = $pdo->prepare("SELECT oi.*, p.cost_price FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?");
                $items_stmt->execute([$order_id]);
                foreach ($items_stmt->fetchAll(PDO::FETCH_ASSOC) as $item) {
                    $sid = 'SALE-' . generate_uuid(); $total = $item['price'] * $item['quantity']; $cost = $item['cost_price'] * $item['quantity'];
                    
                    $log_stmt = $pdo->prepare("INSERT INTO sales_log (id, user_id, product_id, size_id, quantity, price_per_item, total_price, currency, type, cost_at_sale, order_id) VALUES (?, ?, ?, ?, ?, ?, ?, (SELECT currency FROM orders WHERE id = ?), 'sale', ?, ?)");
                    $log_stmt->execute([$sid, $item['user_id'], $item['product_id'], $item['size_id'], $item['quantity'], $item['price'], $total, $order_id, $cost, $order_id]);
                }
                
                $pdo->commit();
                send_response('success',['message' => 'تم تأكيد التسليم بنجاح!']);
            } catch (Exception $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
            break;
            
        case 'update_agent_location':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $lat = filter_var($input['lat'], FILTER_VALIDATE_FLOAT); $lng = filter_var($input['lng'], FILTER_VALIDATE_FLOAT);
            if ($lat === false || $lng === false) throw new Exception("إحداثيات غير صالحة.");
            $location_json = json_encode(['lat' => $lat, 'lng' => $lng]);
            try { $pdo->exec("ALTER TABLE users ADD COLUMN last_active_at DATETIME NULL AFTER last_location"); } catch (Exception $e) {}
            $stmt = $pdo->prepare("UPDATE users SET last_location = ?, last_active_at = NOW() WHERE id = ?"); $stmt->execute([$location_json, $user_id]);
            send_response('success',['message' => 'تم تحديث الموقع']);
            break;

        case 'get_agents_locations':
            if ($user_role !== 'delivery') throw new Exception("غير مصرح لك.");
            $stmt = $pdo->prepare("SELECT id, store_name, last_location, last_active_at FROM users WHERE role = 'delivery' AND is_active = 1 AND id != ? AND last_location IS NOT NULL"); $stmt->execute([$user_id]); $agents = $stmt->fetchAll(PDO::FETCH_ASSOC);
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
    // قمنا بتفعيل إظهار الخطأ الحقيقي بدلاً من الرسالة العامة
    send_response('error',['message' => 'DB Error: ' . $e->getMessage()], 500);
} catch (Exception $e) {
    $msg = $e->getMessage();
    if (strpos($msg, 'SQLSTATE') !== false || strpos($msg, 'PDO') !== false || strpos($msg, '/') !== false || strpos($msg, '\\') !== false || strpos($msg, 'on line') !== false) {
        error_log("System Error in API: " . $msg);
        $msg = 'حدث خطأ غير متوقع. يرجى المحاولة لاحقاً.';
        $code = 500;
    } else {
        $code = (strpos($msg, 'تغيرت الجلسة') !== false || strpos($msg, 'غير مصرح') !== false || strpos($msg, 'يجب تسجيل الدخول') !== false) ? 401 : 400;
    }
    
    // إذا كان الخطأ متعلقاً بضرورة تحديث الملف الشخصي نرسله كود 403 ليتم التعامل معه بالفرونت اند
    if (strpos($msg, 'REQUIRE_PROFILE_UPDATE:') !== false) {
        $code = 403;
        $msg = str_replace('REQUIRE_PROFILE_UPDATE:', '', $msg);
    }
    
    send_response('error',['message' => trim($msg)], $code);
}
?>
