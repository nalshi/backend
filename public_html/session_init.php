<?php
// =================================================================
// ملف فحص جلسة العميل المصغر (Micro-Session Checker)
// سريع جداً، لا يستهلك المعالج، ونفس أمان لوحة التاجر 100%
// =================================================================

require_once __DIR__ . '/nalsh-user-admin-name.php';

header('Content-Type: application/json; charset=utf-8');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$response =['loggedIn' => false];

try {
    // 1. التحقق من الكوكي "تذكرني" إذا انتهت الجلسة (نفس نظام التاجر تماماً)
    if (empty($_SESSION['customer_id']) && isset($_COOKIE['remember_me_customer'])) {
        list($selector, $validator) = explode(':', $_COOKIE['remember_me_customer']);
        if ($selector && $validator) {
            $stmt = $pdo->prepare("SELECT * FROM auth_tokens WHERE selector = ? AND expires >= NOW()");
            $stmt->execute([$selector]);
            $token_data = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($token_data && hash_equals($token_data['hashed_validator'], hash('sha256', $validator))) {
                $stmt_cust = $pdo->prepare("SELECT id, full_name, phone, address, is_active FROM customers WHERE id = ?");
                $stmt_cust->execute([$token_data['user_id']]);
                $customer = $stmt_cust->fetch(PDO::FETCH_ASSOC);
                
                if ($customer && $customer['is_active']) {
                    // استعادة الجلسة بالكامل
                    $_SESSION['customer_id'] = $customer['id'];
                    $_SESSION['customer_name'] = $customer['full_name'];
                    $_SESSION['loggedin'] = true;
                }
            }
        }
    }

    // 2. إذا كان العميل مسجلاً بالفعل، أرسل بياناته للواجهة
    if (!empty($_SESSION['customer_id'])) {
        $stmt = $pdo->prepare("SELECT full_name, phone, address, is_verified FROM customers WHERE id = ? AND is_active = 1");
        $stmt->execute([$_SESSION['customer_id']]);
        $customer = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($customer) {
            $response['loggedIn'] = true;
            $response['customer'] = $customer;
            $response['needs_profile_update'] = (strpos($customer['full_name'], 'عميل') === 0);
            $response['requires_otp'] = false;
        } else {
            // تدمير الجلسة إذا تم حظر العميل
            session_destroy();
            setcookie('remember_me_customer', '', time() - 3600, '/');
        }
    }

    echo json_encode(['status' => 'success'] + $response, JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    echo json_encode(['status' => 'error', 'message' => 'حدث خطأ أثناء فحص الجلسة.']);
}
exit;
