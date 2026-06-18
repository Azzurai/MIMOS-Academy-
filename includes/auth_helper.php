<?php
/**
 * MIMOS Academy — Consolidated Auth Helper
 * ========================================
 * Combines secure sessions, database connectivity, and general utilities.
 */

require_once __DIR__ . '/../config.php';

// --- Security Headers ---
function sendSecurityHeaders() {
    if (headers_sent()) return;
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://www.gstatic.com https://accounts.google.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://challenges.cloudflare.com; font-src 'self' data: https://fonts.gstatic.com; frame-src 'self' https://accounts.google.com https://challenges.cloudflare.com; connect-src 'self' https://accounts.google.com https://challenges.cloudflare.com; img-src 'self' data: https:;");
}

// --- Session Security Settings & Initialization ---
function initSession() {
    sendSecurityHeaders();
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', SESSION_LIFETIME);

    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        ini_set('session.cookie_secure', 1);
    }

    session_name(SESSION_NAME);
    session_start();

    // Regenerate session ID periodically (every 30 minutes)
    if (!isset($_SESSION['_created'])) {
        $_SESSION['_created'] = time();
    } elseif (time() - $_SESSION['_created'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['_created'] = time();
    }

    // Check session lifetime
    if (isset($_SESSION['_last_activity']) && (time() - $_SESSION['_last_activity'] > SESSION_LIFETIME)) {
        session_unset();
        session_destroy();
        session_start();
    }
    $_SESSION['_last_activity'] = time();
}

// Automatically start session
initSession();

// --- CSRF Handling ---
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function regenerateCSRFToken() {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}

// --- Session Getters ---
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }
    return [
        'id'        => $_SESSION['user_id'],
        'name'      => $_SESSION['user_name'] ?? '',
        'email'     => $_SESSION['user_email'] ?? '',
        'avatar'    => $_SESSION['user_avatar'] ?? '',
    ];
}

// --- Database connection ---
function getDBConnection() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
            ];
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log('Database connection failed: ' . $e->getMessage());
            jsonResponse(['success' => false, 'message' => 'A server error occurred. Please try again later.'], 500);
        }
    }
    return $pdo;
}

// --- General Utility Functions ---
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function isStrongPassword($password) {
    if (strlen($password) < 8) return false;
    if (!preg_match('/[A-Z]/', $password)) return false;
    if (!preg_match('/[a-z]/', $password)) return false;
    if (!preg_match('/[0-9]/', $password)) return false;
    return true;
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

// --- Rate Limiting ---
function isRateLimited($email = null) {
    $pdo = getDBConnection();
    $ip = getClientIP();
    $window = date('Y-m-d H:i:s', time() - RATE_LIMIT_WINDOW);

    // IP Check
    $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM mimos_login_attempts WHERE ip_address = :ip AND attempted_at > :window AND success = 0");
    $stmt->execute([':ip' => $ip, ':window' => $window]);
    $result = $stmt->fetch();
    if ($result['attempts'] >= RATE_LIMIT_ATTEMPTS) {
        return true;
    }

    // Email Check
    if ($email) {
        $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM mimos_login_attempts WHERE email = :email AND attempted_at > :window AND success = 0");
        $stmt->execute([':email' => $email, ':window' => $window]);
        $result = $stmt->fetch();
        if ($result['attempts'] >= RATE_LIMIT_ATTEMPTS) {
            return true;
        }
    }
    return false;
}

function recordLoginAttempt($email, $success = false) {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("INSERT INTO mimos_login_attempts (ip_address, email, success) VALUES (:ip, :email, :success)");
    $stmt->execute([
        ':ip'      => getClientIP(),
        ':email'   => $email,
        ':success' => $success ? 1 : 0,
    ]);
}

function cleanupLoginAttempts() {
    $pdo = getDBConnection();
    $cutoff = date('Y-m-d H:i:s', time() - (RATE_LIMIT_WINDOW * 2));
    $stmt = $pdo->prepare("DELETE FROM mimos_login_attempts WHERE attempted_at < :cutoff");
    $stmt->execute([':cutoff' => $cutoff]);
}

// --- Cloudflare Turnstile Verification ---
function verifyTurnstile($token) {
    if (!defined('TURNSTILE_SECRET_KEY') || empty(TURNSTILE_SECRET_KEY)) {
        return true; // Skip verification if not configured
    }
    if (empty($token)) {
        return false;
    }
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret' => TURNSTILE_SECRET_KEY,
        'response' => $token,
        'remoteip' => getClientIP()
    ]));
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    if ($response === false) {
        return false;
    }
    
    $data = json_decode($response, true);
    return !empty($data['success']);
}

// --- HTTP Response Helpers ---
function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    echo json_encode($data);
    exit;
}

function requirePOST() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonResponse(['success' => false, 'message' => 'Method not allowed.'], 405);
    }
}
