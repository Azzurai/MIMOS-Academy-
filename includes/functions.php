<?php
/**
 * MIMOS Academy — Utility Functions
 * ===================================
 * Shared security and helper functions.
 */

require_once __DIR__ . '/db.php';

/**
 * Sanitize user input — strips tags, trims whitespace
 */
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $data;
}

/**
 * Validate email format
 */
function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate password strength
 * Min 8 chars, at least 1 uppercase, 1 lowercase, 1 number
 */
function isStrongPassword($password) {
    if (strlen($password) < 8) return false;
    if (!preg_match('/[A-Z]/', $password)) return false;
    if (!preg_match('/[a-z]/', $password)) return false;
    if (!preg_match('/[0-9]/', $password)) return false;
    return true;
}

/**
 * Generate a cryptographically secure random token
 */
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

/**
 * Hash a password securely using bcrypt
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Verify a password against a hash
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Get client IP address (handles proxies)
 */
function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            // X-Forwarded-For can contain multiple IPs, take the first
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

/**
 * Check rate limiting for login attempts
 * Returns true if the user is rate-limited (should be blocked)
 */
function isRateLimited($email = null) {
    $pdo = getDBConnection();
    $ip = getClientIP();
    $window = date('Y-m-d H:i:s', time() - RATE_LIMIT_WINDOW);

    // Check by IP
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) as attempts FROM login_attempts 
         WHERE ip_address = :ip AND attempted_at > :window AND success = 0"
    );
    $stmt->execute([':ip' => $ip, ':window' => $window]);
    $result = $stmt->fetch();

    if ($result['attempts'] >= RATE_LIMIT_ATTEMPTS) {
        return true;
    }

    // Also check by email if provided
    if ($email) {
        $stmt = $pdo->prepare(
            "SELECT COUNT(*) as attempts FROM login_attempts 
             WHERE email = :email AND attempted_at > :window AND success = 0"
        );
        $stmt->execute([':email' => $email, ':window' => $window]);
        $result = $stmt->fetch();

        if ($result['attempts'] >= RATE_LIMIT_ATTEMPTS) {
            return true;
        }
    }

    return false;
}

/**
 * Record a login attempt (for rate limiting)
 */
function recordLoginAttempt($email, $success = false) {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        "INSERT INTO login_attempts (ip_address, email, success) VALUES (:ip, :email, :success)"
    );
    $stmt->execute([
        ':ip'      => getClientIP(),
        ':email'   => $email,
        ':success' => $success ? 1 : 0,
    ]);
}

/**
 * Send a JSON response and exit
 */
function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    // Security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    echo json_encode($data);
    exit;
}

/**
 * Require POST method — reject GET and other methods
 */
function requirePOST() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonResponse(['success' => false, 'message' => 'Method not allowed.'], 405);
    }
}

/**
 * Clean up expired login attempts (call periodically)
 */
function cleanupLoginAttempts() {
    $pdo = getDBConnection();
    $cutoff = date('Y-m-d H:i:s', time() - (RATE_LIMIT_WINDOW * 2));
    $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE attempted_at < :cutoff");
    $stmt->execute([':cutoff' => $cutoff]);
}
