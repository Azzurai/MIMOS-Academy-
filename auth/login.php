<?php
/**
 * MIMOS Academy — Login Handler
 * ==============================
 * POST /auth/login.php
 * Accepts: email, password, csrf_token
 * Returns: JSON
 * 
 * Security:
 * - Rate limiting (5 attempts per 15 min per IP/email)
 * - Bcrypt password verification
 * - Session regeneration on success
 * - Timing-safe comparison
 * - Generic error messages (don't reveal if email exists)
 */

require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/functions.php';

// Only accept POST
requirePOST();

// Parse JSON body
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    $input = $_POST;
}

// --- CSRF Verification ---
$csrfToken = $input['csrf_token'] ?? '';
if (!verifyCSRFToken($csrfToken)) {
    jsonResponse(['success' => false, 'message' => 'Invalid security token. Please refresh the page.'], 403);
}

// --- Input Validation ---
$email    = strtolower(trim($input['email'] ?? ''));
$password = $input['password'] ?? '';

if (empty($email) || empty($password)) {
    jsonResponse(['success' => false, 'message' => 'Email and password are required.'], 400);
}

if (!isValidEmail($email)) {
    jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
}

// --- Rate Limiting ---
if (isRateLimited($email)) {
    jsonResponse([
        'success' => false,
        'message' => 'Too many login attempts. Please try again in 15 minutes.',
        'locked'  => true,
    ], 429);
}

// --- Verify Credentials ---
$pdo = getDBConnection();
$stmt = $pdo->prepare(
    "SELECT id, full_name, email, password_hash, avatar_url, is_active FROM users WHERE email = :email LIMIT 1"
);
$stmt->execute([':email' => $email]);
$user = $stmt->fetch();

// Use constant-time comparison + generic error to prevent user enumeration
if (!$user || !$user['password_hash'] || !verifyPassword($password, $user['password_hash'])) {
    // Record failed attempt
    recordLoginAttempt($email, false);

    // Use same error message whether email exists or not
    jsonResponse(['success' => false, 'message' => 'Invalid email or password.'], 401);
}

// --- Check if account is active ---
if (!$user['is_active']) {
    jsonResponse(['success' => false, 'message' => 'Your account has been deactivated. Contact support.'], 403);
}

// --- Login Success ---
recordLoginAttempt($email, true);

// Regenerate session ID to prevent session fixation
session_regenerate_id(true);

$_SESSION['user_id']     = $user['id'];
$_SESSION['user_name']   = $user['full_name'];
$_SESSION['user_email']  = $user['email'];
$_SESSION['user_avatar'] = $user['avatar_url'] ?? '';
$_SESSION['_created']    = time();

// Regenerate CSRF token
regenerateCSRFToken();

// Periodic cleanup of old login attempts
if (mt_rand(1, 10) === 1) {
    cleanupLoginAttempts();
}

jsonResponse([
    'success'  => true,
    'message'  => 'Login successful!',
    'redirect' => 'index.html',
    'user'     => [
        'name'   => $user['full_name'],
        'email'  => $user['email'],
        'avatar' => $user['avatar_url'] ?? '',
    ],
]);
