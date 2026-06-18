<?php
/**
 * MIMOS Academy — Reset Password Handler
 * ========================================
 * POST /auth/reset-password.php
 * Accepts: token, password, confirm_password, csrf_token
 * Returns: JSON
 */

require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/functions.php';

requirePOST();

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
$token           = trim($input['token'] ?? '');
$password        = $input['password'] ?? '';
$confirmPassword = $input['confirm_password'] ?? '';

if (empty($token)) {
    jsonResponse(['success' => false, 'message' => 'Invalid or missing reset token.'], 400);
}

if (empty($password) || empty($confirmPassword)) {
    jsonResponse(['success' => false, 'message' => 'Please enter and confirm your new password.'], 400);
}

if (!isStrongPassword($password)) {
    jsonResponse([
        'success' => false,
        'message' => 'Password must be at least 8 characters with 1 uppercase letter, 1 lowercase letter, and 1 number.'
    ], 400);
}

if ($password !== $confirmPassword) {
    jsonResponse(['success' => false, 'message' => 'Passwords do not match.'], 400);
}

// --- Validate Token ---
$pdo = getDBConnection();
$stmt = $pdo->prepare(
    "SELECT id, email FROM users WHERE reset_token = :token AND reset_token_expiry > NOW() AND is_active = 1 LIMIT 1"
);
$stmt->execute([':token' => $token]);
$user = $stmt->fetch();

if (!$user) {
    jsonResponse([
        'success' => false,
        'message' => 'This reset link is invalid or has expired. Please request a new one.',
    ], 400);
}

// --- Update Password ---
$passwordHash = hashPassword($password);

$stmt = $pdo->prepare(
    "UPDATE users SET password_hash = :password, reset_token = NULL, reset_token_expiry = NULL WHERE id = :id"
);
$stmt->execute([
    ':password' => $passwordHash,
    ':id'       => $user['id'],
]);

// Regenerate CSRF
regenerateCSRFToken();

jsonResponse([
    'success'  => true,
    'message'  => 'Password reset successfully! You can now log in with your new password.',
    'redirect' => 'login.html',
]);
