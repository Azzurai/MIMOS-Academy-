<?php
/**
 * MIMOS Academy — Forgot Password Handler
 * =========================================
 * POST /auth/forgot-password.php
 * Accepts: email, csrf_token
 * Returns: JSON
 * 
 * Generates a secure reset token valid for 1 hour.
 * In production: sends email with reset link.
 * In dev mode: returns the reset link in response.
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

// --- Rate Limiting ---
if (isRateLimited()) {
    jsonResponse([
        'success' => false,
        'message' => 'Too many requests. Please try again later.',
    ], 429);
}

// --- Input Validation ---
$email = strtolower(trim($input['email'] ?? ''));

if (empty($email) || !isValidEmail($email)) {
    jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
}

// --- Lookup User ---
$pdo = getDBConnection();
$stmt = $pdo->prepare("SELECT id, full_name FROM users WHERE email = :email AND is_active = 1 LIMIT 1");
$stmt->execute([':email' => $email]);
$user = $stmt->fetch();

// ALWAYS return success (even if email not found) to prevent user enumeration
if (!$user) {
    // Record attempt to rate limit
    recordLoginAttempt($email, false);

    jsonResponse([
        'success' => true,
        'message' => 'If an account with that email exists, you will receive a password reset link.',
    ]);
}

// --- Generate Reset Token ---
$token = generateToken(32); // 64 char hex string
$expiry = date('Y-m-d H:i:s', time() + 3600); // 1 hour from now

$stmt = $pdo->prepare(
    "UPDATE users SET reset_token = :token, reset_token_expiry = :expiry WHERE id = :id"
);
$stmt->execute([
    ':token'  => $token,
    ':expiry' => $expiry,
    ':id'     => $user['id'],
]);

$resetLink = SITE_URL . '/reset-password.html?token=' . $token;

// --- Send Email (when SMTP is configured) ---
if (!empty(SMTP_HOST)) {
    // TODO: Send email using PHPMailer or similar
    // mail($email, 'Password Reset - MIMOS Academy', "Click here: $resetLink");
}

// Record attempt
recordLoginAttempt($email, true);

// Regenerate CSRF
regenerateCSRFToken();

// Response — in dev mode, include the link; in production, remove 'debug_link'
$response = [
    'success' => true,
    'message' => 'If an account with that email exists, you will receive a password reset link.',
];

// DEV MODE: Include reset link in response for testing
if (empty(SMTP_HOST)) {
    $response['debug_link'] = $resetLink;
    $response['dev_note'] = 'SMTP not configured. Reset link shown for development only.';
}

jsonResponse($response);
