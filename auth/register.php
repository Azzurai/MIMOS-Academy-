<?php
/**
 * MIMOS Academy — Registration Handler
 * ======================================
 * POST /auth/register.php
 * Accepts: full_name, email, password, confirm_password, csrf_token
 * Returns: JSON
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
$fullName        = sanitizeInput($input['full_name'] ?? '');
$email           = strtolower(trim($input['email'] ?? ''));
$password        = $input['password'] ?? '';
$confirmPassword = $input['confirm_password'] ?? '';

// Validate required fields
if (empty($fullName) || empty($email) || empty($password) || empty($confirmPassword)) {
    jsonResponse(['success' => false, 'message' => 'All fields are required.'], 400);
}

// Validate name length
if (strlen($fullName) < 2 || strlen($fullName) > 100) {
    jsonResponse(['success' => false, 'message' => 'Full name must be between 2 and 100 characters.'], 400);
}

// Validate email
if (!isValidEmail($email)) {
    jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
}

// Validate password strength
if (!isStrongPassword($password)) {
    jsonResponse([
        'success' => false,
        'message' => 'Password must be at least 8 characters with 1 uppercase letter, 1 lowercase letter, and 1 number.'
    ], 400);
}

// Confirm passwords match
if ($password !== $confirmPassword) {
    jsonResponse(['success' => false, 'message' => 'Passwords do not match.'], 400);
}

// --- Check if email already exists ---
$pdo = getDBConnection();
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
$stmt->execute([':email' => $email]);

if ($stmt->fetch()) {
    jsonResponse(['success' => false, 'message' => 'An account with this email already exists.'], 409);
}

// --- Create user ---
$passwordHash = hashPassword($password);

$stmt = $pdo->prepare(
    "INSERT INTO users (full_name, email, password_hash) VALUES (:name, :email, :password)"
);

try {
    $stmt->execute([
        ':name'     => $fullName,
        ':email'    => $email,
        ':password' => $passwordHash,
    ]);

    $userId = $pdo->lastInsertId();

    // Auto-login after registration
    session_regenerate_id(true);
    $_SESSION['user_id']     = $userId;
    $_SESSION['user_name']   = $fullName;
    $_SESSION['user_email']  = $email;
    $_SESSION['user_avatar'] = '';

    // Regenerate CSRF token
    regenerateCSRFToken();

    jsonResponse([
        'success'  => true,
        'message'  => 'Account created successfully!',
        'redirect' => 'index.html',
    ]);

} catch (PDOException $e) {
    error_log('Registration error: ' . $e->getMessage());
    jsonResponse(['success' => false, 'message' => 'An error occurred. Please try again.'], 500);
}
