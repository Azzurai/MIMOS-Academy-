<?php
/**
 * MIMOS Academy — Logout Handler
 * ================================
 * GET or POST /auth/logout.php
 * Destroys session and redirects to login.
 */

require_once __DIR__ . '/../includes/session.php';

// Clear all session data
$_SESSION = [];

// Delete session cookie
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// Destroy the session
session_destroy();

// Check if AJAX request
if (
    isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
) {
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'message' => 'Logged out successfully.']);
    exit;
}

// Redirect to login page
header('Location: ../login.html');
exit;
