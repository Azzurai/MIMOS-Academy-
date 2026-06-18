<?php
/**
 * MIMOS Academy — Check Session Status
 * ======================================
 * GET /auth/check-session.php
 * Returns JSON with login status and user data.
 * Used by frontend JS to update navbar (logged in vs not).
 */

require_once __DIR__ . '/../includes/session.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

if (isLoggedIn()) {
    $user = getCurrentUser();
    echo json_encode([
        'logged_in' => true,
        'user' => [
            'name'   => $user['name'],
            'email'  => $user['email'],
            'avatar' => $user['avatar'],
        ],
        'csrf_token' => generateCSRFToken(),
    ]);
} else {
    echo json_encode([
        'logged_in'  => false,
        'csrf_token' => generateCSRFToken(),
    ]);
}
