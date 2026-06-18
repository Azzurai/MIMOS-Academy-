<?php
/**
 * MIMOS Academy — Google OAuth Callback
 * =======================================
 * GET /auth/google-callback.php
 * Handles the response from Google after user authorizes.
 * Creates or links user account, then starts session.
 */

require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/functions.php';

// --- Verify State Token (CSRF) ---
$state = $_GET['state'] ?? '';
if (empty($state) || !isset($_SESSION['google_oauth_state']) || $state !== $_SESSION['google_oauth_state']) {
    die('Invalid state token. Possible CSRF attack. <a href="../login.html">Try again</a>');
}
unset($_SESSION['google_oauth_state']);

// --- Check for errors ---
if (isset($_GET['error'])) {
    header('Location: ../login.html?error=google_denied');
    exit;
}

// --- Get authorization code ---
$code = $_GET['code'] ?? '';
if (empty($code)) {
    header('Location: ../login.html?error=no_code');
    exit;
}

// --- Exchange code for access token ---
$tokenResponse = file_get_contents('https://oauth2.googleapis.com/token', false, stream_context_create([
    'http' => [
        'method'  => 'POST',
        'header'  => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query([
            'code'          => $code,
            'client_id'     => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET,
            'redirect_uri'  => GOOGLE_REDIRECT_URI,
            'grant_type'    => 'authorization_code',
        ]),
    ],
]));

if ($tokenResponse === false) {
    error_log('Google OAuth: Failed to exchange code for token');
    header('Location: ../login.html?error=token_failed');
    exit;
}

$tokenData = json_decode($tokenResponse, true);
$accessToken = $tokenData['access_token'] ?? null;

if (!$accessToken) {
    error_log('Google OAuth: No access token in response');
    header('Location: ../login.html?error=no_token');
    exit;
}

// --- Fetch user profile from Google ---
$profileResponse = file_get_contents('https://www.googleapis.com/oauth2/v2/userinfo', false, stream_context_create([
    'http' => [
        'header' => 'Authorization: Bearer ' . $accessToken,
    ],
]));

if ($profileResponse === false) {
    error_log('Google OAuth: Failed to fetch user profile');
    header('Location: ../login.html?error=profile_failed');
    exit;
}

$profile = json_decode($profileResponse, true);
$googleId   = $profile['id'] ?? null;
$googleName = $profile['name'] ?? '';
$googleEmail = strtolower($profile['email'] ?? '');
$googleAvatar = $profile['picture'] ?? '';

if (!$googleId || !$googleEmail) {
    error_log('Google OAuth: Incomplete profile data');
    header('Location: ../login.html?error=incomplete_profile');
    exit;
}

// --- Find or Create User ---
$pdo = getDBConnection();

// Check if user exists by Google ID
$stmt = $pdo->prepare("SELECT * FROM users WHERE google_id = :gid LIMIT 1");
$stmt->execute([':gid' => $googleId]);
$user = $stmt->fetch();

if (!$user) {
    // Check if user exists by email (link accounts)
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $googleEmail]);
    $user = $stmt->fetch();

    if ($user) {
        // Link Google ID to existing account
        $stmt = $pdo->prepare("UPDATE users SET google_id = :gid, avatar_url = :avatar WHERE id = :id");
        $stmt->execute([':gid' => $googleId, ':avatar' => $googleAvatar, ':id' => $user['id']]);
    } else {
        // Create new user
        $stmt = $pdo->prepare(
            "INSERT INTO users (full_name, email, google_id, avatar_url, email_verified) 
             VALUES (:name, :email, :gid, :avatar, 1)"
        );
        $stmt->execute([
            ':name'   => $googleName,
            ':email'  => $googleEmail,
            ':gid'    => $googleId,
            ':avatar' => $googleAvatar,
        ]);

        $user = [
            'id'         => $pdo->lastInsertId(),
            'full_name'  => $googleName,
            'email'      => $googleEmail,
            'avatar_url' => $googleAvatar,
        ];
    }
}

// --- Check if account is active ---
if (isset($user['is_active']) && !$user['is_active']) {
    header('Location: ../login.html?error=account_deactivated');
    exit;
}

// --- Start Session ---
session_regenerate_id(true);
$_SESSION['user_id']     = $user['id'];
$_SESSION['user_name']   = $user['full_name'];
$_SESSION['user_email']  = $user['email'];
$_SESSION['user_avatar'] = $user['avatar_url'] ?? $googleAvatar;
$_SESSION['_created']    = time();

// Redirect to home
header('Location: ../index.html');
exit;
