<?php
/**
 * MIMOS Academy — Google OAuth Login (Redirect)
 * ===============================================
 * GET /auth/google-login.php
 * Redirects user to Google OAuth consent screen.
 * 
 * SETUP REQUIRED:
 * 1. Go to https://console.cloud.google.com/
 * 2. Create a project
 * 3. Enable "Google+ API" or "Google People API"
 * 4. Go to Credentials → Create OAuth 2.0 Client ID
 * 5. Set redirect URI to: https://yourdomain.com/auth/google-callback.php
 * 6. Copy Client ID and Client Secret to config.php
 */

require_once __DIR__ . '/../includes/session.php';

// Check if Google OAuth is configured
if (empty(GOOGLE_CLIENT_ID) || empty(GOOGLE_CLIENT_SECRET)) {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><title>Google Login Not Configured</title></head><body>';
    echo '<h2>Google Login is not yet configured.</h2>';
    echo '<p>Please set up Google OAuth credentials in config.php.</p>';
    echo '<a href="../login.html">Back to Login</a>';
    echo '</body></html>';
    exit;
}

// Generate state token for CSRF protection
$state = generateCSRFToken();
$_SESSION['google_oauth_state'] = $state;

// Build Google OAuth URL
$params = http_build_query([
    'client_id'     => GOOGLE_CLIENT_ID,
    'redirect_uri'  => GOOGLE_REDIRECT_URI,
    'response_type' => 'code',
    'scope'         => 'openid email profile',
    'state'         => $state,
    'access_type'   => 'online',
    'prompt'        => 'select_account',
]);

header('Location: https://accounts.google.com/o/oauth2/v2/auth?' . $params);
exit;
