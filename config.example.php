<?php
/**
 * MIMOS Academy — Configuration File
 * ====================================
 * TEMPLATE — Copy this to config.php and fill in real values.
 * NEVER commit config.php to Git!
 */

// --- Database Credentials ---
define('DB_HOST', 'localhost');
define('DB_USER', 'your_db_username');
define('DB_PASS', 'your_db_password');
define('DB_NAME', 'your_db_name');

// --- Application Settings ---
define('SITE_URL', 'https://yourdomain.com');  // No trailing slash
define('SITE_NAME', 'MIMOS Academy');

// --- Session Security ---
define('SESSION_LIFETIME', 3600);       // 1 hour in seconds
define('SESSION_NAME', 'MIMOS_SESS');

// --- Security Keys ---
define('CSRF_SECRET', 'change-this-to-a-random-64-char-string');
define('RATE_LIMIT_ATTEMPTS', 5);        // Max login attempts
define('RATE_LIMIT_WINDOW', 900);        // 15 min lockout window (seconds)

// --- Google OAuth (leave blank until configured) ---
define('GOOGLE_CLIENT_ID', '');
define('GOOGLE_CLIENT_SECRET', '');
define('GOOGLE_REDIRECT_URI', SITE_URL . '/auth/google-callback.php');

// --- Cloudflare Turnstile (Anti-Bot CAPTCHA) ---
define('TURNSTILE_SITE_KEY', '');       // Retrieve from Cloudflare Dashboard
define('TURNSTILE_SECRET_KEY', '');     // Retrieve from Cloudflare Dashboard

// --- Email (for forgot password — configure when ready) ---
define('SMTP_HOST', '');
define('SMTP_PORT', 587);
define('SMTP_USER', '');
define('SMTP_PASS', '');
define('SMTP_FROM', 'noreply@yourdomain.com');
define('SMTP_FROM_NAME', 'MIMOS Academy');
