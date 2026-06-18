<?php
/**
 * MIMOS Academy — Unified Auth Controller & Router
 * ==================================================
 * Renders frontend forms and processes backend AJAX requests.
 * Exposes views for Login, Register, Forgot Password, and Reset Password.
 */

require_once __DIR__ . '/includes/auth_helper.php';

$action = $_GET['action'] ?? 'login';

// --- HANDLE POST REQUESTS ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Read JSON or form inputs
    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    // CSRF verification
    $csrfToken = $input['csrf_token'] ?? '';
    if (!verifyCSRFToken($csrfToken)) {
        jsonResponse(['success' => false, 'message' => 'Invalid security token. Please refresh the page.'], 403);
    }

    if ($action === 'login') {
        $email    = strtolower(trim($input['email'] ?? ''));
        $password = $input['password'] ?? '';

        $turnstileToken = $input['cf-turnstile-response'] ?? '';

        if (empty($email) || empty($password)) {
            jsonResponse(['success' => false, 'message' => 'Email and password are required.'], 400);
        }
        if (!verifyTurnstile($turnstileToken)) {
            jsonResponse(['success' => false, 'message' => 'Security check failed. Please refresh and try again.'], 400);
        }
        if (!isValidEmail($email)) {
            jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
        }
        if (isRateLimited($email)) {
            jsonResponse(['success' => false, 'message' => 'Too many login attempts. Please try again in 15 minutes.', 'locked' => true], 429);
        }

        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT id, full_name, email, password_hash, avatar_url, is_active FROM mimos_users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        if (!$user || !$user['password_hash'] || !verifyPassword($password, $user['password_hash'])) {
            recordLoginAttempt($email, false);
            jsonResponse(['success' => false, 'message' => 'Invalid email or password.'], 401);
        }

        if (!$user['is_active']) {
            jsonResponse(['success' => false, 'message' => 'Your account has been deactivated. Contact support.'], 403);
        }

        recordLoginAttempt($email, true);
        session_regenerate_id(true);

        $_SESSION['user_id']     = $user['id'];
        $_SESSION['user_name']   = $user['full_name'];
        $_SESSION['user_email']  = $user['email'];
        $_SESSION['user_avatar'] = $user['avatar_url'] ?? '';
        $_SESSION['_created']    = time();

        registerActiveSession($user['id']);

        regenerateCSRFToken();

        if (mt_rand(1, 10) === 1) {
            cleanupLoginAttempts();
        }

        jsonResponse([
            'success'  => true,
            'message'  => 'Login successful!',
            'redirect' => 'index.html',
        ]);
    }
    elseif ($action === 'register') {
        $fullName        = sanitizeInput($input['full_name'] ?? '');
        $email           = strtolower(trim($input['email'] ?? ''));
        $password        = $input['password'] ?? '';
        $confirmPassword = $input['confirm_password'] ?? '';

        $turnstileToken  = $input['cf-turnstile-response'] ?? '';

        if (empty($fullName) || empty($email) || empty($password) || empty($confirmPassword)) {
            jsonResponse(['success' => false, 'message' => 'All fields are required.'], 400);
        }
        if (!verifyTurnstile($turnstileToken)) {
            jsonResponse(['success' => false, 'message' => 'Security check failed. Please refresh and try again.'], 400);
        }
        if (strlen($fullName) < 2 || strlen($fullName) > 100) {
            jsonResponse(['success' => false, 'message' => 'Full name must be between 2 and 100 characters.'], 400);
        }
        if (!isValidEmail($email)) {
            jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
        }
        if (!isStrongPassword($password)) {
            jsonResponse(['success' => false, 'message' => 'Password must be at least 8 characters with 1 uppercase letter, 1 lowercase letter, and 1 number.'], 400);
        }
        if ($password !== $confirmPassword) {
            jsonResponse(['success' => false, 'message' => 'Passwords do not match.'], 400);
        }

        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT id FROM mimos_users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);

        if ($stmt->fetch()) {
            jsonResponse(['success' => false, 'message' => 'An account with this email already exists.'], 409);
        }

        $passwordHash = hashPassword($password);
        $stmt = $pdo->prepare("INSERT INTO mimos_users (full_name, email, password_hash) VALUES (:name, :email, :password)");

        try {
            $stmt->execute([
                ':name'     => $fullName,
                ':email'    => $email,
                ':password' => $passwordHash,
            ]);

            $userId = $pdo->lastInsertId();

            session_regenerate_id(true);
            $_SESSION['user_id']     = $userId;
            $_SESSION['user_name']   = $fullName;
            $_SESSION['user_email']  = $email;
            $_SESSION['user_avatar'] = '';

            registerActiveSession($userId);

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
    }
    elseif ($action === 'forgot') {
        if (isRateLimited()) {
            jsonResponse(['success' => false, 'message' => 'Too many requests. Please try again later.'], 429);
        }

        $email = strtolower(trim($input['email'] ?? ''));
        $turnstileToken = $input['cf-turnstile-response'] ?? '';

        if (empty($email)) {
            jsonResponse(['success' => false, 'message' => 'Email address is required.'], 400);
        }
        if (!verifyTurnstile($turnstileToken)) {
            jsonResponse(['success' => false, 'message' => 'Security check failed. Please refresh and try again.'], 400);
        }
        if (!isValidEmail($email)) {
            jsonResponse(['success' => false, 'message' => 'Please enter a valid email address.'], 400);
        }

        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT id, full_name FROM mimos_users WHERE email = :email AND is_active = 1 LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        if (!$user) {
            recordLoginAttempt($email, false);
            jsonResponse([
                'success' => true,
                'message' => 'If an account with that email exists, you will receive a password reset link.',
            ]);
        }

        $token = generateToken(32);
        $expiry = date('Y-m-d H:i:s', time() + 3600);

        $stmt = $pdo->prepare("UPDATE mimos_users SET reset_token = :token, reset_token_expiry = :expiry WHERE id = :id");
        $stmt->execute([
            ':token'  => $token,
            ':expiry' => $expiry,
            ':id'     => $user['id'],
        ]);

        $resetLink = SITE_URL . '/auth.php?action=reset&token=' . $token;

        if (!empty(SMTP_HOST)) {
            // SMTP implementation details would go here
        }

        recordLoginAttempt($email, true);
        regenerateCSRFToken();

        $response = [
            'success' => true,
            'message' => 'If an account with that email exists, you will receive a password reset link.',
        ];

        if (empty(SMTP_HOST)) {
            $response['debug_link'] = $resetLink;
            $response['dev_note'] = 'SMTP not configured. Reset link shown for development only.';
        }

        jsonResponse($response);
    }
    elseif ($action === 'reset') {
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
            jsonResponse(['success' => false, 'message' => 'Password must be at least 8 characters with 1 uppercase letter, 1 lowercase letter, and 1 number.'], 400);
        }
        if ($password !== $confirmPassword) {
            jsonResponse(['success' => false, 'message' => 'Passwords do not match.'], 400);
        }

        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT id, email FROM mimos_users WHERE reset_token = :token AND reset_token_expiry > NOW() AND is_active = 1 LIMIT 1");
        $stmt->execute([':token' => $token]);
        $user = $stmt->fetch();

        if (!$user) {
            jsonResponse(['success' => false, 'message' => 'This reset link is invalid or has expired. Please request a new one.'], 400);
        }

        $passwordHash = hashPassword($password);
        $stmt = $pdo->prepare("UPDATE mimos_users SET password_hash = :password, reset_token = NULL, reset_token_expiry = NULL WHERE id = :id");
        $stmt->execute([
            ':password' => $passwordHash,
            ':id'       => $user['id'],
        ]);

        regenerateCSRFToken();

        jsonResponse([
            'success'  => true,
            'message'  => 'Password reset successfully! You can now log in with your new password.',
            'redirect' => 'auth.php',
        ]);
    }
    elseif ($action === 'logout-device') {
        if (!isLoggedIn()) {
            jsonResponse(['success' => false, 'message' => 'Unauthorized.'], 401);
        }
        
        $sessionToken = trim($input['session_token'] ?? '');
        if (empty($sessionToken)) {
            $sessionId = intval($input['session_id'] ?? 0);
            if ($sessionId <= 0) {
                jsonResponse(['success' => false, 'message' => 'Session ID or token is required.'], 400);
            }
            
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("SELECT session_token FROM mimos_active_sessions WHERE id = :id AND user_id = :uid LIMIT 1");
            $stmt->execute([':id' => $sessionId, ':uid' => $_SESSION['user_id']]);
            $sess = $stmt->fetch();
            if ($sess) {
                $sessionToken = $sess['session_token'];
            }
        }
        
        if (empty($sessionToken)) {
            jsonResponse(['success' => false, 'message' => 'Session not found.'], 404);
        }
        
        revokeActiveSession($sessionToken);
        
        jsonResponse([
            'success' => true, 
            'message' => 'Device logged out successfully.'
        ]);
    }
    elseif ($action === 'logout-others') {
        if (!isLoggedIn()) {
            jsonResponse(['success' => false, 'message' => 'Unauthorized.'], 401);
        }
        
        revokeOtherSessions($_SESSION['user_id'], $_SESSION['session_token'] ?? '');
        
        jsonResponse([
            'success' => true,
            'message' => 'All other devices logged out successfully.'
        ]);
    }
    else {
        jsonResponse(['success' => false, 'message' => 'Invalid action.'], 400);
    }
}

// --- HANDLE GET API ACTIONS ---
if ($action === 'check-session') {
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    if (isLoggedIn()) {
        $user = getCurrentUser();
        
        $sessionsList = [];
        $rawSessions = getActiveSessions($user['id']);
        foreach ($rawSessions as $sess) {
            $sessionsList[] = [
                'id' => $sess['id'],
                'ip' => $sess['ip_address'],
                'device' => parseUserAgent($sess['user_agent']),
                'is_current' => ($sess['session_token'] === ($_SESSION['session_token'] ?? '')),
                'created_at' => date('Y-m-d H:i', strtotime($sess['created_at'])),
            ];
        }
        
        echo json_encode([
            'logged_in' => true,
            'user' => [
                'name'   => $user['name'],
                'email'  => $user['email'],
                'avatar' => $user['avatar'],
            ],
            'sessions' => $sessionsList,
            'csrf_token' => generateCSRFToken(),
        ]);
    } else {
        echo json_encode([
            'logged_in'  => false,
            'csrf_token' => generateCSRFToken(),
        ]);
    }
    exit;
}

if ($action === 'logout') {
    if (isset($_SESSION['session_token'])) {
        revokeActiveSession($_SESSION['session_token']);
    }
    $_SESSION = [];
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
    session_destroy();

    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'message' => 'Logged out successfully.']);
        exit;
    }

    header('Location: auth.php');
    exit;
}

if ($action === 'google-login') {
    if (empty(GOOGLE_CLIENT_ID) || empty(GOOGLE_CLIENT_SECRET)) {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Google Login Not Configured</title></head><body>';
        echo '<h2>Google Login is not yet configured.</h2>';
        echo '<p>Please set up Google OAuth credentials in config.php.</p>';
        echo '<a href="auth.php">Back to Login</a>';
        echo '</body></html>';
        exit;
    }

    $state = generateCSRFToken();
    $_SESSION['google_oauth_state'] = $state;

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
}

if ($action === 'google-callback') {
    $state = $_GET['state'] ?? '';
    if (empty($state) || !isset($_SESSION['google_oauth_state']) || $state !== $_SESSION['google_oauth_state']) {
        die('Invalid state token. Possible CSRF attack. <a href="auth.php">Try again</a>');
    }
    unset($_SESSION['google_oauth_state']);

    if (isset($_GET['error'])) {
        header('Location: auth.php?error=google_denied');
        exit;
    }

    $code = $_GET['code'] ?? '';
    if (empty($code)) {
        header('Location: auth.php?error=no_code');
        exit;
    }

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
        header('Location: auth.php?error=token_failed');
        exit;
    }

    $tokenData = json_decode($tokenResponse, true);
    $accessToken = $tokenData['access_token'] ?? null;

    if (!$accessToken) {
        error_log('Google OAuth: No access token in response');
        header('Location: auth.php?error=no_token');
        exit;
    }

    $profileResponse = file_get_contents('https://www.googleapis.com/oauth2/v2/userinfo', false, stream_context_create([
        'http' => [
            'header' => 'Authorization: Bearer ' . $accessToken,
        ],
    ]));

    if ($profileResponse === false) {
        error_log('Google OAuth: Failed to fetch user profile');
        header('Location: auth.php?error=profile_failed');
        exit;
    }

    $profile = json_decode($profileResponse, true);
    $googleId   = $profile['id'] ?? null;
    $googleName = $profile['name'] ?? '';
    $googleEmail = strtolower($profile['email'] ?? '');
    $googleAvatar = $profile['picture'] ?? '';

    if (!$googleId || !$googleEmail) {
        error_log('Google OAuth: Incomplete profile data');
        header('Location: auth.php?error=incomplete_profile');
        exit;
    }

    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT * FROM mimos_users WHERE google_id = :gid LIMIT 1");
    $stmt->execute([':gid' => $googleId]);
    $user = $stmt->fetch();

    if (!$user) {
        $stmt = $pdo->prepare("SELECT * FROM mimos_users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $googleEmail]);
        $user = $stmt->fetch();

        if ($user) {
            $stmt = $pdo->prepare("UPDATE mimos_users SET google_id = :gid, avatar_url = :avatar WHERE id = :id");
            $stmt->execute([':gid' => $googleId, ':avatar' => $googleAvatar, ':id' => $user['id']]);
        } else {
            $stmt = $pdo->prepare(
                "INSERT INTO mimos_users (full_name, email, google_id, avatar_url, email_verified) 
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

    if (isset($user['is_active']) && !$user['is_active']) {
        header('Location: auth.php?error=account_deactivated');
        exit;
    }

    session_regenerate_id(true);
    $_SESSION['user_id']     = $user['id'];
    $_SESSION['user_name']   = $user['full_name'];
    $_SESSION['user_email']  = $user['email'];
    $_SESSION['user_avatar'] = $user['avatar_url'] ?? $googleAvatar;
    $_SESSION['_created']    = time();

    registerActiveSession($user['id']);

    header('Location: index.html');
    exit;
}

// Redirect to home if logged in and requesting views
if (isLoggedIn()) {
    header('Location: index.html');
    exit;
}

$csrfToken = generateCSRFToken();

// --- HANDLE GET VIEWS ---
if ($action === 'register'):
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Register for MIMOS Academy — Create your account and start your journey.">
  <title>Register — MIMOS Academy</title>
  <link rel="stylesheet" href="css/styles.css">
  <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php endif; ?>
  <style>
    .auth-page { min-height: 100vh; display: flex; margin-top: var(--navbar-height); }
    .auth-left { flex: 1; display: flex; align-items: center; justify-content: center; padding: var(--spacing-3xl); }
    .auth-right { flex: 1; position: relative; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--color-navy-dark) 0%, var(--color-navy) 50%, #2a1a6e 100%); overflow: hidden; }
    .auth-right::before { content: ''; position: absolute; top: -30%; right: -20%; width: 500px; height: 500px; background: radial-gradient(circle, rgba(74,58,255,0.2) 0%, transparent 70%); border-radius: 50%; }
    .auth-right__content { position: relative; z-index: 1; text-align: center; color: var(--color-white); max-width: 400px; padding: var(--spacing-2xl); }
    .auth-right__content h2 { font-size: var(--font-size-3xl); font-weight: 800; margin-bottom: var(--spacing-lg); line-height: 1.2; }
    .auth-right__content p { color: rgba(255,255,255,0.7); line-height: 1.7; }
    .auth-form-container { width: 100%; max-width: 420px; }
    .auth-form-container .navbar__logo { margin-bottom: var(--spacing-2xl); }
    .auth-form-container .navbar__logo img { height: 48px; }
    .auth-form-container h1 { font-size: var(--font-size-3xl); font-weight: 800; color: var(--color-navy); margin-bottom: var(--spacing-xs); }
    .auth-form-container > p { font-size: var(--font-size-sm); color: var(--color-muted); margin-bottom: var(--spacing-2xl); }
    .auth-divider { display: flex; align-items: center; gap: var(--spacing-md); margin: var(--spacing-xl) 0; color: var(--color-muted); font-size: var(--font-size-sm); }
    .auth-divider::before, .auth-divider::after { content: ''; flex: 1; height: 1px; background: var(--color-border); }
    .btn-google { width: 100%; display: flex; align-items: center; justify-content: center; gap: 10px; padding: 12px 20px; background: var(--color-white); color: var(--color-dark-text); border: 1px solid var(--color-border); border-radius: var(--radius-sm); font-size: var(--font-size-sm); font-weight: 600; cursor: pointer; transition: all var(--transition-fast); }
    .btn-google:hover { background: var(--color-light-bg); border-color: var(--color-muted); transform: translateY(-1px); box-shadow: var(--shadow-sm); }
    .btn-google svg { width: 20px; height: 20px; }
    .auth-form .form-group { margin-bottom: var(--spacing-lg); }
    .auth-form .form-group label { text-transform: none; letter-spacing: 0; font-weight: 600; }
    .form-group--password { position: relative; }
    .password-toggle { position: absolute; right: 12px; top: 38px; background: none; border: none; cursor: pointer; color: var(--color-muted); padding: 4px; }
    .password-toggle:hover { color: var(--color-primary); }
    .password-strength { height: 4px; border-radius: 2px; background: var(--color-border); margin-top: 8px; overflow: hidden; }
    .password-strength__bar { height: 100%; width: 0%; border-radius: 2px; transition: all 0.3s ease; }
    .password-strength__text { font-size: 11px; margin-top: 4px; color: var(--color-muted); }
    .auth-form .form-submit { width: 100%; border-radius: var(--radius-sm); }
    .auth-footer-text { text-align: center; margin-top: var(--spacing-xl); font-size: var(--font-size-sm); color: var(--color-muted); }
    .auth-footer-text a { color: var(--color-primary); font-weight: 600; }
    .auth-footer-text a:hover { text-decoration: underline; }
    .alert-message { padding: 12px 16px; border-radius: var(--radius-sm); font-size: var(--font-size-sm); margin-bottom: var(--spacing-lg); display: none; }
    .alert-message--error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert-message--success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .alert-message.show { display: block; animation: fadeInUp 0.3s ease; }
    .form-row { display: flex; align-items: flex-start; gap: 6px; margin-bottom: var(--spacing-xl); }
    .form-row input[type="checkbox"] { accent-color: var(--color-primary); margin-top: 3px; flex-shrink: 0; }
    .form-row label { font-size: var(--font-size-xs); color: var(--color-muted); line-height: 1.5; cursor: pointer; }
    .form-row label a { color: var(--color-primary); font-weight: 600; }
    @media (max-width: 768px) {
      .auth-right { display: none; }
      .auth-left { padding: var(--spacing-xl); }
    }
  </style>
</head>
<body class="auth-page">

  <!-- ========== NAVBAR ========== -->
  <nav class="navbar" id="navbar">
    <div class="container">
      <a href="index.html" class="navbar__logo"><img src="assets/images/logo.png" alt="MIMOS Academy Logo"></a>
      <ul class="navbar__links" id="navLinks">
        <li><a href="index.html" class="navbar__link">Home</a></li>
        <li><a href="about.html" class="navbar__link">About</a></li>
        <li><a href="programs.html" class="navbar__link">Programs</a></li>
        <li><a href="#" class="navbar__link">Facilities</a></li>
        <li><a href="#" class="navbar__link">News</a></li>
        <li><a href="contact.html" class="navbar__link">Contact</a></li>
      </ul>
      <div class="navbar__actions">
        <a href="auth.php" class="navbar__cta">
          Sign In
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </a>
      </div>
      <button class="navbar__toggle" id="navToggle" aria-label="Menu"><span></span><span></span><span></span></button>
    </div>
  </nav>

  <!-- ========== AUTH FORM CONTAINER ========== -->
  <div style="display: flex; width: 100%; min-height: 100vh;">
    <div class="auth-left">
      <div class="auth-form-container">
        <a href="index.html" class="navbar__logo"><img src="assets/images/logo.png" alt="MIMOS Academy"></a>

        <h1>Create account</h1>
        <p>Join MIMOS Academy and start your tech journey</p>

        <div class="alert-message alert-message--error" id="errorAlert"></div>
        <div class="alert-message alert-message--success" id="successAlert"></div>

        <a href="auth.php?action=google-login" class="btn-google">
          <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
          Sign up with Google
        </a>

        <div class="auth-divider">or</div>

        <form class="auth-form" id="registerForm" novalidate>
          <div class="form-group">
            <label for="fullName">Full name</label>
            <input type="text" id="fullName" name="full_name" placeholder="Enter your full name" autocomplete="name" required>
          </div>

          <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email" placeholder="Enter your email" autocomplete="email" required>
          </div>

          <div class="form-group form-group--password">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Min 8 chars, 1 uppercase, 1 number" autocomplete="new-password" required>
            <button type="button" class="password-toggle" onclick="togglePassword('password', this)" aria-label="Toggle password">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
            <div class="password-strength"><div class="password-strength__bar" id="strengthBar"></div></div>
            <div class="password-strength__text" id="strengthText"></div>
          </div>

          <div class="form-group form-group--password">
            <label for="confirmPassword">Confirm password</label>
            <input type="password" id="confirmPassword" name="confirm_password" placeholder="Re-enter your password" autocomplete="new-password" required>
            <button type="button" class="password-toggle" onclick="togglePassword('confirmPassword', this)" aria-label="Toggle password">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>

          <div class="form-row">
            <input type="checkbox" id="terms" required>
            <label for="terms">I agree to the <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a></label>
          </div>

          <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
          <div class="form-group">
            <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars(TURNSTILE_SITE_KEY); ?>" data-theme="light"></div>
          </div>
          <?php endif; ?>

          <button type="submit" class="form-submit" id="submitBtn">
            Create Account
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </button>
        </form>

        <p class="auth-footer-text">Already have an account? <a href="auth.php">Sign in</a></p>
      </div>
    </div>

    <div class="auth-right">
      <div class="auth-right__content">
        <h2>Join the Next Generation of Tech Leaders</h2>
        <p>Get hands-on training from industry experts and earn globally recognized certifications in cutting-edge technologies.</p>
      </div>
    </div>
  </div>

  <script src="js/main.js"></script>
  <script>
    const csrfToken = '<?php echo $csrfToken; ?>';

    function togglePassword(fieldId, btn) {
      const input = document.getElementById(fieldId);
      if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
      } else {
        input.type = 'password';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
      }
    }

    function showAlert(type, message) {
      const el = document.getElementById(type === 'error' ? 'errorAlert' : 'successAlert');
      const other = document.getElementById(type === 'error' ? 'successAlert' : 'errorAlert');
      other.classList.remove('show');
      el.textContent = message;
      el.classList.add('show');
    }

    document.getElementById('password').addEventListener('input', function() {
      const pw = this.value;
      const bar = document.getElementById('strengthBar');
      const text = document.getElementById('strengthText');
      let score = 0;

      if (pw.length >= 8) score++;
      if (/[A-Z]/.test(pw)) score++;
      if (/[a-z]/.test(pw)) score++;
      if (/[0-9]/.test(pw)) score++;
      if (/[^A-Za-z0-9]/.test(pw)) score++;

      const levels = [
        { width: '0%', color: '#e5e7eb', label: '' },
        { width: '20%', color: '#dc2626', label: 'Very weak' },
        { width: '40%', color: '#ea580c', label: 'Weak' },
        { width: '60%', color: '#eab308', label: 'Fair' },
        { width: '80%', color: '#22c55e', label: 'Strong' },
        { width: '100%', color: '#16a34a', label: 'Very strong' },
      ];

      bar.style.width = levels[score].width;
      bar.style.background = levels[score].color;
      text.textContent = levels[score].label;
      text.style.color = levels[score].color;
    });

    document.getElementById('registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const fullName = document.getElementById('fullName').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      const terms = document.getElementById('terms').checked;
      const submitBtn = document.getElementById('submitBtn');

      if (!fullName || !email || !password || !confirmPassword) {
        showAlert('error', 'All fields are required.');
        return;
      }

      if (!terms) {
        showAlert('error', 'Please agree to the Terms of Service and Privacy Policy.');
        return;
      }

      if (password !== confirmPassword) {
        showAlert('error', 'Passwords do not match.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating account...';

      try {
        const response = await fetch('auth.php?action=register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            full_name: fullName,
            email,
            password,
            confirm_password: confirmPassword,
            csrf_token: csrfToken,
            'cf-turnstile-response': document.querySelector('[name="cf-turnstile-response"]')?.value || '',
          }),
        });

        const data = await response.json();

        if (data.success) {
          showAlert('success', data.message);
          setTimeout(() => {
            window.location.href = data.redirect || 'index.html';
          }, 800);
        } else {
          showAlert('error', data.message);
          if (window.turnstile) turnstile.reset();
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Create Account <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
        }
      } catch (err) {
        showAlert('error', 'A network error occurred. Please try again.');
        if (window.turnstile) turnstile.reset();
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Create Account <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
      }
    });
  </script>
</body>
</html>

<?php elseif ($action === 'forgot'): ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Forgot Password — MIMOS Academy. Reset your account password.">
  <title>Forgot Password — MIMOS Academy</title>
  <link rel="stylesheet" href="css/styles.css">
  <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php endif; ?>
  <style>
    .auth-page { min-height: 100vh; display: flex; margin-top: var(--navbar-height); }
    .auth-left { flex: 1; display: flex; align-items: center; justify-content: center; padding: var(--spacing-3xl); }
    .auth-right { flex: 1; position: relative; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--color-navy-dark) 0%, var(--color-navy) 50%, #2a1a6e 100%); overflow: hidden; }
    .auth-right::before { content: ''; position: absolute; top: -30%; right: -20%; width: 500px; height: 500px; background: radial-gradient(circle, rgba(74,58,255,0.2) 0%, transparent 70%); border-radius: 50%; }
    .auth-right__content { position: relative; z-index: 1; text-align: center; color: var(--color-white); max-width: 400px; padding: var(--spacing-2xl); }
    .auth-right__content h2 { font-size: var(--font-size-3xl); font-weight: 800; margin-bottom: var(--spacing-lg); line-height: 1.2; }
    .auth-right__content p { color: rgba(255,255,255,0.7); line-height: 1.7; }
    .auth-form-container { width: 100%; max-width: 420px; }
    .auth-form-container .navbar__logo { margin-bottom: var(--spacing-2xl); }
    .auth-form-container .navbar__logo img { height: 48px; }
    .auth-form-container h1 { font-size: var(--font-size-3xl); font-weight: 800; color: var(--color-navy); margin-bottom: var(--spacing-xs); }
    .auth-form-container > p { font-size: var(--font-size-sm); color: var(--color-muted); margin-bottom: var(--spacing-2xl); line-height: 1.6; }
    .auth-form .form-group { margin-bottom: var(--spacing-lg); }
    .auth-form .form-group label { text-transform: none; letter-spacing: 0; font-weight: 600; }
    .auth-form .form-submit { width: 100%; border-radius: var(--radius-sm); }
    .auth-footer-text { text-align: center; margin-top: var(--spacing-xl); font-size: var(--font-size-sm); color: var(--color-muted); }
    .auth-footer-text a { color: var(--color-primary); font-weight: 600; }
    .auth-footer-text a:hover { text-decoration: underline; }
    .alert-message { padding: 12px 16px; border-radius: var(--radius-sm); font-size: var(--font-size-sm); margin-bottom: var(--spacing-lg); display: none; }
    .alert-message--error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert-message--success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .alert-message.show { display: block; animation: fadeInUp 0.3s ease; }
    .back-link { display: inline-flex; align-items: center; gap: 6px; font-size: var(--font-size-sm); color: var(--color-muted); margin-bottom: var(--spacing-xl); transition: color var(--transition-fast); }
    .back-link:hover { color: var(--color-primary); }
    .lock-icon { width: 64px; height: 64px; border-radius: 50%; background: var(--color-primary-light); display: flex; align-items: center; justify-content: center; margin-bottom: var(--spacing-xl); }
    .lock-icon svg { color: var(--color-primary); }
    .debug-link { padding: 12px 16px; border-radius: var(--radius-sm); font-size: var(--font-size-xs); background: #fffbeb; border: 1px solid #fde68a; color: #92400e; margin-top: var(--spacing-lg); word-break: break-all; display: none; }
    .debug-link.show { display: block; }
    .debug-link a { color: var(--color-primary); font-weight: 600; }
    @media (max-width: 768px) { .auth-right { display: none; } .auth-left { padding: var(--spacing-xl); } }
  </style>
</head>
<body class="auth-page">

  <!-- ========== NAVBAR ========== -->
  <nav class="navbar" id="navbar">
    <div class="container">
      <a href="index.html" class="navbar__logo"><img src="assets/images/logo.png" alt="MIMOS Academy Logo"></a>
      <ul class="navbar__links" id="navLinks">
        <li><a href="index.html" class="navbar__link">Home</a></li>
        <li><a href="about.html" class="navbar__link">About</a></li>
        <li><a href="programs.html" class="navbar__link">Programs</a></li>
        <li><a href="#" class="navbar__link">Facilities</a></li>
        <li><a href="#" class="navbar__link">News</a></li>
        <li><a href="contact.html" class="navbar__link">Contact</a></li>
      </ul>
      <div class="navbar__actions">
        <a href="auth.php" class="navbar__cta">Sign In <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
      </div>
      <button class="navbar__toggle" id="navToggle" aria-label="Menu"><span></span><span></span><span></span></button>
    </div>
  </nav>

  <div style="display: flex; width: 100%; min-height: 100vh;">
    <div class="auth-left">
      <div class="auth-form-container">
        <a href="auth.php" class="back-link">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
          Back to login
        </a>

        <div class="lock-icon">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>

        <h1>Forgot password?</h1>
        <p>No worries! Enter the email address associated with your account and we'll send you a link to reset your password.</p>

        <div class="alert-message alert-message--error" id="errorAlert"></div>
        <div class="alert-message alert-message--success" id="successAlert"></div>
        <div class="debug-link" id="debugLink"></div>

        <form class="auth-form" id="forgotForm" novalidate>
          <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email" placeholder="Enter your email" autocomplete="email" required>
          </div>

          <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
          <div class="form-group">
            <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars(TURNSTILE_SITE_KEY); ?>" data-theme="light"></div>
          </div>
          <?php endif; ?>

          <button type="submit" class="form-submit" id="submitBtn">
            Send Reset Link
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </button>
        </form>

        <p class="auth-footer-text">Remember your password? <a href="auth.php">Sign in</a></p>
      </div>
    </div>

    <div class="auth-right">
      <div class="auth-right__content">
        <h2>Secure Account Recovery</h2>
        <p>Your account security is our priority. We use time-limited tokens and encrypted links to protect your password reset process.</p>
      </div>
    </div>
  </div>

  <script src="js/main.js"></script>
  <script>
    const csrfToken = '<?php echo $csrfToken; ?>';

    function showAlert(type, message) {
      const el = document.getElementById(type === 'error' ? 'errorAlert' : 'successAlert');
      const other = document.getElementById(type === 'error' ? 'successAlert' : 'errorAlert');
      other.classList.remove('show');
      el.textContent = message;
      el.classList.add('show');
    }

    document.getElementById('forgotForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const submitBtn = document.getElementById('submitBtn');

      if (!email) { showAlert('error', 'Please enter your email address.'); return; }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Sending...';

      try {
        const response = await fetch('auth.php?action=forgot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            email, 
            csrf_token: csrfToken,
            'cf-turnstile-response': document.querySelector('[name="cf-turnstile-response"]')?.value || '',
          }),
        });

        const data = await response.json();

        if (data.success) {
          showAlert('success', data.message);

          if (data.debug_link) {
            const debugEl = document.getElementById('debugLink');
            debugEl.innerHTML = '⚠️ <strong>Dev Mode:</strong> ' + data.dev_note + '<br><a href="' + data.debug_link + '">' + data.debug_link + '</a>';
            debugEl.classList.add('show');
          }
        } else {
          showAlert('error', data.message);
          if (window.turnstile) turnstile.reset();
        }

        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Send Reset Link <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
      } catch (err) {
        showAlert('error', 'A network error occurred. Please try again.');
        if (window.turnstile) turnstile.reset();
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Send Reset Link <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
      }
    });
  </script>
</body>
</html>

<?php elseif ($action === 'reset'):
    $resetToken = trim($_GET['token'] ?? '');
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT id FROM users WHERE reset_token = :token AND reset_token_expiry > NOW() AND is_active = 1 LIMIT 1");
    $stmt->execute([':token' => $resetToken]);
    $isValidToken = (bool) $stmt->fetch();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Reset Password — MIMOS Academy. Set a new password for your account.">
  <title>Reset Password — MIMOS Academy</title>
  <link rel="stylesheet" href="css/styles.css">
  <style>
    .auth-page { min-height: 100vh; display: flex; margin-top: var(--navbar-height); }
    .auth-left { flex: 1; display: flex; align-items: center; justify-content: center; padding: var(--spacing-3xl); }
    .auth-right { flex: 1; position: relative; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--color-navy-dark) 0%, var(--color-navy) 50%, #2a1a6e 100%); overflow: hidden; }
    .auth-right::before { content: ''; position: absolute; top: -30%; right: -20%; width: 500px; height: 500px; background: radial-gradient(circle, rgba(74,58,255,0.2) 0%, transparent 70%); border-radius: 50%; }
    .auth-right__content { position: relative; z-index: 1; text-align: center; color: var(--color-white); max-width: 400px; padding: var(--spacing-2xl); }
    .auth-right__content h2 { font-size: var(--font-size-3xl); font-weight: 800; margin-bottom: var(--spacing-lg); line-height: 1.2; }
    .auth-right__content p { color: rgba(255,255,255,0.7); line-height: 1.7; }
    .auth-form-container { width: 100%; max-width: 420px; }
    .auth-form-container h1 { font-size: var(--font-size-3xl); font-weight: 800; color: var(--color-navy); margin-bottom: var(--spacing-xs); }
    .auth-form-container > p { font-size: var(--font-size-sm); color: var(--color-muted); margin-bottom: var(--spacing-2xl); line-height: 1.6; }
    .auth-form .form-group { margin-bottom: var(--spacing-lg); }
    .auth-form .form-group label { text-transform: none; letter-spacing: 0; font-weight: 600; }
    .form-group--password { position: relative; }
    .password-toggle { position: absolute; right: 12px; top: 38px; background: none; border: none; cursor: pointer; color: var(--color-muted); padding: 4px; }
    .password-toggle:hover { color: var(--color-primary); }
    .auth-form .form-submit { width: 100%; border-radius: var(--radius-sm); }
    .auth-footer-text { text-align: center; margin-top: var(--spacing-xl); font-size: var(--font-size-sm); color: var(--color-muted); }
    .auth-footer-text a { color: var(--color-primary); font-weight: 600; }
    .alert-message { padding: 12px 16px; border-radius: var(--radius-sm); font-size: var(--font-size-sm); margin-bottom: var(--spacing-lg); display: none; }
    .alert-message--error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert-message--success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .alert-message.show { display: block; animation: fadeInUp 0.3s ease; }
    .lock-icon { width: 64px; height: 64px; border-radius: 50%; background: var(--color-primary-light); display: flex; align-items: center; justify-content: center; margin-bottom: var(--spacing-xl); }
    .lock-icon svg { color: var(--color-primary); }
    .password-strength { height: 4px; border-radius: 2px; background: var(--color-border); margin-top: 8px; overflow: hidden; }
    .password-strength__bar { height: 100%; width: 0%; border-radius: 2px; transition: all 0.3s ease; }
    .password-strength__text { font-size: 11px; margin-top: 4px; color: var(--color-muted); }
    @media (max-width: 768px) { .auth-right { display: none; } .auth-left { padding: var(--spacing-xl); } }
  </style>
</head>
<body class="auth-page">

  <nav class="navbar" id="navbar">
    <div class="container">
      <a href="index.html" class="navbar__logo"><img src="assets/images/logo.png" alt="MIMOS Academy Logo"></a>
      <ul class="navbar__links" id="navLinks">
        <li><a href="index.html" class="navbar__link">Home</a></li>
        <li><a href="about.html" class="navbar__link">About</a></li>
        <li><a href="programs.html" class="navbar__link">Programs</a></li>
        <li><a href="#" class="navbar__link">Facilities</a></li>
        <li><a href="#" class="navbar__link">News</a></li>
        <li><a href="contact.html" class="navbar__link">Contact</a></li>
      </ul>
      <div class="navbar__actions">
        <a href="auth.php" class="navbar__cta">Sign In <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
      </div>
      <button class="navbar__toggle" id="navToggle" aria-label="Menu"><span></span><span></span><span></span></button>
    </div>
  </nav>

  <div style="display: flex; width: 100%; min-height: 100vh;">
    <div class="auth-left">
      <div class="auth-form-container">
        <div class="lock-icon">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15v2m-6 4h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2zm10-10V7a4 4 0 0 0-8 0v4h8z"/></svg>
        </div>

        <h1>Set new password</h1>
        <p>Your new password must be at least 8 characters with 1 uppercase letter, 1 lowercase letter, and 1 number.</p>

        <div class="alert-message alert-message--error" id="errorAlert"></div>
        <div class="alert-message alert-message--success" id="successAlert"></div>

        <form class="auth-form" id="resetForm" novalidate style="<?php echo $isValidToken ? '' : 'display:none;'; ?>">
          <div class="form-group form-group--password">
            <label for="password">New password</label>
            <input type="password" id="password" name="password" placeholder="Enter new password" autocomplete="new-password" required>
            <button type="button" class="password-toggle" onclick="togglePassword('password', this)" aria-label="Toggle password">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
            <div class="password-strength"><div class="password-strength__bar" id="strengthBar"></div></div>
            <div class="password-strength__text" id="strengthText"></div>
          </div>

          <div class="form-group form-group--password">
            <label for="confirmPassword">Confirm new password</label>
            <input type="password" id="confirmPassword" name="confirm_password" placeholder="Re-enter new password" autocomplete="new-password" required>
            <button type="button" class="password-toggle" onclick="togglePassword('confirmPassword', this)" aria-label="Toggle password">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>

          <button type="submit" class="form-submit" id="submitBtn">
            Reset Password
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </button>
        </form>

        <p class="auth-footer-text">Remember your password? <a href="auth.php">Sign in</a></p>
      </div>
    </div>

    <div class="auth-right">
      <div class="auth-right__content">
        <h2>Almost There!</h2>
        <p>Choose a strong, unique password to keep your MIMOS Academy account secure.</p>
      </div>
    </div>
  </div>

  <script src="js/main.js"></script>
  <script>
    const csrfToken = '<?php echo $csrfToken; ?>';
    const resetToken = '<?php echo sanitizeInput($resetToken); ?>';
    const isValidToken = <?php echo $isValidToken ? 'true' : 'false'; ?>;

    if (!isValidToken) {
      document.getElementById('errorAlert').textContent = 'Invalid or expired reset token. Please request a new link.';
      document.getElementById('errorAlert').classList.add('show');
    }

    function togglePassword(fieldId, btn) {
      const input = document.getElementById(fieldId);
      if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
      } else {
        input.type = 'password';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
      }
    }

    function showAlert(type, message) {
      const el = document.getElementById(type === 'error' ? 'errorAlert' : 'successAlert');
      const other = document.getElementById(type === 'error' ? 'successAlert' : 'errorAlert');
      other.classList.remove('show');
      el.textContent = message;
      el.classList.add('show');
    }

    document.getElementById('password').addEventListener('input', function() {
      const pw = this.value;
      const bar = document.getElementById('strengthBar');
      const text = document.getElementById('strengthText');
      let score = 0;
      if (pw.length >= 8) score++;
      if (/[A-Z]/.test(pw)) score++;
      if (/[a-z]/.test(pw)) score++;
      if (/[0-9]/.test(pw)) score++;
      if (/[^A-Za-z0-9]/.test(pw)) score++;
      const levels = [
        { width: '0%', color: '#e5e7eb', label: '' },
        { width: '20%', color: '#dc2626', label: 'Very weak' },
        { width: '40%', color: '#ea580c', label: 'Weak' },
        { width: '60%', color: '#eab308', label: 'Fair' },
        { width: '80%', color: '#22c55e', label: 'Strong' },
        { width: '100%', color: '#16a34a', label: 'Very strong' },
      ];
      bar.style.width = levels[score].width;
      bar.style.background = levels[score].color;
      text.textContent = levels[score].label;
      text.style.color = levels[score].color;
    });

    document.getElementById('resetForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      const submitBtn = document.getElementById('submitBtn');

      if (!password || !confirmPassword) { showAlert('error', 'Please fill in both password fields.'); return; }
      if (password !== confirmPassword) { showAlert('error', 'Passwords do not match.'); return; }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Resetting...';

      try {
        const response = await fetch('auth.php?action=reset', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: resetToken, password, confirm_password: confirmPassword, csrf_token: csrfToken }),
        });
        const data = await response.json();

        if (data.success) {
          showAlert('success', data.message);
          document.getElementById('resetForm').style.display = 'none';
          setTimeout(() => { window.location.href = data.redirect || 'auth.php'; }, 2000);
        } else {
          showAlert('error', data.message);
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Reset Password <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
        }
      } catch (err) {
        showAlert('error', 'A network error occurred. Please try again.');
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Reset Password <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
      }
    });
  </script>
</body>
</html>

<?php else:
    // Default: Login View
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Login to MIMOS Academy — Access your programs, certifications, and learning dashboard.">
  <title>Login — MIMOS Academy</title>
  <link rel="stylesheet" href="css/styles.css">
  <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php endif; ?>
  <style>
    .auth-page { min-height: 100vh; display: flex; margin-top: var(--navbar-height); }
    .auth-left { flex: 1; display: flex; align-items: center; justify-content: center; padding: var(--spacing-3xl); }
    .auth-right { flex: 1; position: relative; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--color-navy-dark) 0%, var(--color-navy) 50%, #2a1a6e 100%); overflow: hidden; }
    .auth-right::before { content: ''; position: absolute; top: -30%; right: -20%; width: 500px; height: 500px; background: radial-gradient(circle, rgba(74,58,255,0.2) 0%, transparent 70%); border-radius: 50%; }
    .auth-right__content { position: relative; z-index: 1; text-align: center; color: var(--color-white); max-width: 400px; padding: var(--spacing-2xl); }
    .auth-right__content h2 { font-size: var(--font-size-3xl); font-weight: 800; margin-bottom: var(--spacing-lg); line-height: 1.2; }
    .auth-right__content p { font-size: var(--font-size-base); color: rgba(255,255,255,0.7); line-height: 1.7; }
    .auth-form-container { width: 100%; max-width: 420px; }
    .auth-form-container .navbar__logo { margin-bottom: var(--spacing-2xl); }
    .auth-form-container .navbar__logo img { height: 48px; }
    .auth-form-container h1 { font-size: var(--font-size-3xl); font-weight: 800; color: var(--color-navy); margin-bottom: var(--spacing-xs); }
    .auth-form-container > p { font-size: var(--font-size-sm); color: var(--color-muted); margin-bottom: var(--spacing-2xl); }
    .auth-divider { display: flex; align-items: center; gap: var(--spacing-md); margin: var(--spacing-xl) 0; color: var(--color-muted); font-size: var(--font-size-sm); }
    .auth-divider::before, .auth-divider::after { content: ''; flex: 1; height: 1px; background: var(--color-border); }
    .btn-google { width: 100%; display: flex; align-items: center; justify-content: center; gap: 10px; padding: 12px 20px; background: var(--color-white); color: var(--color-dark-text); border: 1px solid var(--color-border); border-radius: var(--radius-sm); font-size: var(--font-size-sm); font-weight: 600; cursor: pointer; transition: all var(--transition-fast); }
    .btn-google:hover { background: var(--color-light-bg); border-color: var(--color-muted); transform: translateY(-1px); box-shadow: var(--shadow-sm); }
    .btn-google svg { width: 20px; height: 20px; }
    .auth-form .form-group { margin-bottom: var(--spacing-lg); }
    .auth-form .form-group label { text-transform: none; letter-spacing: 0; font-weight: 600; }
    .form-group--password { position: relative; }
    .password-toggle { position: absolute; right: 12px; top: 38px; background: none; border: none; cursor: pointer; color: var(--color-muted); padding: 4px; }
    .password-toggle:hover { color: var(--color-primary); }
    .form-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--spacing-xl); }
    .form-row label { display: flex; align-items: center; gap: 6px; font-size: var(--font-size-sm); color: var(--color-body-text); cursor: pointer; }
    .form-row label input[type="checkbox"] { accent-color: var(--color-primary); }
    .form-row a { font-size: var(--font-size-sm); color: var(--color-primary); font-weight: 600; }
    .form-row a:hover { text-decoration: underline; }
    .auth-form .form-submit { border-radius: var(--radius-sm); width: 100%; }
    .auth-footer-text { text-align: center; margin-top: var(--spacing-xl); font-size: var(--font-size-sm); color: var(--color-muted); }
    .auth-footer-text a { color: var(--color-primary); font-weight: 600; }
    .auth-footer-text a:hover { text-decoration: underline; }
    .alert-message { padding: 12px 16px; border-radius: var(--radius-sm); font-size: var(--font-size-sm); margin-bottom: var(--spacing-lg); display: none; }
    .alert-message--error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert-message--success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .alert-message.show { display: block; animation: fadeInUp 0.3s ease; }
    @media (max-width: 768px) {
      .auth-right { display: none; }
      .auth-left { padding: var(--spacing-xl); }
    }
  </style>
</head>
<body class="auth-page">

  <!-- ========== NAVBAR ========== -->
  <nav class="navbar" id="navbar">
    <div class="container">
      <a href="index.html" class="navbar__logo">
        <img src="assets/images/logo.png" alt="MIMOS Academy Logo">
      </a>
      <ul class="navbar__links" id="navLinks">
        <li><a href="index.html" class="navbar__link">Home</a></li>
        <li><a href="about.html" class="navbar__link">About</a></li>
        <li><a href="programs.html" class="navbar__link">Programs</a></li>
        <li><a href="#" class="navbar__link">Facilities</a></li>
        <li><a href="#" class="navbar__link">News</a></li>
        <li><a href="contact.html" class="navbar__link">Contact</a></li>
      </ul>
      <div class="navbar__actions">
        <a href="auth.php?action=register" class="navbar__cta">
          Register Now
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </a>
      </div>
      <button class="navbar__toggle" id="navToggle" aria-label="Menu">
        <span></span><span></span><span></span>
      </button>
    </div>
  </nav>

  <!-- ========== AUTH FORM CONTAINER ========== -->
  <div style="display: flex; width: 100%; min-height: 100vh;">
    <div class="auth-left">
      <div class="auth-form-container">
        <a href="index.html" class="navbar__logo">
          <img src="assets/images/logo.png" alt="MIMOS Academy">
        </a>

        <h1>Welcome back</h1>
        <p>Sign in to your MIMOS Academy account</p>

        <div class="alert-message alert-message--error" id="errorAlert"></div>
        <div class="alert-message alert-message--success" id="successAlert"></div>

        <a href="auth.php?action=google-login" class="btn-google">
          <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
          Sign in with Google
        </a>

        <div class="auth-divider">or</div>

        <form class="auth-form" id="loginForm" novalidate>
          <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email" placeholder="Enter your email" autocomplete="email" required>
          </div>

          <div class="form-group form-group--password">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter your password" autocomplete="current-password" required>
            <button type="button" class="password-toggle" onclick="togglePassword('password', this)" aria-label="Toggle password visibility">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>

          <div class="form-row">
            <label><input type="checkbox" id="remember"> Remember me</label>
            <a href="auth.php?action=forgot">Forgot password?</a>
          </div>

          <?php if (defined('TURNSTILE_SITE_KEY') && !empty(TURNSTILE_SITE_KEY)): ?>
          <div class="form-group">
            <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars(TURNSTILE_SITE_KEY); ?>" data-theme="light"></div>
          </div>
          <?php endif; ?>

          <button type="submit" class="form-submit" id="submitBtn">
            Sign In
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </button>
        </form>

        <p class="auth-footer-text">
          Don't have an account? <a href="auth.php?action=register">Create one</a>
        </p>
      </div>
    </div>

    <!-- Right — Branding -->
    <div class="auth-right">
      <div class="auth-right__content">
        <h2>Driving Malaysia's High-Tech Excellence</h2>
        <p>Access world-class training programs in semiconductor, AI, cybersecurity, and emerging technologies.</p>
      </div>
    </div>
  </div>

  <script src="js/main.js"></script>
  <script>
    const csrfToken = '<?php echo $csrfToken; ?>';

    function togglePassword(fieldId, btn) {
      const input = document.getElementById(fieldId);
      if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
      } else {
        input.type = 'password';
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
      }
    }

    function showAlert(type, message) {
      const el = document.getElementById(type === 'error' ? 'errorAlert' : 'successAlert');
      const other = document.getElementById(type === 'error' ? 'successAlert' : 'errorAlert');
      other.classList.remove('show');
      el.textContent = message;
      el.classList.add('show');
    }

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const submitBtn = document.getElementById('submitBtn');

      if (!email || !password) {
        showAlert('error', 'Please enter your email and password.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in...';

      try {
        const response = await fetch('auth.php?action=login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password,
            csrf_token: csrfToken,
            'cf-turnstile-response': document.querySelector('[name="cf-turnstile-response"]')?.value || '',
          }),
        });

        const data = await response.json();

        if (data.success) {
          showAlert('success', data.message);
          setTimeout(() => {
            window.location.href = data.redirect || 'index.html';
          }, 800);
        } else {
          showAlert('error', data.message);
          if (window.turnstile) turnstile.reset();
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Sign In <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
        }
      } catch (err) {
        showAlert('error', 'A network error occurred. Please try again.');
        if (window.turnstile) turnstile.reset();
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Sign In <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
      }
    });

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('error')) {
      const errorMap = {
        'google_denied': 'Google sign-in was cancelled.',
        'token_failed': 'Google authentication failed. Please try again.',
        'account_deactivated': 'Your account has been deactivated. Contact support.',
      };
      showAlert('error', errorMap[urlParams.get('error')] || 'An error occurred.');
    }
    if (urlParams.get('registered')) {
      showAlert('success', 'Account created! Please sign in.');
    }
    if (urlParams.get('reset')) {
      showAlert('success', 'Password reset successfully! Please sign in.');
    }
  </script>
</body>
</html>
<?php endif; ?>
