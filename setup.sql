-- ============================================
-- MIMOS Academy — Database Schema
-- Run this on your MySQL database via cPanel phpMyAdmin
-- ============================================

-- Users table
CREATE TABLE IF NOT EXISTS `mimos_users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `full_name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) DEFAULT NULL,
    `google_id` VARCHAR(255) DEFAULT NULL UNIQUE,
    `avatar_url` VARCHAR(500) DEFAULT NULL,
    `reset_token` VARCHAR(64) DEFAULT NULL,
    `reset_token_expiry` DATETIME DEFAULT NULL,
    `email_verified` TINYINT(1) DEFAULT 0,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_email` (`email`),
    INDEX `idx_google_id` (`google_id`),
    INDEX `idx_reset_token` (`reset_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login attempts table (for rate limiting / brute force protection)
CREATE TABLE IF NOT EXISTS `mimos_login_attempts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `email` VARCHAR(255) DEFAULT NULL,
    `attempted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `success` TINYINT(1) DEFAULT 0,
    INDEX `idx_ip_time` (`ip_address`, `attempted_at`),
    INDEX `idx_email_time` (`email`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions table (optional server-side session tracking)
CREATE TABLE IF NOT EXISTS `mimos_active_sessions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `session_token` VARCHAR(128) NOT NULL UNIQUE,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(500) DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `mimos_users`(`id`) ON DELETE CASCADE,
    INDEX `idx_session_token` (`session_token`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

