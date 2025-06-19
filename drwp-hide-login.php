<?php
/**
 * Plugin Name: DRWP Hide Login
 * Plugin URI: https://iwebclue.com/plugins/drwp-hide-login
 * Description: Hide the default wp-login.php and protect your WordPress site with a customizable, secure login slug.
 * Version: 1.0
 * Author: Desraj Kumawat
 * Author URI: https://iwebclue.com/
 * Text Domain: drwp-hide-login
 * Domain Path: /languages
 * License: GPLv2 or later
 */

defined('ABSPATH') || exit;

// Load plugin textdomain
function drwp_load_textdomain() {
    load_plugin_textdomain('drwp-hide-login', false, dirname(plugin_basename(__FILE__)) . '/languages');
}
add_action('plugins_loaded', 'drwp_load_textdomain');

// Register plugin settings
function drwp_register_settings() {
    register_setting('general', 'drwp_login_slug', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_title',
        'default' => 'secure-login'
    ]);
    register_setting('general', 'drwp_allowed_ips', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => ''
    ]);

    add_settings_field(
        'drwp_login_slug',
        __('Custom Login URL', 'drwp-hide-login'),
        'drwp_login_slug_field',
        'general'
    );

    add_settings_field(
        'drwp_allowed_ips',
        __('Allowed IPs', 'drwp-hide-login'),
        'drwp_allowed_ips_field',
        'general'
    );
}
add_action('admin_init', 'drwp_register_settings');

// Settings field output
function drwp_login_slug_field() {
    $slug = get_option('drwp_login_slug', 'secure-login');
    echo "<input type='text' name='drwp_login_slug' value='" . esc_attr($slug) . "' />";
    echo '<p class="description">' . __('Set a custom slug to replace wp-login.php (e.g., "my-login")', 'drwp-hide-login') . '</p>';
}

function drwp_allowed_ips_field() {
    $ips = get_option('drwp_allowed_ips', '');
    echo "<input type='text' name='drwp_allowed_ips' value='" . esc_attr($ips) . "' />";
    echo '<p class="description">' . __('Comma-separated IP addresses allowed to access login.', 'drwp-hide-login') . '</p>';
}

// Main login blocking and redirection logic
function drwp_check_login_access() {
    if (is_user_logged_in()) return;

    $slug = get_option('drwp_login_slug', 'secure-login');
    $request = trim($_SERVER['REQUEST_URI'], '/');
    $allowed_ips = array_filter(array_map('trim', explode(',', get_option('drwp_allowed_ips', ''))));
    $user_ip = $_SERVER['REMOTE_ADDR'];

    // Check IP whitelist
    if (!empty($allowed_ips) && !in_array($user_ip, $allowed_ips)) {
        status_header(403);
        exit(__('Access denied from your IP address.', 'drwp-hide-login'));
    }

    // Custom slug handling
    if ($request === $slug) {
        require_once ABSPATH . 'wp-login.php';
        exit;
    }

    // Block access to wp-login.php and wp-admin
    if (strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false || (strpos($_SERVER['REQUEST_URI'], 'wp-admin') !== false && !is_user_logged_in())) {
        wp_redirect(home_url('/404'));
        exit;
    }
}
add_action('init', 'drwp_check_login_access');

// Temporary login token system
function drwp_temp_login_request() {
    if (isset($_GET['drwp_send_login_link']) && current_user_can('manage_options') && check_admin_referer('drwp_send_login')) {
        $token = wp_generate_password(20, false);
        set_transient('drwp_token_' . $token, true, 15 * MINUTE_IN_SECONDS);
        $slug = get_option('drwp_login_slug', 'secure-login');
        $url = home_url("/$slug?token=$token");
        wp_mail(get_option('admin_email'), __('Temporary Login Link', 'drwp-hide-login'), __('Here is your login link:', 'drwp-hide-login') . "\n\n" . $url);
        wp_redirect(admin_url('options-general.php?drwp_sent=1'));
        exit;
    }
}
add_action('admin_init', 'drwp_temp_login_request');

function drwp_check_temp_token() {
    if (isset($_GET['token'])) {
        $token = sanitize_text_field($_GET['token']);
        if (get_transient('drwp_token_' . $token)) {
            delete_transient('drwp_token_' . $token);
            require_once ABSPATH . 'wp-login.php';
            exit;
        } else {
            wp_die(__('This login link is invalid or expired.', 'drwp-hide-login'));
        }
    }
}
add_action('init', 'drwp_check_temp_token');

// Add admin bar links
function drwp_admin_bar_links($admin_bar) {
    if (!current_user_can('manage_options')) return;

    $slug = get_option('drwp_login_slug', 'secure-login');
    $login_url = home_url("/$slug");

    $admin_bar->add_node([
        'id' => 'drwp_login',
        'title' => __('🔐 Login URL', 'drwp-hide-login'),
        'href' => $login_url
    ]);

    $admin_bar->add_node([
        'id' => 'drwp_send_link',
        'title' => __('📧 Send Temp Link', 'drwp-hide-login'),
        'href' => wp_nonce_url(admin_url('?drwp_send_login_link=1'), 'drwp_send_login')
    ]);
}
add_action('admin_bar_menu', 'drwp_admin_bar_links', 100);
