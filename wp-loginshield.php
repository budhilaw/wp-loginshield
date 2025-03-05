<?php
/**
 * Plugin Name: WP LoginShield
 * Plugin URI: https://budhilaw.com/plugins/wp-loginshield
 * Description: Enhance WordPress security by customizing the login path, blocking brute force attacks, and monitoring login attempts.
 * Version: 1.0.0
 * Author: Budhilaw
 * Author URI: https://budhilaw.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-loginshield
 * Domain Path: /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

define('WP_LOGINSHIELD_VERSION', '1.0.0');
define('WP_LOGINSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));

// Include the core class
require_once WP_LOGINSHIELD_PLUGIN_DIR . 'includes/class-wp-login-shield.php';

// Initialize the plugin
function run_wp_login_shield() {
    $plugin = new WP_LoginShield();
    $plugin->run();
    
    // Add JavaScript translations for the admin
    add_action('admin_enqueue_scripts', 'wp_loginshield_localize_script');
}

/**
 * Add JavaScript translations
 */
function wp_loginshield_localize_script($hook) {
    if ('settings_page_wp-loginshield' != $hook) {
        return;
    }
    
    wp_localize_script('wp-loginshield-admin', 'wpLoginShieldAdmin', array(
        'confirmUnban' => __('Are you sure you want to unban this IP address?', 'wp-loginshield'),
        'confirmClearAll' => __('Are you sure you want to clear all IP bans? This action cannot be undone.', 'wp-loginshield'),
        'confirmClearAllAttempts' => __('Are you sure you want to clear all login attempt records? This action cannot be undone.', 'wp-loginshield')
    ));
}

run_wp_login_shield(); 