<?php
/**
 * Plugin Name: WP LoginShield
 * Plugin URI: https://budhilaw.com/plugins/wp-loginshield
 * Description: Enhance WordPress security by customizing the login path, blocking brute force attacks, and monitoring login attempts.
 * Version: 1.0.1
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

// DIRECT LOGIN PROTECTION - This must run before WordPress is fully loaded
if (!function_exists('wp_loginshield_protect_login')) {
    function wp_loginshield_protect_login() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        
        // Check if this is a direct attempt to access wp-login.php
        if (strpos($request_uri, 'wp-login.php') !== false) {
            // Skip protection for wp-cron.php, xmlrpc.php, and other WordPress system files
            if (strpos($request_uri, 'wp-cron.php') !== false || 
                strpos($request_uri, 'xmlrpc.php') !== false) {
                return;
            }
            
            // Allow special WordPress actions
            $special_actions = array('postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register');
            if (isset($_GET['action']) && in_array($_GET['action'], $special_actions)) {
                return;
            }
            
            // Check for token
            $login_path = get_option('wp_login_shield', 'login');
            if (isset($_GET['wls-token']) && $_GET['wls-token'] == $login_path) {
                return;
            }
            
            // Check for cookie
            if (isset($_COOKIE['wp_loginshield_access']) && $_COOKIE['wp_loginshield_access'] == '1') {
                return;
            }
            
            // Check if user is already logged in (via WordPress auth cookie)
            if (isset($_COOKIE[LOGGED_IN_COOKIE])) {
                return;
            }
            
            // If we get here, block access with direct redirect (no WordPress functions needed)
            header('HTTP/1.1 404 Not Found');
            header('Status: 404 Not Found');
            // Simple HTML for a 404 page
            echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>';
            echo '<h1>404 Not Found</h1><p>The page you requested could not be found.</p>';
            echo '</body></html>';
            exit;
        }
    }
    
    // Execute the protection function directly, before any WordPress hooks
    wp_loginshield_protect_login();
}

define('WP_LOGINSHIELD_VERSION', '1.0.1');
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