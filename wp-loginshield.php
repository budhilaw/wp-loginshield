<?php
/**
 * Plugin Name: WP LoginShield
 * Plugin URI: https://budhilaw.com/plugins/wp-loginshield
 * Description: Enhance WordPress security by customizing the login path, blocking brute force attacks, and monitoring login attempts.
 * Version: 1.0.3
 * Author: Ericsson Budhilaw
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
        
        // CRITICAL: Skip everything if this is not a wp-login.php request
        if (strpos($request_uri, 'wp-login.php') === false) {
            return;
        }
        
        // Check if custom login path protection is enabled - if not, allow direct access to wp-login.php
        $enable_custom_login = get_option('wp_login_shield_enable_custom_login', 1);
        if (!$enable_custom_login) {
            return; // Skip login protection if feature is disabled
        }
        
        // Early IP ban check if it's enabled in the database
        $ip_ban_enabled = get_option('wp_login_shield_enable_ip_ban', 0);
        if ($ip_ban_enabled) {
            // Get banned IPs
            $banned_ips = get_option('wp_login_shield_banned_ips', array());
            
            // Get visitor IP using various methods
            $ip_keys = array(
                'HTTP_CLIENT_IP',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED',
                'HTTP_X_CLUSTER_CLIENT_IP',
                'HTTP_FORWARDED_FOR',
                'HTTP_FORWARDED',
                'REMOTE_ADDR'
            );
            
            $visitor_ip = '';
            foreach ($ip_keys as $key) {
                if (array_key_exists($key, $_SERVER) === true) {
                    foreach (explode(',', $_SERVER[$key]) as $ip) {
                        $ip = trim($ip);
                        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                            $visitor_ip = $ip;
                            break 2;
                        }
                    }
                }
            }
            
            // Check if IP is banned
            if (!empty($visitor_ip) && isset($banned_ips[$visitor_ip])) {
                $max_attempts = get_option('wp_login_shield_max_login_attempts', 3);
                
                // First check: is this IP explicitly marked as banned?
                $explicitly_banned = isset($banned_ips[$visitor_ip]['is_banned']) && $banned_ips[$visitor_ip]['is_banned'] === true;
                
                // Second check: check attempts count
                $too_many_attempts = false;
                if (isset($banned_ips[$visitor_ip]) && isset($banned_ips[$visitor_ip]['attempts']) && is_numeric($banned_ips[$visitor_ip]['attempts']) && $banned_ips[$visitor_ip]['attempts'] >= $max_attempts) {
                    $too_many_attempts = true;
                }
                
                // Block if either explicitly banned or too many attempts
                if ($explicitly_banned || $too_many_attempts) {
                    // Block the banned IP with a 403
                    header('HTTP/1.1 403 Forbidden');
                    echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
                    echo '<h1>Access Denied</h1>';
                    echo '<p>Your IP has been temporarily banned due to too many failed login attempts.</p>';
                    echo '</body></html>';
                    exit;
                }
            }
        }
        
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
        
        // Get custom redirect slug if set, otherwise use 404
        $redirect_slug = get_option('wp_login_shield_redirect_slug', '404');
        $enable_custom_redirect = get_option('wp_login_shield_enable_custom_redirect', 0);
        
        // Check if custom redirect is enabled and a custom slug is set
        if ($enable_custom_redirect && $redirect_slug !== '404') {
            // Construct the redirect URL without WordPress functions
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
            
            // Extract the path part for WordPress installations in subdirectories
            $path_parts = explode('/', $_SERVER['SCRIPT_NAME']);
            array_pop($path_parts); // Remove the filename part
            $path = implode('/', $path_parts);
            $path = $path ? $path . '/' : '/'; // Ensure trailing slash
            
            $redirect_url = $protocol . '://' . $host . $path . $redirect_slug;
            
            header('Location: ' . $redirect_url);
            exit;
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
    
    // Execute the protection function directly, before any WordPress hooks
    wp_loginshield_protect_login();
}

define('WP_LOGINSHIELD_VERSION', '1.0.3');
define('WP_LOGINSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));

// Include the core class
require_once WP_LOGINSHIELD_PLUGIN_DIR . 'includes/class-wp-login-shield.php';

// Initialize the plugin
function run_wp_login_shield() {
    $plugin = new WP_LoginShield();
    $plugin->run();
}
run_wp_login_shield(); 