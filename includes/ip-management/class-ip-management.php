<?php

/**
 * IP Management Class
 * 
 * Handles IP banning, whitelisting, and related functionality
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

// Include the Banned IPs DB class
require_once plugin_dir_path(dirname(__FILE__)) . 'db/class-banned-ips-db.php';

class WP_LoginShield_IP_Management {

    /**
     * Max login attempts before banning
     *
     * @var int
     */
    protected $max_login_attempts = 3;

    /**
     * IP whitelist enabled
     *
     * @var bool
     */
    protected $ip_whitelist_enabled = false;

    /**
     * Whitelisted IPs for login page access
     *
     * @var array
     */
    protected $whitelist_ips = array();

    /**
     * Banned IPs database instance
     *
     * @var WP_LoginShield_Banned_IPs_DB
     */
    public $banned_ips_db;

    /**
     * Initialize the class
     */
    public function __construct() {
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->whitelist_ips = get_option('wp_login_shield_whitelist_ips', array());
        $this->max_login_attempts = get_option('wp_login_shield_max_login_attempts', 3);
        $this->banned_ips_db = new WP_LoginShield_Banned_IPs_DB();
    }

    /**
     * Initialize hooks
     */
    public function init() {
        // Add login failed hook if IP banning is enabled
        if (get_option('wp_login_shield_enable_ip_ban', 0)) {
            add_filter('authenticate', array($this, 'check_banned_ip'), 1, 3);
            
            // Add additional hooks for checking banned IPs
            add_action('login_init', array($this, 'check_banned_ip'));
            add_action('admin_init', array($this, 'check_banned_ip'));
            
            // Also catch XML-RPC login attempts
            add_filter('xmlrpc_login_error', array($this, 'check_banned_ip_xmlrpc'), 10, 2);

            // Schedule cleanup of expired bans
            if (!wp_next_scheduled('wp_login_shield_cleanup_expired_bans')) {
                wp_schedule_event(time(), 'hourly', 'wp_login_shield_cleanup_expired_bans');
            }
            add_action('wp_login_shield_cleanup_expired_bans', array($this, 'cleanup_expired_bans'));
        }
        
        // Check IP whitelist if enabled
        if ($this->ip_whitelist_enabled) {
            add_action('login_init', array($this, 'check_ip_whitelist'));
        }
    }

    /**
     * Get the client IP address
     * 
     * @return string IP address
     */
    public function get_client_ip() {
        // Check for CloudFlare IP
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        
        // Check standard proxy headers
        $ip_keys = array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    
                    // Validate IP address
                    if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        // Default fallback
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    /**
     * Check if the current IP is banned
     * 
     * @param null|WP_User|WP_Error $user User object or error
     * @param string $username Username
     * @return null|WP_User|WP_Error
     */
    public function check_banned_ip($user = null, $username = '') {
        // Safely check if IP is banned
        try {
            if ($this->is_ip_banned()) {
                // Clear any WordPress auth cookies
                $this->clear_auth_cookies();
                
                wp_die(
                    esc_html__('Your IP has been temporarily banned.', 'wp-login-shield'),
                    esc_html__('Access Denied', 'wp-login-shield'),
                    array('response' => 403)
                );
            }
        } catch (Exception $e) {
            // Log the error but don't block access
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('WP Login Shield - Error checking banned IP: ' . $e->getMessage());
            }
        }
        
        return $user;
    }

    /**
     * Check if an IP is banned
     * 
     * @param string $ip IP address to check. If empty, checks current visitor's IP.
     * @return bool True if IP is banned, false otherwise
     */
    public function is_ip_banned($ip = '') {
        // If no IP provided, get current visitor's IP
        if (empty($ip)) {
            $ip = $this->get_client_ip();
        }
        
        if (empty($ip)) {
            return false;
        }

        return (bool) $this->banned_ips_db->is_ip_banned($ip);
    }

    /**
     * Ban an IP address
     * 
     * @param string $ip IP address to ban
     * @param string $reason Reason for the ban
     * @param int $duration Duration in hours
     * @return bool True if IP was banned, false otherwise
     */
    public function ban_ip($ip, $reason = 'Too many failed login attempts', $duration = 24) {
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        return (bool) $this->banned_ips_db->add_banned_ip($ip, $reason, $duration);
    }

    /**
     * Unban a specific IP address
     * 
     * @param string $ip IP address to unban
     * @return bool True if IP was unbanned, false otherwise
     */
    public function unban_ip($ip) {
        if (empty($ip)) {
            return false;
        }
        
        return (bool) $this->banned_ips_db->remove_banned_ip($ip);
    }

    /**
     * Get all banned IPs with their information
     * 
     * @param bool $active_only Whether to return only currently active bans
     * @return array Banned IPs with their information
     */
    public function get_banned_ips($active_only = false) {
        return $this->banned_ips_db->get_banned_ips($active_only);
    }

    /**
     * Clean up expired bans
     */
    public function cleanup_expired_bans() {
        $this->banned_ips_db->cleanup_expired_bans();
    }

    /**
     * Handle failed login attempt
     * 
     * @param string $username Username that failed to log in
     */
    public function handle_failed_login($username) {
        $ip = $this->get_client_ip();
        
        if (empty($ip)) {
            return;
        }
        
        // Check if IP is already banned
        if ($this->is_ip_banned($ip)) {
            return;
        }
        
        // Get current failed attempts count
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        $attempts = isset($banned_ips[$ip]['attempts']) ? (int)$banned_ips[$ip]['attempts'] : 0;
        $attempts++;
        
        // Update or create the record
        if (!isset($banned_ips[$ip])) {
            $banned_ips[$ip] = array();
        }
        
        $banned_ips[$ip]['attempts'] = $attempts;
        $banned_ips[$ip]['last_attempt'] = time();
        
        // Ban if max attempts reached
        if ($attempts >= $this->max_login_attempts) {
            $this->ban_ip($ip, 'Exceeded maximum login attempts');
        }
        
        update_option('wp_login_shield_banned_ips', $banned_ips);
    }

    /**
     * Check if the visitor IP is whitelisted
     */
    public function check_ip_whitelist() {
        if (!$this->ip_whitelist_enabled) {
            return;
        }
        
        // Get visitor IP
        $ip = $this->get_client_ip();
        
        if (empty($ip)) {
            return;
        }
        
        // Convert whitelist to array if needed
        $whitelist_ips = $this->whitelist_ips;
        if (is_string($whitelist_ips)) {
            $whitelist_ips = preg_split('/\r\n|\r|\n/', $whitelist_ips);
            $whitelist_ips = array_map('trim', $whitelist_ips);
            $whitelist_ips = array_filter($whitelist_ips);
        }
        
        // If IP is not whitelisted, block
        if (!empty($whitelist_ips) && !in_array($ip, $whitelist_ips)) {
            wp_die(
                esc_html__('Access Denied: Your IP address is not allowed to access this page.', 'wp-login-shield'),
                esc_html__('Access Denied', 'wp-login-shield'),
                array('response' => 403)
            );
        }
    }

    /**
     * Clear all WordPress authentication cookies
     */
    private function clear_auth_cookies() {
        if (function_exists('wp_clear_auth_cookie')) {
            wp_clear_auth_cookie();
        }
        
        // Force expire cookies by setting their expiration in the past
        if (isset($_COOKIE[AUTH_COOKIE])) {
            setcookie(AUTH_COOKIE, ' ', time() - YEAR_IN_SECONDS, ADMIN_COOKIE_PATH, COOKIE_DOMAIN);
        }
        
        if (isset($_COOKIE[SECURE_AUTH_COOKIE])) {
            setcookie(SECURE_AUTH_COOKIE, ' ', time() - YEAR_IN_SECONDS, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, true);
        }
        
        if (isset($_COOKIE[LOGGED_IN_COOKIE])) {
            setcookie(LOGGED_IN_COOKIE, ' ', time() - YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN);
            setcookie(LOGGED_IN_COOKIE, ' ', time() - YEAR_IN_SECONDS, SITECOOKIEPATH, COOKIE_DOMAIN);
        }
        
        // Clear any custom plugin cookies
        setcookie('wp_loginshield_access', ' ', time() - YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN);
    }
} 