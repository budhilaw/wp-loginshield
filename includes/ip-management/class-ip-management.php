<?php

/**
 * IP Management Class
 * 
 * Handles IP banning, whitelisting, and related functionality
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

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
     * Initialize the class
     */
    public function __construct() {
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->whitelist_ips = get_option('wp_login_shield_whitelist_ips', array());
        $this->max_login_attempts = get_option('wp_login_shield_max_login_attempts', 3);
    }

    /**
     * Initialize hooks
     */
    public function init() {
        // Add login failed hook if IP banning is enabled
        if (get_option('wp_login_shield_enable_ip_ban', 0)) {
            add_action('wp_login_failed', array($this, 'handle_failed_login'));
            add_filter('authenticate', array($this, 'check_banned_ip'), 1, 3);
            
            // Add additional hooks for checking banned IPs
            add_action('login_init', array($this, 'check_banned_ip'));
            add_action('admin_init', array($this, 'check_banned_ip'));
            
            // Also catch XML-RPC login attempts
            add_filter('xmlrpc_login_error', array($this, 'check_banned_ip_xmlrpc'), 10, 2);
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
                    
                    // Validate IP address - don't filter out private IPs to ensure we get the actual client IP
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
     * Handle failed login attempts
     * 
     * @param string $username The username that was used in the failed login
     */
    public function handle_failed_login($username) {
        // Get visitor IP
        $ip = $this->get_client_ip();
        
        if (empty($ip)) {
            return;
        }
        
        // Get current banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        // Make sure banned_ips is an array
        if (!is_array($banned_ips)) {
            $banned_ips = array();
        }
        
        // If IP already exists, increment attempts
        if (isset($banned_ips[$ip]) && is_array($banned_ips[$ip])) {
            // Only increment if not explicitly banned
            if (!isset($banned_ips[$ip]['is_banned']) || $banned_ips[$ip]['is_banned'] !== true) {
                $banned_ips[$ip]['attempts'] = isset($banned_ips[$ip]['attempts']) && is_numeric($banned_ips[$ip]['attempts']) 
                    ? $banned_ips[$ip]['attempts'] + 1 : 1;
                $banned_ips[$ip]['last_attempt'] = time();
                
                // Auto-set explicit ban if max attempts reached
                if ($banned_ips[$ip]['attempts'] >= $this->max_login_attempts) {
                    $banned_ips[$ip]['is_banned'] = true;
                    $banned_ips[$ip]['ban_date'] = time();
                }
            }
        } else {
            // First attempt for this IP
            $banned_ips[$ip] = array(
                'attempts' => 1,
                'last_attempt' => time()
            );
        }
        
        // Update the option
        update_option('wp_login_shield_banned_ips', $banned_ips);
    }

    /**
     * Check if the current IP is banned
     * 
     * @param null|WP_User|WP_Error $user User object or error
     * @param string $username Username
     * @return null|WP_User|WP_Error
     */
    public function check_banned_ip() {
        // Safely check if IP is banned
        try {
            if ($this->is_ip_banned()) {
                // Clear any WordPress auth cookies
                $this->clear_auth_cookies();
                
                wp_die(
                    __('Your IP has been temporarily banned due to too many failed login attempts.', 'wp-login-shield'),
                    __('Access Denied', 'wp-login-shield'),
                    array('response' => 403)
                );
            }
        } catch (Exception $e) {
            // Log the error but don't block access
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('WP Login Shield - Error checking banned IP: ' . $e->getMessage());
            }
        }
        
        return null;
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
        
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        if (!is_array($banned_ips)) {
            $banned_ips = array();
            update_option('wp_login_shield_banned_ips', $banned_ips);
            return false;
        }
        
        if (isset($banned_ips[$ip])) {
            if (!is_array($banned_ips[$ip])) {
                $banned_ips[$ip] = array();
            }
            
            // Reset attempts and remove explicit ban flag
            $banned_ips[$ip]['attempts'] = 0;
            $banned_ips[$ip]['is_banned'] = false;
            update_option('wp_login_shield_banned_ips', $banned_ips);
            return true;
        }
        return false;
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
                    __('Access Denied: Your IP address is not allowed to access this page.', 'wp-login-shield'),
                __('Access Denied', 'wp-login-shield'),
                array('response' => 403)
            );
        }
    }

    /**
     * Sanitize whitelist IPs input
     * 
     * @param string|array $input The unsanitized input
     * @return array Sanitized IPs
     */
    public function sanitize_whitelist_ips($input) {
        if (empty($input)) {
            return array();
        }
        
        if (is_string($input)) {
            $ips = preg_split('/\r\n|\r|\n/', $input);
        } else if (is_array($input)) {
            $ips = $input;
        } else {
            return array();
        }
        
        $valid_ips = array();
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid_ips[] = $ip;
            }
        }
        
        return $valid_ips;
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
        
        // Get banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        if (!is_array($banned_ips)) {
            return false;
        }
        
        // First check: is this IP explicitly banned?
        if (isset($banned_ips[$ip]) && is_array($banned_ips[$ip]) && 
            isset($banned_ips[$ip]['is_banned']) && $banned_ips[$ip]['is_banned'] === true) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('WP Login Shield - IP is explicitly banned: ' . $ip);
            }
            
            return true;
        }
        
        // Second check: does the IP have too many failed attempts?
        if (isset($banned_ips[$ip]) && is_array($banned_ips[$ip])) {
            // Check if the IP has exceeded max login attempts
            if (isset($banned_ips[$ip]['attempts']) && is_numeric($banned_ips[$ip]['attempts']) && $banned_ips[$ip]['attempts'] >= $this->max_login_attempts) {
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('WP Login Shield - IP is banned due to too many attempts: ' . $ip);
                }
                
                // IP is banned due to attempts
                return true;
            }
        }

        return false;
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

    /**
     * Ban an IP address
     * 
     * @param string $ip IP address to ban
     * @return bool True if IP was banned, false otherwise
     */
    public function ban_ip($ip) {
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Get current banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        // Set the IP as banned
        if (isset($banned_ips[$ip])) {
            // Update existing record
            $banned_ips[$ip]['is_banned'] = true;
            $banned_ips[$ip]['ban_date'] = time();
        } else {
            // Create new record
            $banned_ips[$ip] = array(
                'attempts' => $this->max_login_attempts, // Set to max to ensure it's banned
                'last_attempt' => time(),
                'is_banned' => true,
                'ban_date' => time()
            );
        }
        
        // Update the option
        update_option('wp_login_shield_banned_ips', $banned_ips);
        
        return true;
    }

    /**
     * Get all banned IPs with their information
     * 
     * @param bool $active_only Whether to return only currently active bans
     * @return array Banned IPs with their information
     */
    public function get_banned_ips($active_only = false) {
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        if (!is_array($banned_ips)) {
            return array();
        }
        
        // If we only want active bans, filter out expired ones
        if ($active_only) {
            foreach ($banned_ips as $ip => $data) {
                // Skip if not explicitly banned
                if (!isset($data['is_banned']) || $data['is_banned'] !== true) {
                    unset($banned_ips[$ip]);
                    continue;
                }
            }
        }
        
        return $banned_ips;
    }
} 