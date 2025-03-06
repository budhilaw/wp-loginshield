<?php

/**
 * Login Protection Class
 * 
 * Handles all functionality related to custom login paths and redirect protection
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

class WP_LoginShield_Protection {

    /**
     * The default login path
     *
     * @var string
     */
    protected $default_path = 'login';

    /**
     * The current login path from options
     *
     * @var string
     */
    protected $login_path;

    /**
     * IP whitelist enabled
     *
     * @var bool
     */
    protected $ip_whitelist_enabled = false;

    /**
     * Login access monitoring enabled
     *
     * @var bool
     */
    protected $login_access_monitoring_enabled = false;

    /**
     * Reference to the IP Management module
     *
     * @var WP_LoginShield_IP_Management
     */
    protected $ip_management;

    /**
     * Reference to the Monitoring module
     *
     * @var WP_LoginShield_Monitoring
     */
    protected $monitoring;

    /**
     * Initialize the class
     *
     * @param WP_LoginShield_IP_Management $ip_management IP management class instance
     * @param WP_LoginShield_Monitoring $monitoring Monitoring class instance
     */
    public function __construct($ip_management = null, $monitoring = null) {
        $this->login_path = get_option('wp_login_shield', $this->default_path);
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        
        $this->ip_management = $ip_management;
        $this->monitoring = $monitoring;
    }

    /**
     * Initialize hooks
     */
    public function init() {
        // Filter to change login URL
        add_filter('site_url', array($this, 'change_login_url'), 10, 4);
        
        // Hook to block wp-login.php access
        add_action('plugins_loaded', array($this, 'block_wp_login'), 1);
        
        // Add rewrite rules
        add_action('init', array($this, 'add_rewrite_rules'));
    }

    /**
     * Change the login URL to use our custom path
     *
     * @param string $url The complete site URL including scheme and path
     * @param string $path Path relative to the site URL
     * @param string $scheme The scheme to use
     * @param int $blog_id The blog ID
     * @return string Modified URL
     */
    public function change_login_url($url, $path, $scheme, $blog_id) {
        if ($path == 'wp-login.php') {
            // Don't change URL if user is already logged in
            if (is_user_logged_in()) {
                return $url;
            }
            
            // Don't change URL if this is a special action like resetpass
            if (isset($_GET['action']) && in_array($_GET['action'], array('postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register'))) {
                return $url;
            }
            
            // Don't change URL if ?wls-token is present (indicates coming from custom login path)
            if (isset($_GET['wls-token']) && $_GET['wls-token'] == $this->login_path) {
                return $url;
            }
            
            return site_url($this->login_path, $scheme);
        }
        return $url;
    }

    /**
     * Block direct access to wp-login.php
     */
    public function block_wp_login() {
        global $pagenow;
        
        // Get request information
        $request_uri = $_SERVER['REQUEST_URI'];
        $request_path = parse_url($request_uri, PHP_URL_PATH);
        $request_path = trim($request_path, '/');
        $cookie_name = 'wp_loginshield_access';
        $cookie_expiration = 3600; // 1 hour in seconds
        
        // Skip all checks if user is already logged in and not trying to access the login page
        if (is_user_logged_in() && !strpos($request_uri, 'wp-login.php') && $request_path !== 'wp-admin' && strpos($request_path, 'wp-admin/') !== 0) {
            return;
        }
        
        // If someone is accessing the custom login path, redirect to wp-login.php with token
        if (!is_admin() && ($request_path == $this->login_path)) {
            // Check IP whitelist if enabled
            if ($this->ip_whitelist_enabled && $this->ip_management) {
                $this->ip_management->check_ip_whitelist();
            }
            
            // Record the access attempt if monitoring is enabled
            if ($this->login_access_monitoring_enabled && $this->monitoring) {
                try {
                    $this->monitoring->record_login_page_access();
                } catch (Exception $e) {
                    // Log the error but don't disrupt the user flow
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log('WP Login Shield - Error in monitoring: ' . $e->getMessage());
                    }
                }
            }
            
            // Set cookie for 1 hour to allow access to wp-login.php
            setcookie(
                $cookie_name, 
                '1', 
                time() + $cookie_expiration, 
                COOKIEPATH, 
                COOKIE_DOMAIN,
                is_ssl(),
                true
            );
            
            // Redirect to wp-login.php with token
            wp_safe_redirect(site_url('wp-login.php?wls-token=' . $this->login_path));
            exit;
        }
        
        // Handle direct access to wp-admin (redirect to 404 if not logged in)
        if ($request_path == 'wp-admin' || strpos($request_path, 'wp-admin/') === 0) {
            if (!is_user_logged_in()) {
                // Record the access attempt if monitoring is enabled
                if ($this->login_access_monitoring_enabled && $this->monitoring) {
                    try {
                        $this->monitoring->record_login_page_access();
                    } catch (Exception $e) {
                        // Log the error but don't disrupt the user flow
                        if (defined('WP_DEBUG') && WP_DEBUG) {
                            error_log('WP Login Shield - Error in monitoring: ' . $e->getMessage());
                        }
                    }
                }
                
                // Block access by redirecting to 404
                wp_redirect(home_url('404'));
                exit;
            }
        }
        
        // Handle direct access to wp-login.php
        if (strpos($request_uri, 'wp-login.php') !== false) {
            // Allow access if:
            // 1. The wls-token parameter is present and matches the login path
            // 2. The access cookie is set
            // 3. Special WordPress actions like reset password are being performed
            $has_valid_token = isset($_GET['wls-token']) && $_GET['wls-token'] == $this->login_path;
            $has_valid_cookie = isset($_COOKIE[$cookie_name]) && $_COOKIE[$cookie_name] == '1';
            $has_special_action = isset($_GET['action']) && in_array($_GET['action'], array('postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register'));
            
            if (!$has_valid_token && !$has_valid_cookie && !$has_special_action) {
                // Record the access attempt if monitoring is enabled
                if ($this->login_access_monitoring_enabled && $this->monitoring) {
                    try {
                        $this->monitoring->record_login_page_access();
                    } catch (Exception $e) {
                        // Log the error but don't disrupt the user flow
                        if (defined('WP_DEBUG') && WP_DEBUG) {
                            error_log('WP Login Shield - Error in monitoring: ' . $e->getMessage());
                        }
                    }
                }
                
                // Block access to wp-login.php
                wp_redirect(home_url('404'));
                exit;
            }
            
            // If token is present, refresh the cookie
            if ($has_valid_token) {
                setcookie(
                    $cookie_name, 
                    '1', 
                    time() + $cookie_expiration, 
                    COOKIEPATH, 
                    COOKIE_DOMAIN,
                    is_ssl(),
                    true
                );
            }
        }
    }

    /**
     * Add rewrite rules for our custom login path
     */
    public function add_rewrite_rules() {
        add_rewrite_rule($this->login_path . '/?$', 'index.php?' . $this->login_path . '=1', 'top');
        
        // Flush rewrite rules only once after activation
        if (get_option('wp_login_shield_flush_rewrite_rules', 0) == 1) {
            flush_rewrite_rules();
            update_option('wp_login_shield_flush_rewrite_rules', 0);
        }
    }
} 