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
     * The redirect slug to use for blocked requests
     *
     * @var string
     */
    protected $redirect_slug = '404';

    /**
     * Whether to use custom redirect or default 404
     *
     * @var bool
     */
    protected $enable_custom_redirect = false;

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
     * Custom login enabled
     *
     * @var bool
     */
    protected $custom_login_enabled = true;

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
        $this->redirect_slug = get_option('wp_login_shield_redirect_slug', '404');
        $this->enable_custom_redirect = get_option('wp_login_shield_enable_custom_redirect', 0);
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        $this->custom_login_enabled = get_option('wp_login_shield_enable_custom_login', 1);
        
        $this->ip_management = $ip_management;
        $this->monitoring = $monitoring;
    }

    /**
     * Initialize hooks
     */
    public function init() {
        // Always add protection for unauthorized access
        add_action('plugins_loaded', array($this, 'block_wp_login'), 1);
        
        // Only add custom login URL features if enabled
        if ($this->custom_login_enabled) {
            // Filter to change login URL
            add_filter('site_url', array($this, 'change_login_url'), 10, 4);
            
            // Add rewrite rules
            add_action('init', array($this, 'add_rewrite_rules'));
        }
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
        // Don't change URL if custom login is disabled
        if (!$this->custom_login_enabled) {
            return $url;
        }
        
        if ($path == 'wp-login.php') {
            // Don't change URL if user is already logged in
            if (is_user_logged_in()) {
                return $url;
            }
            
            // Check if this is a failed login attempt (preserve wls-token)
            if (isset($_GET['wls-token']) && isset($_GET['_wpnonce'])) {
                $token = sanitize_text_field(wp_unslash($_GET['wls-token']));
                $nonce = sanitize_text_field(wp_unslash($_GET['_wpnonce']));
                if (wp_verify_nonce($nonce, 'wp_login_shield_token')) {
                    return add_query_arg(
                        array(
                            'wls-token' => $token,
                            '_wpnonce' => $nonce
                        ),
                        $url
                    );
                }
            }
            
            // Don't change URL if this is a special action like resetpass
            if (isset($_GET['action']) && in_array($_GET['action'], array('postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register'))) {
                // Verify nonce for action parameter when possible
                if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'wp_login_shield_action')) {
                    return $url;
                } else if (in_array($_GET['action'], array('logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp'))) {
                    // Standard WordPress actions might not have our nonce, so accept them but consider adding nonce verification
                    return $url;
                }
            }
            
            // Don't change URL if ?wls-token is present (indicates coming from custom login path)
            if (isset($_GET['wls-token']) && $_GET['wls-token'] == $this->login_path) {
                // Verify nonce for wls-token parameter
                if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'wp_login_shield_token')) {
                    return $url;
                }
            }
            
            return site_url($this->login_path, $scheme);
        }
        return $url;
    }

    /**
     * Block unauthorized access to wp-login.php and handle custom login path
     */
    public function block_wp_login() {
        if (!isset($_SERVER['REQUEST_URI'])) {
            return;
        }
        
        $request_uri = wp_unslash($_SERVER['REQUEST_URI']);
        $request_path = trim(parse_url($request_uri, PHP_URL_PATH), '/');
        
        // Clean up expired bans before proceeding
        if ($this->ip_management && method_exists($this->ip_management->banned_ips_db, 'cleanup_expired_bans')) {
            $this->ip_management->banned_ips_db->cleanup_expired_bans();
        }
        
        // Set up cookie parameters
        $cookie_name = 'wp_login_shield_' . COOKIEHASH;
        $cookie_expiration = HOUR_IN_SECONDS;
        
        // Handle custom login path if enabled
        if ($this->custom_login_enabled && ($request_path == $this->login_path)) {
            // Check IP whitelist if enabled
            if ($this->ip_whitelist_enabled && $this->ip_management) {
                $this->ip_management->check_ip_whitelist();
            }
            
            // Record the access attempt if monitoring is enabled
            if ($this->login_access_monitoring_enabled && $this->monitoring) {
                try {
                    $this->monitoring->record_login_page_access();
                } catch (Exception $e) {
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log('WP Login Shield - Error in monitoring: ' . $e->getMessage());
                    }
                }
            }
            
            // Set cookie and redirect to wp-login.php
            setcookie(
                $cookie_name, 
                '1', 
                time() + $cookie_expiration, 
                COOKIEPATH, 
                COOKIE_DOMAIN,
                is_ssl(),
                true
            );
            
            $nonce = wp_create_nonce('wp_login_shield_token');
            wp_safe_redirect(site_url('wp-login.php?wls-token=' . $this->login_path . '&_wpnonce=' . $nonce));
            exit;
        }
        
        // Handle direct access to wp-login.php
        if (strpos($request_uri, 'wp-login.php') !== false) {
            // Check if we should allow access
            $has_valid_token = isset($_GET['wls-token']) && $_GET['wls-token'] == $this->login_path && 
                              isset($_GET['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'wp_login_shield_token');
            $has_valid_cookie = isset($_COOKIE[$cookie_name]) && $_COOKIE[$cookie_name] == '1';
            $has_special_action = isset($_GET['action']) && in_array($_GET['action'], array('postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register'));
            
            // Allow access if using custom login and has valid token/cookie, or if it's a special action
            $allow_access = (!$this->custom_login_enabled) || ($has_valid_token || $has_valid_cookie) || $has_special_action;
            
            if (!$allow_access) {
                // Record the access attempt if monitoring is enabled
                if ($this->login_access_monitoring_enabled && $this->monitoring) {
                    try {
                        $this->monitoring->record_login_page_access();
                    } catch (Exception $e) {
                        if (defined('WP_DEBUG') && WP_DEBUG) {
                            error_log('WP Login Shield - Error in monitoring: ' . $e->getMessage());
                        }
                    }
                }
                
                // Handle redirect based on settings
                if ($this->enable_custom_redirect && $this->redirect_slug !== '404') {
                    wp_redirect(home_url($this->redirect_slug));
                } else {
                    wp_redirect(home_url('404'));
                }
                exit;
            }
            
            // Refresh cookie if access is allowed via token
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
        // Only add rewrite rule if custom login is enabled
        if ($this->custom_login_enabled) {
            add_rewrite_rule($this->login_path . '/?$', 'index.php?' . $this->login_path . '=1', 'top');
            
            // Flush rewrite rules only once after activation
            if (get_option('wp_login_shield_flush_rewrite_rules', 0) == 1) {
                flush_rewrite_rules();
                update_option('wp_login_shield_flush_rewrite_rules', 0);
            }
        }
    }
} 