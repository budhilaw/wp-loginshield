<?php

/**
 * Monitoring Class
 * 
 * Handles access monitoring and login tracking functionality
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

class WP_LoginShield_Monitoring {

    /**
     * Max login records to keep
     *
     * @var int
     */
    protected $max_login_records = 500;

    /**
     * Login page access monitoring enabled
     *
     * @var bool
     */
    protected $login_access_monitoring_enabled = false;

    /**
     * Max login page access records to keep
     *
     * @var int
     */
    protected $max_login_access_records = 500;

    /**
     * Custom timezone for date display
     *
     * @var string
     */
    protected $timezone = '';

    /**
     * Clock style (12 or 24 hour)
     *
     * @var string
     */
    protected $time_format = '24';

    /**
     * Reference to the IP Management module
     *
     * @var WP_LoginShield_IP_Management
     */
    protected $ip_management;

    /**
     * Initialize the class
     * 
     * @param WP_LoginShield_IP_Management $ip_management IP management class instance
     */
    public function __construct($ip_management = null) {
        $this->ip_management = $ip_management;
        $this->login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        $this->max_login_records = get_option('wp_login_shield_max_login_records', 500);
        $this->max_login_access_records = get_option('wp_login_shield_max_login_access_records', 500);
        $this->timezone = get_option('wp_login_shield_timezone', '');
        $this->time_format = get_option('wp_login_shield_time_format', '24');
    }

    /**
     * Initialize hooks
     */
    public function init() {
        // Track all login attempts if enabled
        if (get_option('wp_login_shield_enable_login_tracking', 0)) {
            // Track successful logins
            add_action('wp_login', array($this, 'track_successful_login'), 10, 2);
            
            // Track failed logins (always track when login tracking is enabled)
            add_action('wp_login_failed', array($this, 'track_failed_login'));
        }
        
        // Monitor login page access if enabled
        if ($this->login_access_monitoring_enabled) {
            add_action('login_init', array($this, 'record_login_page_access'), 5);
            add_action('wp_loaded', array($this, 'check_for_login_page_access'), 5);
        }
    }

    /**
     * Format datetime with timezone support
     *
     * @param int $timestamp Unix timestamp
     * @return string Formatted datetime
     */
    public function format_datetime($timestamp) {
        if (empty($timestamp)) {
            return '';
        }
        
        // Set timezone if specified
        if (!empty($this->timezone)) {
            // Use DateTime with WordPress timezone support instead of date_default_timezone_set
            $date_obj = new DateTime();
            $date_obj->setTimestamp($timestamp);
            $date_obj->setTimezone(new DateTimeZone($this->timezone));
            
            if ($this->time_format == '12') {
                return $date_obj->format('M j, Y g:i:s A');
            } else {
                return $date_obj->format('M j, Y H:i:s');
            }
        }
        
        // Use WordPress date_i18n for localized date display with default timezone
        if ($this->time_format == '12') {
            return date_i18n('M j, Y g:i:s A', $timestamp);
        } else {
            return date_i18n('M j, Y H:i:s', $timestamp);
        }
    }

    /**
     * Track successful login attempts
     * 
     * @param string $username Username
     * @param WP_User $user User object
     */
    public function track_successful_login($username, $user) {
        // Get visitor IP and user agent
        $ip = $this->ip_management ? $this->ip_management->get_client_ip() : '';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : __('Unknown', 'wp-login-shield');
        
        if (empty($ip)) {
            $ip = __('Unknown', 'wp-login-shield');
        }
        
        // Create record data
        $data = array(
            'time' => time(),
            'ip' => $ip,
            'username' => $username,
            'status' => 'success',
            'user_agent' => $user_agent
        );
        
        // Get the tracking DB instance
        $tracking_db = new WP_LoginShield_Login_Tracking_DB();
        
        // Add the record
        $tracking_db->add_record($data);
    }

    /**
     * Track failed login attempts
     * 
     * @param string $username Username or email
     */
    public function track_failed_login($username) {
        // Get visitor IP and user agent
        $ip = $this->ip_management ? $this->ip_management->get_client_ip() : '';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : __('Unknown', 'wp-login-shield');
        
        if (empty($ip)) {
            $ip = __('Unknown', 'wp-login-shield');
        }
        
        // Create record data
        $data = array(
            'time' => time(),
            'ip' => $ip,
            'username' => $username,
            'status' => 'failed',
            'user_agent' => $user_agent
        );
        
        // Get the tracking DB instance
        $tracking_db = new WP_LoginShield_Login_Tracking_DB();
        
        // Add the record
        $tracking_db->add_record($data);
    }

    /**
     * Record login page access attempts
     */
    public function record_login_page_access() {
        try {
            if (!$this->login_access_monitoring_enabled) {
                return;
            }
            
            // Get visitor information
            $ip = $this->ip_management ? $this->ip_management->get_client_ip() : '';
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : __('Unknown', 'wp-login-shield');
            
            // Handle referrer properly
            $http_referrer = '';
            if (!isset($_SERVER['HTTP_REFERER']) || empty($_SERVER['HTTP_REFERER'])) {
                $http_referrer = 'Direct';
            } else {
                $http_referrer = $_SERVER['HTTP_REFERER'];
            }
            
            $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : __('Unknown', 'wp-login-shield');
            $request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : __('Unknown', 'wp-login-shield');
            $remote_host = isset($_SERVER['REMOTE_HOST']) ? $_SERVER['REMOTE_HOST'] : gethostbyaddr($ip);
            
            // Check if the IP is whitelisted
            $is_whitelisted = false;
            if ($this->ip_management && method_exists($this->ip_management, 'check_ip_whitelist')) {
                // This should be implemented by checking if IP is in whitelist
                // but we don't have direct access to the whitelist here
                // For now, just set to false
                $is_whitelisted = false;
            }
            
            // Get query parameters (for security analysis)
            $query_params = $_GET;
            
            // Ensure we have an array
            if (!is_array($query_params)) {
                $query_params = array();
            }
            
            // Remove sensitive data
            if (isset($query_params['pwd'])) {
                $query_params['pwd'] = '[REDACTED]';
            }
            if (isset($query_params['password'])) {
                $query_params['password'] = '[REDACTED]';
            }
            
            // Get current login access records
            $access_records = get_option('wp_login_shield_access_records', array());
            
            // Ensure access_records is an array
            if (!is_array($access_records)) {
                // If it's not an array, reset it to an empty array
                $access_records = array();
                // Also update the option to fix it for future
                update_option('wp_login_shield_access_records', array());
            }
            
            // Add new record
            $access_records[] = array(
                'time' => time(),
                'ip' => $ip,
                'user_agent' => $user_agent,
                'http_referrer' => $http_referrer,
                'request_uri' => $request_uri,
                'request_method' => $request_method,
                'remote_host' => $remote_host,
                'query_params' => json_encode($query_params),
                'is_whitelisted' => $is_whitelisted
            );
            
            // Limit the number of records we store
            if (is_array($access_records) && count($access_records) > $this->max_login_access_records) {
                $access_records = array_slice($access_records, -$this->max_login_access_records);
            }
            
            // Update the option
            update_option('wp_login_shield_access_records', $access_records);
        } catch (Exception $e) {
            // Log error if debugging is enabled
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('WP Login Shield - Error in record_login_page_access: ' . $e->getMessage());
            }
        }
    }

    /**
     * Check for login page access at wp_loaded
     * This helps catch more login page access attempts
     */
    public function check_for_login_page_access() {
        global $pagenow;
        
        // Skip if we're in admin
        if (is_admin()) {
            return;
        }
        
        $request_uri = wp_parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $request_path = trim($request_uri, '/');
        $login_path = get_option('wp_login_shield', 'login');
        
        // If accessing wp-login.php or custom login path, record it
        if ($pagenow == 'wp-login.php' || $request_path == $login_path || 
            strpos($request_uri, 'wp-login.php') !== false) {
            $this->record_login_page_access();
        }
    }
} 