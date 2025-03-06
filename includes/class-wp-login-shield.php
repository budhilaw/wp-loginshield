<?php

/**
 * Main WP Login Shield Class
 *
 * @package    WP_LoginShield
 * @since      1.0.0
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

class WP_LoginShield {

    /**
     * The default login path
     *
     * @var string
     */
    protected $default_path = 'login';

    /**
     * Custom login path
     *
     * @var string
     */
    protected $login_path;

    /**
     * Custom timezone
     *
     * @var string
     */
    protected $timezone;

    /**
     * Time format (12 or 24)
     *
     * @var string
     */
    protected $time_format;

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
     * List of whitelisted IPs
     *
     * @var array
     */
    protected $whitelist_ips = array();
    
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
    protected $max_access_records = 1000;

    /**
     * Plugin version
     *
     * @var string
     */
    protected $version = '1.0.1';

    /**
     * Admin class instance
     *
     * @var WP_LoginShield_Admin
     */
    public $admin;

    /**
     * Protection class instance
     *
     * @var WP_LoginShield_Protection
     */
    public $protection;

    /**
     * IP Management class instance
     *
     * @var WP_LoginShield_IP_Management
     */
    public $ip_management;

    /**
     * Monitoring class instance
     *
     * @var WP_LoginShield_Monitoring
     */
    public $monitoring;

    /**
     * Constructor
     */
    public function __construct() {
        $this->login_path = get_option('wp_login_shield', $this->default_path);
        $this->timezone = get_option('wp_login_shield_timezone', '');
        $this->time_format = get_option('wp_login_shield_time_format', '24');
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->whitelist_ips = get_option('wp_login_shield_whitelist_ips', array());
        $this->login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        
        // Load required files
        $this->load_dependencies();
        
        // Initialize feature classes
        $this->initialize_classes();
    }

    /**
     * Load dependencies
     */
    private function load_dependencies() {
        // Include feature class files
        require_once plugin_dir_path(__FILE__) . 'protection/class-login-protection.php';
        require_once plugin_dir_path(__FILE__) . 'ip-management/class-ip-management.php';
        require_once plugin_dir_path(__FILE__) . 'monitoring/class-monitoring.php';
        require_once plugin_dir_path(__FILE__) . 'admin/class-admin.php';
    }

    /**
     * Initialize feature classes
     */
    private function initialize_classes() {
        // Initialize IP management
        $this->ip_management = new WP_LoginShield_IP_Management();
        
        // Initialize monitoring (passing IP management for dependency)
        $this->monitoring = new WP_LoginShield_Monitoring($this->ip_management);
        
        // Initialize protection (passing IP management and monitoring for dependencies)
        $this->protection = new WP_LoginShield_Protection($this->ip_management, $this->monitoring);
        
        // Initialize admin
        $this->admin = new WP_LoginShield_Admin($this);
    }

    /**
     * Run the plugin
     */
    public function run() {
        // Initialize admin hooks
        $this->admin->init();
        
        // Initialize protection hooks
        $this->protection->init();
        
        // Initialize IP management hooks
        $this->ip_management->init();
        
        // Initialize monitoring hooks
        $this->monitoring->init();
        
        // Handle activation
        register_activation_hook(dirname(dirname(__FILE__)) . '/wp-loginshield.php', array($this, 'activate'));
        
        // Handle deactivation
        register_deactivation_hook(dirname(dirname(__FILE__)) . '/wp-loginshield.php', array($this, 'deactivate'));
    }

    /**
     * Format datetime based on settings
     *
     * @param int $timestamp The timestamp to format
     * @return string
     */
    public function format_datetime($timestamp) {
        if (empty($timestamp)) {
            return '';
        }
        
        // Set timezone if specified in settings
        if (!empty($this->timezone)) {
            $date_obj = new DateTime();
            $date_obj->setTimestamp($timestamp);
            $date_obj->setTimezone(new DateTimeZone($this->timezone));
            
            if ($this->time_format == '12') {
                return $date_obj->format('M j, Y g:i:s A');
            } else {
                return $date_obj->format('M j, Y H:i:s');
            }
        }
        
        // Use WordPress timezone and format
        if ($this->time_format == '12') {
            return date_i18n('M j, Y g:i:s A', $timestamp);
        } else {
            return date_i18n('M j, Y H:i:s', $timestamp);
        }
    }

    /**
     * Plugin activation hook
     */
    public function activate() {
        // Add custom login path to options if not exists
        if (!get_option('wp_login_shield')) {
            add_option('wp_login_shield', $this->default_path);
        }

        // Create empty banned IPs option if not exists
        if (!get_option('wp_login_shield_banned_ips')) {
            add_option('wp_login_shield_banned_ips', array());
        }
        
        // Create empty login records option if not exists
        if (!get_option('wp_login_shield_login_records')) {
            add_option('wp_login_shield_login_records', array());
        }
        
        // Create empty access records option if not exists
        if (!get_option('wp_login_shield_access_records')) {
            add_option('wp_login_shield_access_records', array());
        }
        
        // Create empty whitelist IPs option if not exists
        if (!get_option('wp_login_shield_whitelist_ips')) {
            add_option('wp_login_shield_whitelist_ips', array());
        }
        
        // Make sure WordPress knows about the rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation hook
     */
    public function deactivate() {
        // Remove rewrite rules
        flush_rewrite_rules();
        
        // Clean up the ban_duration option since it's no longer used
        delete_option('wp_login_shield_ban_duration');
    }
} 