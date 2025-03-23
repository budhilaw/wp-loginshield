<?php

// Include the Login Tracking DB class
require_once plugin_dir_path(dirname(__FILE__)) . 'db/class-login-tracking-db.php';

/**
 * Admin Class
 * 
 * Handles all admin interface, settings pages, and options
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

class WP_LoginShield_Admin {

    /**
     * Plugin name
     *
     * @var string
     */
    protected $plugin_name = 'WP Login Shield';

    /**
     * Plugin version
     *
     * @var string
     */
    protected $version = '1.0.4';

    /**
     * Default timezone
     *
     * @var string
     */
    protected $default_timezone = '';

    /**
     * Default time format
     *
     * @var string
     */
    protected $default_time_format = '24';

    /**
     * The plugin's main instance
     *
     * @var WP_LoginShield
     */
    protected $plugin;

    /**
     * Constructor
     *
     * @param WP_LoginShield $plugin Main plugin instance
     */
    public function __construct($plugin) {
        $this->plugin = $plugin;
    }

    /**
     * Initialize admin functionality
     */
    public function init() {
        // Add admin page
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Enqueue admin scripts
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }

    /**
     * Add plugin menu items to admin dashboard
     */
    public function add_admin_menu() {
        add_menu_page(
            $this->plugin_name, 
            $this->plugin_name, 
            'manage_options', 
            'wp-login-shield', 
            array($this, 'display_settings_page'), 
            'dashicons-shield'
        );
        add_submenu_page('wp-login-shield', 'Settings', 'Settings', 'manage_options', 'wp-login-shield', array($this, 'display_settings_page'));
        
        // Only add Banned IPs page if the IP ban feature is enabled
        $ip_ban_enabled = get_option('wp_login_shield_enable_ip_ban', 0);
        if ($ip_ban_enabled) {
            add_submenu_page('wp-login-shield', 'Banned IPs', 'Banned IPs', 'manage_options', 'wp-login-shield-banned', array($this, 'display_banned_ips_page'));
        }
        
        // Only add Login Tracking page if the login tracking feature is enabled
        $login_tracking_enabled = get_option('wp_login_shield_enable_login_tracking', 0);
        if ($login_tracking_enabled) {
            add_submenu_page('wp-login-shield', 'Login Tracking', 'Login Tracking', 'manage_options', 'wp-login-shield-tracking', array($this, 'display_login_tracking_page'));
        }
        
        // Only add Access Monitoring page if the feature is enabled
        $login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        if ($login_access_monitoring_enabled) {
            add_submenu_page('wp-login-shield', 'Access Monitoring', 'Access Monitoring', 'manage_options', 'wp-login-shield-monitoring', array($this, 'display_access_monitoring_page'));
        }
        
        add_submenu_page('wp-login-shield', 'About', 'About', 'manage_options', 'wp-login-shield-about', array($this, 'display_about_page'));
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield', 
            array(
                'sanitize_callback' => array($this, 'sanitize_login_path'),
                'type' => 'string'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_custom_login', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_ip_ban', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_login_tracking', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_timezone', 
            array(
                'sanitize_callback' => 'sanitize_text_field',
                'type' => 'string'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_time_format', 
            array(
                'sanitize_callback' => 'sanitize_text_field',
                'type' => 'string'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_ip_whitelist', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_whitelist_ips', 
            array(
                'sanitize_callback' => array($this, 'sanitize_whitelist_ips'),
                'type' => 'array'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_login_access_monitoring', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_max_login_attempts', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'integer'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_redirect_slug', 
            array(
                'sanitize_callback' => array($this, 'sanitize_redirect_slug'),
                'type' => 'string'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_custom_redirect', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_logout_redirect_slug', 
            array(
                'sanitize_callback' => array($this, 'sanitize_redirect_slug'),
                'type' => 'string'
            )
        );
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_enable_logout_redirect', 
            array(
                'sanitize_callback' => 'intval',
                'type' => 'boolean'
            )
        );
        
        // Cookie lifespan setting
        register_setting(
            'wp_login_shield_settings', 
            'wp_login_shield_cookie_lifespan', 
            array(
                'sanitize_callback' => 'sanitize_text_field',
                'type' => 'string'
            )
        );
        
        add_settings_section(
            'wp_login_shield_section',
            'Login Protection Settings',
            array($this, 'settings_section_callback'),
            'wp_login_shield_settings'
        );
        
        add_settings_field(
            'wp_login_shield',
            'Custom Login Path',
            array($this, 'login_path_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield')
        );
        
        add_settings_field(
            'wp_login_shield_redirect_settings',
            'Redirect Settings',
            array($this, 'redirect_settings_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_redirect_slug')
        );
        
        add_settings_field(
            'wp_login_shield_enable_ip_ban',
            'IP Banning',
            array($this, 'ip_ban_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_enable_ip_ban')
        );
        
        add_settings_field(
            'wp_login_shield_enable_login_tracking',
            'Login Tracking',
            array($this, 'login_tracking_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_enable_login_tracking')
        );
        
        add_settings_field(
            'wp_login_shield_timezone',
            'Timezone',
            array($this, 'timezone_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_timezone')
        );
        
        add_settings_field(
            'wp_login_shield_time_format',
            'Time Format',
            array($this, 'time_format_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_time_format')
        );
        
        add_settings_field(
            'wp_login_shield_enable_ip_whitelist',
            'IP Whitelist',
            array($this, 'ip_whitelist_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_enable_ip_whitelist')
        );
        
        add_settings_field(
            'wp_login_shield_enable_login_access_monitoring',
            'Login Access Monitoring',
            array($this, 'login_access_monitoring_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_enable_login_access_monitoring')
        );
        
        // Add cookie lifespan field
        add_settings_field(
            'wp_login_shield_cookie_lifespan',
            'Cookie Lifespan',
            array($this, 'cookie_lifespan_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section',
            array('label_for' => 'wp_login_shield_cookie_lifespan')
        );
    }

    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        echo '<p>Configure your login protection settings below:</p>';
    }

    /**
     * Login path field callback
     */
    public function login_path_field_callback() {
        $login_path = get_option('wp_login_shield', 'login');
        $enable_custom_login = get_option('wp_login_shield_enable_custom_login', 1);
        ?>
        <label>
            <input type="checkbox" name="wp_login_shield_enable_custom_login" value="1" <?php checked($enable_custom_login, 1); ?>>
            Enable custom login path
        </label>
        <p>
            <input type="text" name="wp_login_shield" value="<?php echo esc_attr($login_path); ?>" class="regular-text" <?php disabled($enable_custom_login, 0); ?>>
        </p>
        <p class="description">
            When enabled, the standard wp-login.php page will be protected. Enter the custom path for the login page (e.g., "secret-login" would make your login page <?php echo esc_html(site_url('/secret-login')); ?>)
        </p>
        <?php
    }

    /**
     * Redirect settings field callback
     */
    public function redirect_settings_field_callback() {
        $redirect_slug = get_option('wp_login_shield_redirect_slug', '404');
        $enable_custom_redirect = get_option('wp_login_shield_enable_custom_redirect', 0);
        $enable_custom_login = get_option('wp_login_shield_enable_custom_login', 1);
        $logout_redirect_slug = get_option('wp_login_shield_logout_redirect_slug', '');
        $enable_logout_redirect = get_option('wp_login_shield_enable_logout_redirect', 0);
        ?>
        <div class="redirect-settings">
            <h4 style="margin-top: 0px !important; padding-top: 0px !important;">Blocked Access Redirect</h4>
            <label>
                <input type="checkbox" name="wp_login_shield_enable_custom_redirect" value="1" <?php checked($enable_custom_redirect, 1); ?> <?php disabled($enable_custom_login, 0); ?>>
                Enable custom redirect for unauthorized login attempts
            </label>
            <p>
                <label for="wp_login_shield_redirect_slug">Redirect Slug:</label>
                <input type="text" id="wp_login_shield_redirect_slug" name="wp_login_shield_redirect_slug" value="<?php echo esc_attr($redirect_slug); ?>" class="regular-text" <?php disabled(($enable_custom_login && $enable_custom_redirect) ? 0 : 1, 1); ?>>
            </p>
            <p class="description">
                Enter the slug for where users should be redirected when they try to access wp-login.php directly.<br>
                Default is "404" which shows a 404 page. You can enter a post or page slug (e.g., "no-access") to redirect to that content instead.<br>
                When custom redirect is disabled, users will see a standard 404 page.
            </p>

            <h4 style="margin-top: 20px;">Logout Redirect</h4>
            <label>
                <input type="checkbox" name="wp_login_shield_enable_logout_redirect" value="1" <?php checked($enable_logout_redirect, 1); ?> <?php disabled($enable_custom_login, 0); ?>>
                Enable custom redirect after logout
            </label>
            <p>
                <label for="wp_login_shield_logout_redirect_slug">Logout Redirect Slug:</label>
                <input type="text" id="wp_login_shield_logout_redirect_slug" name="wp_login_shield_logout_redirect_slug" value="<?php echo esc_attr($logout_redirect_slug); ?>" class="regular-text" <?php disabled(($enable_custom_login && $enable_logout_redirect) ? 0 : 1, 1); ?>>
            </p>
            <p class="description">
                Enter the slug for where users should be redirected after logging out.<br>
                You can enter a post or page slug (e.g., "thank-you" or "home") to redirect to that content after logout.
            </p>
        </div>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Handle enable/disable of redirect slug fields based on checkbox states
                $('input[name="wp_login_shield_enable_custom_redirect"]').on('change', function() {
                    $('#wp_login_shield_redirect_slug').prop('disabled', !this.checked);
                });
                
                $('input[name="wp_login_shield_enable_logout_redirect"]').on('change', function() {
                    $('#wp_login_shield_logout_redirect_slug').prop('disabled', !this.checked);
                });
                
                // Handle enable/disable of both redirect options based on custom login state
                $('input[name="wp_login_shield_enable_custom_login"]').on('change', function() {
                    var enabled = this.checked;
                    $('input[name="wp_login_shield_enable_custom_redirect"]').prop('disabled', !enabled);
                    $('input[name="wp_login_shield_enable_logout_redirect"]').prop('disabled', !enabled);
                    $('#wp_login_shield_redirect_slug').prop('disabled', !enabled || !$('input[name="wp_login_shield_enable_custom_redirect"]').prop('checked'));
                    $('#wp_login_shield_logout_redirect_slug').prop('disabled', !enabled || !$('input[name="wp_login_shield_enable_logout_redirect"]').prop('checked'));
                });
            });
        </script>
        <?php
    }

    /**
     * IP ban field callback
     */
    public function ip_ban_field_callback() {
        $ip_ban_enabled = get_option('wp_login_shield_enable_ip_ban', 0);
        $max_login_attempts = get_option('wp_login_shield_max_login_attempts', 3);
        ?>
        <label>
            <input type="checkbox" name="wp_login_shield_enable_ip_ban" value="1" <?php checked($ip_ban_enabled, 1); ?>>
            Automatically ban IP addresses after too many failed login attempts
        </label>
        <p>
            <label for="wp_login_shield_max_login_attempts">Max failed login attempts before ban:</label>
            <input type="number" name="wp_login_shield_max_login_attempts" id="wp_login_shield_max_login_attempts" min="1" max="10" value="<?php echo intval($max_login_attempts); ?>" style="width: 60px;">
        </p>
        <p class="description">
            When enabled, IP addresses with too many failed login attempts will be banned from accessing your login page.
        </p>
        <?php
    }

    /**
     * Login tracking field callback
     */
    public function login_tracking_field_callback() {
        $login_tracking_enabled = get_option('wp_login_shield_enable_login_tracking', 0);
        ?>
        <label>
            <input type="checkbox" name="wp_login_shield_enable_login_tracking" value="1" <?php checked($login_tracking_enabled, 1); ?>>
            Enable tracking of all login attempts
        </label>
        <p class="description">
            When enabled, all login attempts (successful and failed) will be tracked and available for review.
        </p>
        <?php
    }

    /**
     * Timezone field callback
     */
    public function timezone_field_callback() {
        $timezone = get_option('wp_login_shield_timezone', '');
        $timezone_list = timezone_identifiers_list();
        
        echo '<select name="wp_login_shield_timezone" id="wp_login_shield_timezone">';
        echo '<option value="">WordPress Default</option>';
        
        foreach ($timezone_list as $tz) {
            $selected = ($timezone == $tz) ? ' selected="selected"' : '';
            echo '<option value="' . esc_attr($tz) . '"' . esc_attr($selected) . '>' . esc_html($tz) . '</option>';
        }
        
        echo '</select>';
        echo '<p class="description">Select the timezone for displaying timestamps in the plugin.</p>';
    }

    /**
     * Time format field callback
     */
    public function time_format_field_callback() {
        $time_format = get_option('wp_login_shield_time_format', '24');
        ?>
        <label>
            <input type="radio" name="wp_login_shield_time_format" value="12" <?php checked($time_format, '12'); ?>>
            12-hour format (e.g., 3:45 PM)
        </label><br>
        <label>
            <input type="radio" name="wp_login_shield_time_format" value="24" <?php checked($time_format, '24'); ?>>
            24-hour format (e.g., 15:45)
        </label>
        <?php
    }

    /**
     * IP whitelist field callback
     */
    public function ip_whitelist_field_callback() {
        $ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $whitelist_ips = get_option('wp_login_shield_whitelist_ips', array());
        
        if (is_array($whitelist_ips)) {
            $whitelist_ips_text = implode("\n", $whitelist_ips);
        } else {
            $whitelist_ips_text = '';
        }
        ?>
        <label>
            <input type="checkbox" name="wp_login_shield_enable_ip_whitelist" value="1" <?php checked($ip_whitelist_enabled, 1); ?>>
            Enable IP whitelist for login page access
        </label>
        <p class="description">
            When enabled, only the IP addresses listed below will be able to access the login page.
        </p>
        <p>
            <textarea name="wp_login_shield_whitelist_ips" rows="5" cols="40" class="large-text code"><?php echo esc_textarea($whitelist_ips_text); ?></textarea>
        </p>
        <p class="description">
            Enter one IP address per line. Both IPv4 and IPv6 are supported.
        </p>
        <?php
    }

    /**
     * Login access monitoring field callback
     */
    public function login_access_monitoring_field_callback() {
        $login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        ?>
        <label>
            <input type="checkbox" name="wp_login_shield_enable_login_access_monitoring" value="1" <?php checked($login_access_monitoring_enabled, 1); ?>>
            Enable monitoring of all login page access attempts
        </label>
        <p class="description">
            When enabled, all attempts to access your login page will be recorded, even if they don't attempt to log in.
        </p>
        <?php
    }

    /**
     * Cookie lifespan field callback
     */
    public function cookie_lifespan_field_callback() {
        $cookie_lifespan = get_option('wp_login_shield_cookie_lifespan', '24');
        
        // Define the lifespan options (in hours)
        $lifespan_options = array(
            '1' => '1 Hour',
            '24' => '24 Hours (1 Day)',
            '72' => '72 Hours (3 Days)',
            '168' => '168 Hours (1 Week)',
            '720' => '720 Hours (30 Days/1 Month)'
        );
        ?>
        <select name="wp_login_shield_cookie_lifespan" id="wp_login_shield_cookie_lifespan">
            <?php foreach ($lifespan_options as $value => $label) : ?>
                <option value="<?php echo esc_attr($value); ?>" <?php selected($cookie_lifespan, $value); ?>><?php echo esc_html($label); ?></option>
            <?php endforeach; ?>
        </select>
        <p class="description">
            Choose how long the login cookie should remain valid after accessing the custom login page.
        </p>
        <?php
    }

    /**
     * Update login path settings and handle custom login changes
     *
     * @param string $input The login path input value
     * @return string The sanitized login path
     */
    public function sanitize_login_path($input) {
        // Add nonce verification
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'wp_login_shield_settings-options')) {
            add_settings_error('wp_login_shield', 'nonce_error', __('Security check failed. Please try again.', 'wp-login-shield'), 'error');
            return get_option('wp_login_shield');
        }
        
        // Get the current login path for comparison
        $old_login_path = get_option('wp_login_shield', 'login');
        
        // Check if the custom login enable/disable setting was changed
        $old_enable_custom_login = get_option('wp_login_shield_enable_custom_login', 1);
        $new_enable_custom_login = isset($_POST['wp_login_shield_enable_custom_login']) ? 1 : 0;
        
        // Trim whitespace
        $input = trim($input);
        
        // Replace any non-alphanumeric characters (except dash and underscore) with nothing
        $sanitized_input = preg_replace('/[^a-zA-Z0-9\-\_]/', '', $input);
        
        // Fallback to default if empty
        if (empty($sanitized_input)) {
            $sanitized_input = 'login';
            add_settings_error(
                'wp_login_shield',
                'wp_login_shield_error',
                'Login path cannot be empty. Reset to default "login".',
                'error'
            );
        }
        
        // Check for reserved WordPress terms
        $reserved_terms = array(
            'wp-admin', 'admin', 'login', 'wp-login', 'wordpress', 'wp-content',
            'wp-includes', 'wp-json', 'index', 'feed', 'rss', 'feed', 'category',
            'tag', 'post', 'page', 'comment'
        );
        
        if (in_array(strtolower($sanitized_input), $reserved_terms)) {
            add_settings_error(
                'wp_login_shield',
                'wp_login_shield_error',
                'The login path cannot be a reserved WordPress term. Please choose a different path.',
                'error'
            );
            
            // Return the previously saved value
            return $old_login_path;
        }
        
        // Schedule a rewrite rules flush if login path changed or custom login setting changed
        if ($sanitized_input !== $old_login_path || $old_enable_custom_login !== $new_enable_custom_login) {
            update_option('wp_login_shield_flush_rewrite_rules', 1);
        }
        
        return $sanitized_input;
    }

    /**
     * Sanitize whitelist IPs
     *
     * @param string $input The whitelist IPs input
     * @return array Sanitized whitelist IPs
     */
    public function sanitize_whitelist_ips($input) {
        // If empty, return empty array
        if (empty($input)) {
            return array();
        }
        
        // Split input by newline
        $ips = explode("\n", $input);
        
        // Sanitize and validate each IP
        $valid_ips = array();
        foreach ($ips as $ip) {
            $ip = trim($ip);
            
            if (empty($ip)) {
                continue;
            }
            
            // Validate IPv4 or IPv6
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid_ips[] = $ip;
            }
        }
        
        return $valid_ips;
    }

    /**
     * Sanitize redirect slug
     */
    public function sanitize_redirect_slug($input) {
        // Clean the input
        $sanitized_input = sanitize_title($input);
        
        // If empty, use the default
        if (empty($sanitized_input)) {
            return '404';
        }
        
        return $sanitized_input;
    }

    /**
     * Enqueue admin scripts
     *
     * @param string $hook The current admin page
     */
    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'wp-login-shield') === false) {
            return;
        }
        
        wp_enqueue_script(
            'wp-login-shield-admin-js',
            plugins_url('/admin/js/wp-login-shield-admin.js', dirname(dirname(__FILE__))),
            array('jquery'),
            $this->version,
            true
        );
        
        wp_enqueue_style(
            'wp-login-shield-admin-css',
            plugins_url('/admin/css/wp-login-shield-admin.css', dirname(dirname(__FILE__))),
            array(),
            $this->version
        );
        
        // Enqueue dashboard CSS for admin pages
        wp_enqueue_style(
            'wp-login-shield-dashboard-css',
            plugins_url('/admin/css/wpls-dashboard.css', dirname(dirname(__FILE__))),
            array('wp-login-shield-admin-css'),
            $this->version
        );
    }

    /**
     * Display settings page
     */
    public function display_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        ?>
        <div class="wrap wp-login-shield-settings-page">
            <h1><?php echo esc_html($this->plugin_name); ?> Settings</h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('wp_login_shield_settings'); ?>
                
                <div class="wp-login-shield-card">
                    <div class="wp-login-shield-card-header">
                        <h2><span class="dashicons dashicons-shield"></span> Login Protection Settings</h2>
                        <button type="button" class="handlediv" aria-expanded="true">
                            <span class="screen-reader-text">Toggle panel</span>
                            <span class="toggle-indicator" aria-hidden="true"></span>
                        </button>
                    </div>
                    
                    <div class="wp-login-shield-card-body">
                        <p class="description">Configure your login protection settings below:</p>
                        
                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row">Custom Login Path</th>
                                <td>
                                    <?php $this->login_path_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Redirect Settings</th>
                                <td>
                                    <?php $this->redirect_settings_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">IP Banning</th>
                                <td>
                                    <?php $this->ip_ban_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Login Tracking</th>
                                <td>
                                    <?php $this->login_tracking_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Timezone</th>
                                <td>
                                    <?php $this->timezone_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Time Format</th>
                                <td>
                                    <?php $this->time_format_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">IP Whitelist</th>
                                <td>
                                    <?php $this->ip_whitelist_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Login Access Monitoring</th>
                                <td>
                                    <?php $this->login_access_monitoring_field_callback(); ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">Cookie Lifespan</th>
                                <td>
                                    <?php $this->cookie_lifespan_field_callback(); ?>
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>
                
                <?php submit_button(); ?>
            </form>
            
            <div class="wp-login-shield-footer">
                <?php echo esc_html($this->plugin_name); ?> v<?php echo esc_html($this->version); ?> | Developed by <a href="https://budhilaw.com" target="_blank">Ericsson Budhilaw</a>
            </div>
        </div>
        
        <script>
            jQuery(document).ready(function($) {
                // Handle collapsible panels
                $('.handlediv').on('click', function() {
                    var $button = $(this);
                    var $card = $button.closest('.wp-login-shield-card');
                    var $body = $card.find('.wp-login-shield-card-body');
                    var isExpanded = $button.attr('aria-expanded') === 'true';
                    
                    // Toggle body visibility
                    $body.toggleClass('closed');
                    
                    // Update aria-expanded attribute
                    $button.attr('aria-expanded', !isExpanded);
                    
                    // Update toggle indicator
                    $button.find('.toggle-indicator').css('transform', isExpanded ? 'rotate(180deg)' : 'rotate(0deg)');
                    
                    // Store state in localStorage
                    try {
                        var key = 'wpls_settings_card';
                        localStorage.setItem(key, isExpanded ? '0' : '1');
                    } catch (e) {
                        // Local storage might not be available
                        console.log('LocalStorage not available');
                    }
                });
                
                // Apply initial states on page load
                $('.wp-login-shield-card').each(function() {
                    var $card = $(this);
                    var $body = $card.find('.wp-login-shield-card-body');
                    var $button = $card.find('.handlediv');
                    
                    try {
                        var key = 'wpls_settings_card';
                        var savedState = localStorage.getItem(key);
                        
                        if (savedState === '0') {
                            $body.addClass('closed');
                            $button.attr('aria-expanded', 'false');
                            $button.find('.toggle-indicator').css('transform', 'rotate(180deg)');
                        }
                    } catch (e) {
                        // Local storage might not be available
                        console.log('LocalStorage not available for reading');
                    }
                });
            });
        </script>
        <?php
    }

    /**
     * Display banned IPs page
     */
    public function display_banned_ips_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $ban_message = '';
        $ban_error = '';
        
        // Handle ban IP form submission
        if (isset($_POST['wp_login_shield_ban_ip']) && isset($_POST['_wpnonce']) && current_user_can('manage_options')) {
            $nonce = sanitize_text_field(wp_unslash($_POST['_wpnonce']));
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_ban_ip')) {
                $ip_to_ban = isset($_POST['ip_address']) ? sanitize_text_field(wp_unslash($_POST['ip_address'])) : '';
                $ban_duration = isset($_POST['ban_duration']) ? absint($_POST['ban_duration']) : 24;
                $ban_reason = isset($_POST['ban_reason']) ? sanitize_text_field(wp_unslash($_POST['ban_reason'])) : 'Manual ban by administrator';
                
                // Validate IP address
                if (empty($ip_to_ban)) {
                    $ban_error = 'Please enter an IP address.';
                } elseif (!filter_var($ip_to_ban, FILTER_VALIDATE_IP)) {
                    $ban_error = 'Please enter a valid IP address.';
                } elseif ($ban_duration < 1 || $ban_duration > 720) {
                    $ban_error = 'Ban duration must be between 1 and 720 hours.';
                } else {
                    // Ban the IP
                    if (isset($this->plugin) && isset($this->plugin->ip_management) && method_exists($this->plugin->ip_management, 'ban_ip')) {
                        $this->plugin->ip_management->ban_ip($ip_to_ban, $ban_reason, $ban_duration);
                        $ban_message = 'IP address ' . esc_html($ip_to_ban) . ' has been banned for ' . esc_html($ban_duration) . ' hours.';
                    } else {
                        $ban_error = 'Could not ban IP address. IP Management module not available.';
                    }
                }
            }
        }
        
        // Handle unban IP
        if (isset($_GET['action']) && $_GET['action'] === 'unban' && isset($_GET['ip']) && isset($_GET['_wpnonce'])) {
            $nonce = sanitize_text_field(wp_unslash($_GET['_wpnonce']));
            $ip = sanitize_text_field(wp_unslash($_GET['ip']));
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_unban_ip_' . $ip)) {
                if (isset($this->plugin) && isset($this->plugin->ip_management) && method_exists($this->plugin->ip_management, 'unban_ip')) {
                    $this->plugin->ip_management->unban_ip($ip);
                    $ban_message = 'IP address ' . esc_html($ip) . ' has been unbanned.';
                } else {
                    $ban_error = 'Could not unban IP address. IP Management module not available.';
                }
            }
        }
        
        // Get banned IPs
        $banned_ips = array();
        if (isset($this->plugin) && isset($this->plugin->ip_management) && method_exists($this->plugin->ip_management, 'get_banned_ips')) {
            $banned_ips = $this->plugin->ip_management->get_banned_ips(true);
        }
        ?>
        <div class="wrap wp-login-shield-banned-page">
            <h1>WP Login Shield - Banned IPs</h1>
            
            <?php if (!empty($ban_message)): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html($ban_message); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($ban_error)): ?>
                <div class="notice notice-error is-dismissible">
                    <p><?php echo esc_html($ban_error); ?></p>
                </div>
            <?php endif; ?>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-shield"></span> Ban an IP Address</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="toggle-indicator" aria-hidden="false"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <p>Enter an IP address to ban it from accessing your login page.</p>
                    
                    <form method="post" action="">
                        <?php wp_nonce_field('wp_login_shield_ban_ip'); ?>
                        <div class="form-fields">
                            <div class="field-group ip-input-group">
                                <label for="ip_address">IP Address</label>
                                <input type="text" id="ip_address" name="ip_address" placeholder="e.g., 192.168.1.1" required>
                            </div>
                            <div class="field-group">
                                <label for="ban_duration">Ban Duration (hours)</label>
                                <input type="number" id="ban_duration" name="ban_duration" value="24" min="1" max="720">
                            </div>
                            <div class="field-group">
                                <label for="ban_reason">Reason</label>
                                <input type="text" id="ban_reason" name="ban_reason" placeholder="Reason for ban">
                            </div>
                            <div class="field-group submit-group">
                                <button type="submit" name="wp_login_shield_ban_ip" class="button button-primary ban-button">Ban IP Address</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-list-view"></span> Currently Banned IPs</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="toggle-indicator" aria-hidden="false"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <p>The following IP addresses are currently banned from logging into your site:</p>
                    
                    <table class="widefat striped">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Ban Date</th>
                                <th>Expires</th>
                                <th>Reason</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($banned_ips)): ?>
                                <tr>
                                    <td colspan="5">No IP addresses are currently banned.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($banned_ips as $record): 
                                    $banned_at = strtotime($record['banned_at']);
                                    $banned_until = strtotime($record['banned_until']);
                                ?>
                                    <tr>
                                        <td><?php echo esc_html($record['ip_address']); ?></td>
                                        <td><?php echo esc_html($this->plugin->format_datetime($banned_at)); ?></td>
                                        <td><?php echo esc_html($this->plugin->format_datetime($banned_until)); ?></td>
                                        <td><?php echo esc_html($record['reason']); ?></td>
                                        <td>
                                            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('action' => 'unban', 'ip' => $record['ip_address']), admin_url('admin.php?page=wp-login-shield-banned')), 'wp_login_shield_unban_ip_' . $record['ip_address'])); ?>" class="button button-small button-unban">Unban</a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <?php $this->display_footer_note(); ?>
        </div>
        
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Ensure toggle buttons are always visible and working
                $('.wp-login-shield-card-header .handlediv').css('display', 'inline-block');
                
                // Direct toggle for card bodies
                $('.wp-login-shield-card-header .handlediv').on('click', function() {
                    var $card = $(this).closest('.wp-login-shield-card');
                    var $body = $card.find('.wp-login-shield-card-body');
                    $body.slideToggle(200);
                    
                    var isVisible = $body.is(':visible');
                    $(this).attr('aria-expanded', isVisible ? 'true' : 'false');
                    
                    // Store state in localStorage
                    try {
                        localStorage.setItem('wpls_banned_card_' + $('.wp-login-shield-card').index($card), isVisible ? '1' : '0');
                    } catch(e) {}
                });
                
                // Force both panels to be open initially, overriding any saved state
                $('.wp-login-shield-card').each(function() {
                    var $card = $(this);
                    var $body = $card.find('.wp-login-shield-card-body');
                    var $button = $card.find('.handlediv');
                    
                    // Force show
                    $body.show();
                    $button.attr('aria-expanded', 'true');
                    
                    // Clear saved state so it's open by default next time too
                    try {
                        var index = $('.wp-login-shield-card').index($card);
                        localStorage.setItem('wpls_banned_card_' + index, '1');
                    } catch(e) {}
                });
            });
        </script>
        <?php
    }

    /**
     * Display login tracking page with a card-based UI like the Access Monitoring and Banned IPs pages
     */
    public function display_login_tracking_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $message = '';
        $error = '';
        
        // Handle clear login attempts action
        if (isset($_POST['wp_login_shield_clear_login_attempts']) && isset($_POST['_wpnonce']) && current_user_can('manage_options')) {
            $nonce = sanitize_text_field(wp_unslash($_POST['_wpnonce']));
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_clear_login_attempts')) {
                $tracking_db = new WP_LoginShield_Login_Tracking_DB();
                $tracking_db->clear_all_records();
                $message = 'Login attempts have been cleared successfully.';
            } else {
                $error = 'Security check failed. Please try again.';
            }
        }
        
        // Get tracking DB instance
        $tracking_db = new WP_LoginShield_Login_Tracking_DB();
        
        // Prepare pagination
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval(wp_unslash($_GET['paged']))) : 1;
        $total_items = $tracking_db->get_total_records();
        $total_pages = ceil($total_items / $per_page);
        
        // Get current page items
        $records = $tracking_db->get_records($per_page, $current_page);
        ?>
        <div class="wrap wp-login-shield-banned-page">
            <h1>Login Tracking</h1>
            
            <?php if (!empty($message)): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html($message); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($error)): ?>
                <div class="notice notice-error is-dismissible">
                    <p><?php echo esc_html($error); ?></p>
                </div>
            <?php endif; ?>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-chart-bar"></span> Login Tracking Tools</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="screen-reader-text">Toggle panel</span>
                        <span class="toggle-indicator" aria-hidden="true"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <p>Manage your login attempts data:</p>
                    <form method="post" action="" style="display: inline-block;">
                        <?php wp_nonce_field('wp_login_shield_clear_login_attempts'); ?>
                        <button type="submit" name="wp_login_shield_clear_login_attempts" class="button button-secondary" onclick="return confirm('Are you sure you want to clear all login attempts? This cannot be undone.');">
                            <span class="dashicons dashicons-trash" style="margin-top: 3px; margin-right: 5px;"></span>
                            Clear All Login Attempts
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-list-view"></span> Recent Login Attempts</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="screen-reader-text">Toggle panel</span>
                        <span class="toggle-indicator" aria-hidden="true"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <table class="widefat login-attempts-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Username</th>
                                <th>Status</th>
                                <th>IP Address</th>
                                <th>User Agent</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            if (empty($records)) {
                                echo '<tr><td colspan="5">No login attempts recorded yet.</td></tr>';
                            } else {
                                foreach ($records as $record) {
                                    $status_class = ($record['status'] === 'success') ? 'login-success' : 'login-failed';
                                    $status_text = ($record['status'] === 'success') ? 'Success' : 'Failed';
                                    
                                    echo '<tr>';
                                    echo '<td>' . esc_html($this->plugin->format_datetime(strtotime($record['time']))) . '</td>';
                                    echo '<td>' . esc_html($record['username']) . '</td>';
                                    echo '<td><span class="' . esc_attr($status_class) . '">' . esc_html($status_text) . '</span></td>';
                                    echo '<td>' . esc_html($record['ip']) . '</td>';
                                    echo '<td class="user-agent-cell">' . esc_html($record['user_agent']) . '</td>';
                                    echo '</tr>';
                                }
                            }
                            ?>
                        </tbody>
                    </table>
                    
                    <?php if ($total_pages > 1): ?>
                    <div class="pagination-wrapper">
                        <div class="pagination">
                            <?php
                            echo wp_kses_post(paginate_links(array(
                                'base' => add_query_arg('paged', '%#%'),
                                'format' => '',
                                'prev_text' => __('&laquo;', 'wp-login-shield'),
                                'next_text' => __('&raquo;', 'wp-login-shield'),
                                'total' => $total_pages,
                                'current' => $current_page
                            )));
                            ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="wp-login-shield-footer">
                <?php echo esc_html($this->plugin_name); ?> v<?php echo esc_html($this->version); ?> | Developed by <a href="https://budhilaw.com" target="_blank">Ericsson Budhilaw</a>
            </div>
        </div>
        <?php
    }

    /**
     * Display access monitoring page with card-based UI like the Banned IPs page
     */
    public function display_access_monitoring_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $message = '';
        $error = '';
        
        // Handle clear log action
        if (isset($_POST['wp_login_shield_clear_access_logs']) && isset($_POST['_wpnonce']) && current_user_can('manage_options')) {
            $nonce = sanitize_text_field(wp_unslash($_POST['_wpnonce']));
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_clear_access_logs')) {
                update_option('wp_login_shield_access_records', array());
                $message = 'Access monitoring logs have been cleared.';
            } else {
                $error = 'Security check failed. Please try again.';
            }
        }
        
        $access_records = get_option('wp_login_shield_access_records', array());
        $access_records = array_reverse($access_records); // Most recent first
        
        // Prepare pagination
        $total_items = count($access_records);
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval(wp_unslash($_GET['paged']))) : 1;
        $offset = ($current_page - 1) * $per_page;
        $total_pages = ceil($total_items / $per_page);
        
        // Get current page items
        $records = array_slice($access_records, $offset, $per_page);
        ?>
        <div class="wrap wp-login-shield-banned-page">
            <h1>Login Access Monitoring</h1>
            
            <?php if (!empty($message)): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html($message); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($error)): ?>
                <div class="notice notice-error is-dismissible">
                    <p><?php echo esc_html($error); ?></p>
                </div>
            <?php endif; ?>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-shield"></span> Access Monitoring Tools</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="screen-reader-text">Toggle panel</span>
                        <span class="toggle-indicator" aria-hidden="true"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <p>Here you can clear the access monitoring logs.</p>
                    
                    <form method="post" action="" style="display: inline-block; margin-right: 10px;">
                        <?php wp_nonce_field('wp_login_shield_clear_access_logs'); ?>
                        <button type="submit" name="wp_login_shield_clear_access_logs" class="button button-secondary" onclick="return confirm('Are you sure you want to clear all access logs? This cannot be undone.');">
                            <span class="dashicons dashicons-trash" style="margin-top: 3px; margin-right: 5px;"></span>
                            Clear Access Logs
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-list-view"></span> Recent Login Page Access Attempts</h2>
                    <button type="button" class="handlediv" aria-expanded="true">
                        <span class="screen-reader-text">Toggle panel</span>
                        <span class="toggle-indicator" aria-hidden="true"></span>
                    </button>
                </div>
                
                <div class="wp-login-shield-card-body">
                    <p>Below are the most recent attempts to access your login page:</p>
                    
                    <div class="login-attempts-table-wrapper">
                        <table class="widefat striped">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>IP Address</th>
                                    <th>Accessed Path</th>
                                    <th>User Agent</th>
                                    <th>Referrer</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                if (empty($records)) {
                                    echo '<tr><td colspan="5">No access records found.</td></tr>';
                                } else {
                                    foreach ($records as $record) {
                                        echo '<tr>';
                                        echo '<td>' . esc_html($this->plugin->format_datetime($record['time'])) . '</td>';
                                        echo '<td>' . esc_html($record['ip']) . '</td>';
                                        echo '<td>' . esc_html($record['request_uri']) . '</td>';
                                        echo '<td class="user-agent">' . esc_html($record['user_agent']) . '</td>';
                                        
                                        // Handle referrer display - check for all possible variations of Direct access
                                        $referrer = '';
                                        if (empty($record['http_referrer'])) {
                                            $referrer = 'Direct';
                                        } elseif ($record['http_referrer'] === 'Direct' || $record['http_referrer'] === 'Direct access' ||
                                                  strpos($record['http_referrer'], 'Direct%20access') !== false ||
                                                  strpos($record['http_referrer'], 'Direct access') !== false) {
                                            $referrer = 'Direct';
                                        } else {
                                            $referrer = '<a href="' . esc_url($record['http_referrer']) . '" target="_blank">' . esc_html($record['http_referrer']) . '</a>';
                                        }
                                        
                                        echo '<td>' . wp_kses_post($referrer) . '</td>';
                                        echo '</tr>';
                                    }
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>

                    <?php
                    if ($total_pages > 1) {
                        echo '<div class="pagination-wrapper">';
                        echo '<nav class="pagination" aria-label="Access logs pagination">';
                        echo wp_kses_post(paginate_links(array(
                            'base' => add_query_arg('paged', '%#%'),
                            'format' => '',
                            'prev_text' => __('&laquo;', 'wp-login-shield'),
                            'next_text' => __('&raquo;', 'wp-login-shield'),
                            'total' => $total_pages,
                            'current' => $current_page,
                            'type' => 'list',
                            'mid_size' => 1,
                            'end_size' => 1,
                            'add_args' => array(), // Prevents extra query args
                            'add_fragment' => '',
                        )));
                        echo '</nav>';
                        echo '</div>';
                    }
                    ?>
                </div>
            </div>
            
            <?php $this->display_footer_note(); ?>
        </div>
        <?php
    }

    /**
     * Display about page
     */
    public function display_about_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        ?>
        <div class="wrap wp-login-shield-about-page">
            <h1><?php echo esc_html($this->plugin_name); ?></h1>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-info"></span>Plugin Information</h2>
                </div>
                <div class="wp-login-shield-card-body">
                    <table class="plugin-info-table">
                        <tr>
                            <th>Version:</th>
                            <td><?php echo esc_html($this->version); ?></td>
                        </tr>
                        <tr>
                            <th>Author:</th>
                            <td><a href="https://budhilaw.com" target="_blank">Ericsson Budhilaw</a></td>
                        </tr>
                    </table>
                    <p>
                        <?php echo esc_html($this->plugin_name); ?> enhances your WordPress site's security by customizing the login path,
                        blocking brute force attacks, and monitoring login attempts.
                    </p>
                </div>
            </div>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-shield"></span>Features</h2>
                </div>
                <div class="wp-login-shield-card-body">
                    <ul class="features-list">
                        <li>
                            <strong>Custom Login URL</strong>
                            Change your WordPress login URL to prevent automated attacks.
                        </li>
                        <li>
                            <strong>IP Banning</strong>
                            Automatically ban IP addresses that attempt too many failed logins.
                        </li>
                        <li>
                            <strong>Login Tracking</strong>
                            Track all login attempts to your WordPress site.
                        </li>
                        <li>
                            <strong>Access Monitoring</strong>
                            Monitor all attempts to access your login page, even without login attempts.
                        </li>
                        <li>
                            <strong>IP Whitelisting</strong>
                            Allow only specific IP addresses to access your login page.
                        </li>
                    </ul>
                </div>
            </div>
            
            <div class="wp-login-shield-card">
                <div class="wp-login-shield-card-header">
                    <h2><span class="dashicons dashicons-lightbulb"></span>Usage Tips</h2>
                </div>
                <div class="wp-login-shield-card-body">
                    <ul class="usage-tips-list">
                        <li>
                            <strong>Custom Login Path</strong>
                            Set a custom login path in the plugin settings. Your login page will then be accessible at 
                            <span class="code-example"><?php echo esc_html(site_url('/')); ?><em>your-custom-path</em></span>
                        </li>
                        <li>
                            <strong>IP Banning</strong>
                            Enable automatic IP banning to protect against brute force attacks.
                        </li>
                        <li>
                            <strong>Whitelisting</strong>
                            For the highest security, enable IP whitelisting and add only trusted IP addresses.
                        </li>
                        <li>
                            <strong>Login Tracking</strong>
                            Regularly review login attempts to monitor for suspicious activity.
                        </li>
                    </ul>
                </div>
            </div>
            
            <div class="wp-login-shield-footer">
                <?php echo esc_html($this->plugin_name); ?> v<?php echo esc_html($this->version); ?> | Developed by <a href="https://budhilaw.com" target="_blank">Ericsson Budhilaw</a>
            </div>
        </div>
        <?php
    }

    /**
     * Display footer note
     */
    private function display_footer_note() {
        // No longer needed as we've integrated the footer in the about page
        return;
    }
} 