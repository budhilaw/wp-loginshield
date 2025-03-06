<?php

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
    protected $version = '1.0.1';

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
        add_submenu_page('wp-login-shield', 'Banned IPs', 'Banned IPs', 'manage_options', 'wp-login-shield-banned', array($this, 'display_banned_ips_page'));
        add_submenu_page('wp-login-shield', 'Login Tracking', 'Login Tracking', 'manage_options', 'wp-login-shield-tracking', array($this, 'display_login_tracking_page'));
        add_submenu_page('wp-login-shield', 'Access Monitoring', 'Access Monitoring', 'manage_options', 'wp-login-shield-monitoring', array($this, 'display_access_monitoring_page'));
        add_submenu_page('wp-login-shield', 'About', 'About', 'manage_options', 'wp-login-shield-about', array($this, 'display_about_page'));
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('wp_login_shield_settings', 'wp_login_shield', array($this, 'sanitize_login_path'));
        register_setting('wp_login_shield_settings', 'wp_login_shield_enable_ip_ban');
        register_setting('wp_login_shield_settings', 'wp_login_shield_enable_login_tracking');
        register_setting('wp_login_shield_settings', 'wp_login_shield_timezone');
        register_setting('wp_login_shield_settings', 'wp_login_shield_time_format');
        register_setting('wp_login_shield_settings', 'wp_login_shield_enable_ip_whitelist');
        register_setting('wp_login_shield_settings', 'wp_login_shield_whitelist_ips', array($this, 'sanitize_whitelist_ips'));
        register_setting('wp_login_shield_settings', 'wp_login_shield_enable_login_access_monitoring');
        register_setting('wp_login_shield_settings', 'wp_login_shield_max_login_attempts', 'intval');
        
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
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_enable_ip_ban',
            'IP Banning',
            array($this, 'ip_ban_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_enable_login_tracking',
            'Login Tracking',
            array($this, 'login_tracking_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_timezone',
            'Timezone',
            array($this, 'timezone_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_time_format',
            'Time Format',
            array($this, 'time_format_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_enable_ip_whitelist',
            'IP Whitelist',
            array($this, 'ip_whitelist_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
        );
        
        add_settings_field(
            'wp_login_shield_enable_login_access_monitoring',
            'Login Access Monitoring',
            array($this, 'login_access_monitoring_field_callback'),
            'wp_login_shield_settings',
            'wp_login_shield_section'
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
        ?>
        <input type="text" name="wp_login_shield" value="<?php echo esc_attr($login_path); ?>" class="regular-text">
        <p class="description">
            Enter the custom path for the login page (e.g., "secret-login" would make your login page <?php echo esc_html(site_url('/secret-login')); ?>)
        </p>
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
            echo '<option value="' . esc_attr($tz) . '"' . $selected . '>' . esc_html($tz) . '</option>';
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
     * Sanitize login path
     *
     * @param string $path The login path to sanitize
     * @return string Sanitized login path
     */
    public function sanitize_login_path($path) {
        // Trim whitespace
        $path = trim($path);
        
        // Replace any non-alphanumeric characters (except dash and underscore) with nothing
        $path = preg_replace('/[^a-zA-Z0-9\-\_]/', '', $path);
        
        // Fallback to default if empty
        if (empty($path)) {
            $path = 'login';
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
        
        if (in_array(strtolower($path), $reserved_terms)) {
            add_settings_error(
                'wp_login_shield',
                'wp_login_shield_error',
                'The login path cannot be a reserved WordPress term. Please choose a different path.',
                'error'
            );
            
            // Return the previously saved value
            return get_option('wp_login_shield', 'login');
        }
        
        return $path;
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
        <div class="wrap">
            <h1><?php echo esc_html($this->plugin_name); ?> Settings</h1>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('wp_login_shield_settings');
                do_settings_sections('wp_login_shield_settings');
                submit_button();
                ?>
            </form>
        </div>
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
            $nonce = sanitize_text_field($_POST['_wpnonce']);
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_ban_ip')) {
                $ip_to_ban = isset($_POST['ip_address']) ? sanitize_text_field($_POST['ip_address']) : '';
                
                // Validate IP address
                if (empty($ip_to_ban)) {
                    $ban_error = 'Please enter an IP address.';
                } elseif (!filter_var($ip_to_ban, FILTER_VALIDATE_IP)) {
                    $ban_error = 'Please enter a valid IP address.';
                } else {
                    // Ban the IP
                    if (isset($this->plugin) && isset($this->plugin->ip_management) && method_exists($this->plugin->ip_management, 'ban_ip')) {
                        $this->plugin->ip_management->ban_ip($ip_to_ban);
                        $ban_message = 'IP address ' . esc_html($ip_to_ban) . ' has been banned.';
                    } else {
                        $ban_error = 'Could not ban IP address. IP Management module not available.';
                    }
                }
            }
        }
        
        // Handle unban IP
        if (isset($_GET['action']) && $_GET['action'] === 'unban' && isset($_GET['ip']) && isset($_GET['_wpnonce'])) {
            $nonce = sanitize_text_field($_GET['_wpnonce']);
            $ip = sanitize_text_field($_GET['ip']);
            
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
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($banned_ips)): ?>
                                <tr>
                                    <td colspan="3">No IP addresses are currently banned.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($banned_ips as $ip => $data): 
                                    // Skip if not a valid data structure
                                    if (!is_array($data)) {
                                        continue;
                                    }
                                    
                                    // Get ban information
                                    $is_banned = isset($data['is_banned']) && $data['is_banned'] === true;
                                    
                                    // Skip if not banned
                                    if (!$is_banned) {
                                        continue;
                                    }
                                    
                                    $ban_date = isset($data['ban_date']) ? $data['ban_date'] : (isset($data['last_attempt']) ? $data['last_attempt'] : 0);
                                ?>
                                    <tr>
                                        <td><?php echo esc_html($ip); ?></td>
                                        <td><?php echo esc_html(date('Y-m-d H:i:s', $ban_date)); ?></td>
                                        <td>
                                            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('action' => 'unban', 'ip' => $ip), admin_url('admin.php?page=wp-login-shield-banned')), 'wp_login_shield_unban_ip_' . $ip)); ?>" class="button button-small button-unban">Unban</a>
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
            $nonce = sanitize_text_field($_POST['_wpnonce']);
            
            if (wp_verify_nonce($nonce, 'wp_login_shield_clear_login_attempts')) {
                update_option('wp_login_shield_login_attempts', array());
                $message = 'Login attempts have been cleared successfully.';
            } else {
                $error = 'Security check failed. Please try again.';
            }
        }
        
        $login_attempts = get_option('wp_login_shield_login_attempts', array());
        $login_attempts = array_reverse($login_attempts); // Most recent first
        
        // Prepare pagination
        $total_items = count($login_attempts);
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        $total_pages = ceil($total_items / $per_page);
        
        // Get current page items
        $attempts = array_slice($login_attempts, $offset, $per_page);
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
                            if (empty($attempts)) {
                                echo '<tr><td colspan="5">No login attempts recorded yet.</td></tr>';
                            } else {
                                foreach ($attempts as $attempt) {
                                    $status_class = ($attempt['status'] === 'success') ? 'login-success' : 'login-failed';
                                    $status_text = ($attempt['status'] === 'success') ? 'Success' : 'Failed';
                                    
                                    echo '<tr>';
                                    echo '<td>' . $this->plugin->format_datetime($attempt['time']) . '</td>';
                                    echo '<td>' . esc_html($attempt['username']) . '</td>';
                                    echo '<td><span class="' . esc_attr($status_class) . '">' . esc_html($status_text) . '</span></td>';
                                    echo '<td>' . esc_html($attempt['ip']) . '</td>';
                                    echo '<td class="user-agent-cell">' . esc_html($attempt['user_agent']) . '</td>';
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
                            echo paginate_links(array(
                                'base' => add_query_arg('paged', '%#%'),
                                'format' => '',
                                'prev_text' => '<span class="dashicons dashicons-arrow-left-alt2"></span>',
                                'next_text' => '<span class="dashicons dashicons-arrow-right-alt2"></span>',
                                'total' => $total_pages,
                                'current' => $current_page,
                                'type' => 'list',
                                'mid_size' => 1,
                                'end_size' => 1,
                                'add_args' => array(), // Prevents extra query args
                                'add_fragment' => '',
                            ));
                            ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="wp-login-shield-footer">
                <?php echo esc_html($this->plugin_name); ?> v<?php echo esc_html($this->version); ?> | Developed by <a href="https://budhilaw.com" target="_blank">Budhilaw</a>
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
            $nonce = sanitize_text_field($_POST['_wpnonce']);
            
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
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
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
                                    echo '<td>' . $this->plugin->format_datetime($record['time']) . '</td>';
                                    echo '<td>' . esc_html($record['ip']) . '</td>';
                                    echo '<td>' . (isset($record['request_uri']) ? esc_html($record['request_uri']) : 'Unknown') . '</td>';
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
                                        $referrer = '<a href="' . esc_url($record['http_referrer']) . '" target="_blank">' . esc_url($record['http_referrer']) . '</a>';
                                    }
                                    
                                    echo '<td>' . $referrer . '</td>';
                                    echo '</tr>';
                                }
                            }
                            ?>
                        </tbody>
                    </table>
                    
                    <?php
                    if ($total_pages > 1) {
                        echo '<div class="pagination-wrapper">';
                        echo '<nav class="pagination" aria-label="Access logs pagination">';
                        echo paginate_links(array(
                            'base' => add_query_arg('paged', '%#%'),
                            'format' => '',
                            'prev_text' => '<span class="dashicons dashicons-arrow-left-alt2"></span>',
                            'next_text' => '<span class="dashicons dashicons-arrow-right-alt2"></span>',
                            'total' => $total_pages,
                            'current' => $current_page,
                            'type' => 'list',
                            'mid_size' => 1,
                            'end_size' => 1,
                            'add_args' => array(), // Prevents extra query args
                            'add_fragment' => '',
                        ));
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
                            <td><a href="https://budhilaw.com" target="_blank">Budhilaw</a></td>
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
                <?php echo esc_html($this->plugin_name); ?> v<?php echo esc_html($this->version); ?> | Developed by <a href="https://budhilaw.com" target="_blank">Budhilaw</a>
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