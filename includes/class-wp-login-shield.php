<?php

/**
 * The main plugin class
 *
 * @since      1.0.0
 * @package    WP_LoginShield
 */

class WP_LoginShield {

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
     * Max login attempts before banning
     *
     * @var int
     */
    protected $max_login_attempts = 3;

    /**
     * Ban duration in hours
     *
     * @var int
     */
    protected $ban_duration = 24;

    /**
     * Max login records to keep
     *
     * @var int
     */
    protected $max_login_records = 500;

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
     * Initialize the plugin
     */
    public function __construct() {
        $this->login_path = get_option('wp_login_shield', $this->default_path);
        $this->timezone = get_option('wp_login_shield_timezone', '');
        $this->time_format = get_option('wp_login_shield_time_format', '24');
        $this->ip_whitelist_enabled = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $this->whitelist_ips = get_option('wp_login_shield_whitelist_ips', array());
        $this->login_access_monitoring_enabled = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        
        // Add admin page
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Enqueue admin scripts
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }

    /**
     * Run the plugin
     */
    public function run() {
        // Filter to change login URL
        add_filter('site_url', array($this, 'change_login_url'), 10, 4);
        
        // Hook to block wp-login.php access
        add_action('init', array($this, 'block_wp_login'));
        
        // Add rewrite rules
        add_action('init', array($this, 'add_rewrite_rules'));
        
        // Handle activation
        register_activation_hook(dirname(dirname(__FILE__)) . '/wp-loginshield.php', array($this, 'activate'));
        
        // Handle deactivation
        register_deactivation_hook(dirname(dirname(__FILE__)) . '/wp-loginshield.php', array($this, 'deactivate'));

        // Add login failed hook if IP banning is enabled
        if (get_option('wp_login_shield_enable_ip_ban', 0)) {
            add_action('wp_login_failed', array($this, 'handle_failed_login'));
            add_filter('authenticate', array($this, 'check_banned_ip'), 30, 3);
        }

        // Track all login attempts if enabled
        if (get_option('wp_login_shield_enable_login_tracking', 0)) {
            // Track successful logins
            add_action('wp_login', array($this, 'track_successful_login'), 10, 2);
            
            // Track failed logins regardless of IP ban setting
            if (!get_option('wp_login_shield_enable_ip_ban', 0)) {
                add_action('wp_login_failed', array($this, 'track_failed_login'));
            }
        }
        
        // Check IP whitelist if enabled
        if (get_option('wp_login_shield_enable_ip_whitelist', 0)) {
            add_action('login_init', array($this, 'check_ip_whitelist'));
        }
        
        // Monitor login page access if enabled
        if (get_option('wp_login_shield_enable_login_access_monitoring', 0)) {
            add_action('login_init', array($this, 'record_login_page_access'), 5);
            add_action('wp_loaded', array($this, 'check_for_login_page_access'), 5);
        }
    }

    /**
     * Add the admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            __('WP LoginShield', 'wp-loginshield'),
            __('WP LoginShield', 'wp-loginshield'),
            'manage_options',
            'wp-loginshield',
            array($this, 'display_settings_page')
        );
    }

    /**
     * Register the plugin settings
     */
    public function register_settings() {
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield',
            array(
                'sanitize_callback' => array($this, 'sanitize_login_path'),
                'default' => $this->default_path,
            )
        );

        // Register IP Ban setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_enable_ip_ban',
            array(
                'sanitize_callback' => 'absint',
                'default' => 0,
            )
        );

        // Register Login Tracking setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_enable_login_tracking',
            array(
                'sanitize_callback' => 'absint',
                'default' => 0,
            )
        );

        // Register Timezone setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_timezone',
            array(
                'sanitize_callback' => 'sanitize_text_field',
                'default' => '',
            )
        );

        // Register Time Format setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_time_format',
            array(
                'sanitize_callback' => 'sanitize_text_field',
                'default' => '24',
            )
        );

        // Register IP Whitelist setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_enable_ip_whitelist',
            array(
                'sanitize_callback' => 'absint',
                'default' => 0,
            )
        );

        // Register Whitelisted IPs setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_whitelist_ips',
            array(
                'sanitize_callback' => array($this, 'sanitize_whitelist_ips'),
                'default' => '',
            )
        );

        // Register Login Page Access Monitoring setting
        register_setting(
            'wp_login_shield_options',
            'wp_login_shield_enable_login_access_monitoring',
            array(
                'sanitize_callback' => 'absint',
                'default' => 0,
            )
        );

        add_settings_section(
            'wp_login_shield_section',
            __('Login Path Settings', 'wp-login-shield'),
            array($this, 'settings_section_callback'),
            'wp-login-shield'
        );

        // Add option field
        add_settings_field(
            'login_path',
            __('Login Path', 'wp-login-shield'),
            array($this, 'login_path_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add IP Ban setting field
        add_settings_field(
            'enable_ip_ban',
            __('IP Ban Protection', 'wp-login-shield'),
            array($this, 'ip_ban_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add Login Tracking setting field
        add_settings_field(
            'enable_login_tracking',
            __('Login Attempt Tracking', 'wp-login-shield'),
            array($this, 'login_tracking_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add Timezone setting field
        add_settings_field(
            'timezone',
            __('Timezone for Logs', 'wp-login-shield'),
            array($this, 'timezone_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add Time Format setting field
        add_settings_field(
            'time_format',
            __('Time Format', 'wp-login-shield'),
            array($this, 'time_format_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add IP Whitelist setting field
        add_settings_field(
            'enable_ip_whitelist',
            __('IP Whitelist Protection', 'wp-login-shield'),
            array($this, 'ip_whitelist_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );

        // Add Login Page Access Monitoring setting field
        add_settings_field(
            'enable_login_access_monitoring',
            __('Login Page Access Monitoring', 'wp-login-shield'),
            array($this, 'login_access_monitoring_field_callback'),
            'wp-login-shield',
            'wp_login_shield_section'
        );
    }

    /**
     * Settings section description
     */
    public function settings_section_callback() {
        echo '<p>' . __('Customize your WordPress login path for enhanced security.', 'wp-login-shield') . '</p>';
    }

    /**
     * Custom login path field
     */
    public function login_path_field_callback() {
        $value = get_option('wp_login_shield', $this->default_path);
        echo '<input type="text" id="wp_login_shield" name="wp_login_shield" value="' . esc_attr($value) . '" class="regular-text" />';
        echo '<p class="description">' . __('Your new login URL will be: ', 'wp-login-shield') . '<code>' . esc_url(home_url('/')) . '<span id="preview-slug">' . esc_html($value) . '</span></code></p>';
    }

    /**
     * IP Ban field callback
     */
    public function ip_ban_field_callback() {
        $value = get_option('wp_login_shield_enable_ip_ban', 0);
        echo '<label for="wp_login_shield_enable_ip_ban">';
        echo '<input type="checkbox" id="wp_login_shield_enable_ip_ban" name="wp_login_shield_enable_ip_ban" value="1" ' . checked(1, $value, false) . '/>';
        echo ' ' . __('Enable IP banning after 3 failed login attempts (ban lasts for 24 hours)', 'wp-login-shield') . '</label>';
        
        if ($value) {
            $banned_ips = get_option('wp_login_shield_banned_ips', array());
            if (!empty($banned_ips)) {
                $count = count($banned_ips);
                echo '<p class="description">' . sprintf(_n('Currently %d IP address is banned.', 'Currently %d IP addresses are banned.', $count, 'wp-login-shield'), $count) . ' ';
                echo '<a href="' . admin_url('options-general.php?page=wp-login-shield&tab=banned-ips') . '">' . __('Manage banned IPs', 'wp-login-shield') . '</a></p>';
            }
        }
    }

    /**
     * Login Tracking field callback
     */
    public function login_tracking_field_callback() {
        $value = get_option('wp_login_shield_enable_login_tracking', 0);
        echo '<label for="wp_login_shield_enable_login_tracking">';
        echo '<input type="checkbox" id="wp_login_shield_enable_login_tracking" name="wp_login_shield_enable_login_tracking" value="1" ' . checked(1, $value, false) . '/>';
        echo ' ' . __('Enable tracking of all login attempts (both successful and failed)', 'wp-login-shield') . '</label>';
        
        if ($value) {
            $login_attempts = get_option('wp_login_shield_login_attempts', array());
            if (!empty($login_attempts)) {
                $count = count($login_attempts);
                echo '<p class="description">' . sprintf(_n('Currently tracking %d login attempt.', 'Currently tracking %d login attempts.', $count, 'wp-login-shield'), $count) . ' ';
                echo '<a href="' . admin_url('options-general.php?page=wp-login-shield&tab=login-tracking') . '">' . __('View login attempts', 'wp-login-shield') . '</a></p>';
            }
        }
    }

    /**
     * Timezone field callback
     */
    public function timezone_field_callback() {
        $value = get_option('wp_login_shield_timezone', '');
        ?>
        <select name="wp_login_shield_timezone">
            <option value="" <?php selected($value, ''); ?>><?php _e('WordPress Default', 'wp-login-shield'); ?></option>
            <?php
            foreach (timezone_identifiers_list() as $tz) {
                echo '<option value="' . esc_attr($tz) . '" ' . selected($value, $tz, false) . '>' . esc_html($tz) . '</option>';
            }
            ?>
        </select>
        <p class="description"><?php _e('Select a timezone for displaying timestamps in login records', 'wp-login-shield'); ?></p>
        <?php
    }

    /**
     * Time Format field callback
     */
    public function time_format_field_callback() {
        $value = get_option('wp_login_shield_time_format', '24');
        ?>
        <select name="wp_login_shield_time_format">
            <option value="12" <?php selected($value, '12'); ?>><?php _e('12-hour (eg. 1:30 PM)', 'wp-login-shield'); ?></option>
            <option value="24" <?php selected($value, '24'); ?>><?php _e('24-hour (eg. 13:30)', 'wp-login-shield'); ?></option>
        </select>
        <p class="description"><?php _e('Select time format for displaying timestamps', 'wp-login-shield'); ?></p>
        <?php
    }

    /**
     * IP Whitelist field callback
     */
    public function ip_whitelist_field_callback() {
        $value = get_option('wp_login_shield_enable_ip_whitelist', 0);
        $whitelist_ips = get_option('wp_login_shield_whitelist_ips', '');
        
        echo '<p>';
        echo '<label><input type="checkbox" name="wp_login_shield_enable_ip_whitelist" value="1" ' . checked(1, $value, false) . ' /> ';
        echo __('Enable IP Whitelist', 'wp-login-shield') . '</label>';
        echo '</p>';
        
        echo '<p>';
        echo '<label for="wp_login_shield_whitelist_ips">' . __('Whitelisted IPs (one per line):', 'wp-login-shield') . '</label><br>';
        echo '<textarea name="wp_login_shield_whitelist_ips" id="wp_login_shield_whitelist_ips" rows="5" cols="50" class="large-text code">' . esc_textarea($whitelist_ips) . '</textarea>';
        echo '</p>';
        
        echo '<p class="description">' . __('Enter IP addresses that should always be allowed to access the login page. Enter one IP per line.', 'wp-login-shield') . '</p>';
        echo '<p class="description">' . __('Your current IP is:', 'wp-login-shield') . ' <code>' . esc_html($this->get_client_ip()) . '</code></p>';
    }

    /**
     * Login Page Access Monitoring field callback
     */
    public function login_access_monitoring_field_callback() {
        $value = get_option('wp_login_shield_enable_login_access_monitoring', 0);
        
        echo '<p>';
        echo '<label><input type="checkbox" name="wp_login_shield_enable_login_access_monitoring" value="1" ' . checked(1, $value, false) . ' /> ';
        echo __('Enable Login Access Monitoring', 'wp-login-shield') . '</label>';
        echo '</p>';
        
        echo '<p class="description">' . __('When enabled, all access attempts to the login page will be recorded.', 'wp-login-shield') . '</p>';
        
        // Only show count if monitoring is enabled
        if ($value) {
            $login_access_records = get_option('wp_login_shield_access_records', array());
            $count = count($login_access_records);
            
            echo '<p class="description">' . sprintf(_n('Currently tracking %d access record.', 'Currently tracking %d access records.', $count, 'wp-login-shield'), $count) . '</p>';
        }
    }

    /**
     * Sanitize the login path setting
     *
     * @param string $path The input login path
     * @return string
     */
    public function sanitize_login_path($path) {
        // Sanitize the path
        $path = sanitize_title($path);
        
        // Ensure not empty
        if (empty($path)) {
            add_settings_error(
                'custom_login_path',
                'empty_path',
                __('Login path cannot be empty. Using default.', 'wp-login-shield'),
                'error'
            );
            return get_option('wp_login_shield', $this->default_path);
        }
        
        // Ensure path is not a WordPress reserved term
        $reserved = array('wp-admin', 'admin', 'login', 'wp-login', 'wp-login.php', 'dashboard');
        if (in_array($path, $reserved)) {
            add_settings_error(
                'wp_login_shield',
                'reserved_path',
                __('This is a reserved WordPress term. Please choose a different path.', 'wp-login-shield'),
                'error'
            );
            return get_option('wp_login_shield', $this->default_path);
        }
        
        // Flush rewrite rules on save
        $this->login_path = $path;
        flush_rewrite_rules();
        
        return $path;
    }

    /**
     * Display the settings page
     */
    public function display_settings_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }

        // Get the active tab
        $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'settings';
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <h2 class="nav-tab-wrapper">
                <a href="?page=wp-loginshield&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Settings', 'wp-loginshield'); ?>
                </a>
                <?php if (get_option('wp_login_shield_enable_ip_ban', 0)): ?>
                <a href="?page=wp-loginshield&tab=banned-ips" class="nav-tab <?php echo $active_tab == 'banned-ips' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Banned IPs', 'wp-loginshield'); ?>
                </a>
                <?php endif; ?>
                <?php if (get_option('wp_login_shield_enable_login_tracking', 0)): ?>
                <a href="?page=wp-loginshield&tab=login-tracking" class="nav-tab <?php echo $active_tab == 'login-tracking' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Login Tracking', 'wp-loginshield'); ?>
                </a>
                <?php endif; ?>
                <?php if (get_option('wp_login_shield_enable_login_access_monitoring', 0)): ?>
                <a href="?page=wp-loginshield&tab=access-monitoring" class="nav-tab <?php echo $active_tab == 'access-monitoring' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Access Monitoring', 'wp-loginshield'); ?>
                </a>
                <?php endif; ?>
                <a href="?page=wp-loginshield&tab=about" class="nav-tab <?php echo $active_tab == 'about' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('About', 'wp-loginshield'); ?>
                </a>
            </h2>
            
            <?php if ($active_tab == 'settings'): ?>
                <form action="options.php" method="post">
                    <?php
                    // Output security fields
                    settings_fields('wp_login_shield_options');
                    
                    // Output setting sections
                    do_settings_sections('wp-login-shield');
                    
                    // Submit button
                    submit_button();
                    ?>
                </form>
            <?php elseif ($active_tab == 'banned-ips'): ?>
                <?php $this->display_banned_ips_page(); ?>
            <?php elseif ($active_tab == 'login-tracking'): ?>
                <?php $this->display_login_tracking_page(); ?>
            <?php elseif ($active_tab == 'access-monitoring'): ?>
                <?php $this->display_access_monitoring_page(); ?>
            <?php elseif ($active_tab == 'about'): ?>
                <?php $this->display_about_page(); ?>
            <?php endif; ?>
        </div>
        
        <?php $this->display_footer_note(); ?>
        <?php
    }

    /**
     * Display a footer note for branding
     */
    private function display_footer_note() {
        ?>
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #777; font-size: 12px; text-align: center;">
            <?php echo sprintf(__('WP LoginShield by %s - For custom WordPress development, please visit %s', 'wp-loginshield'), 
                '<a href="https://budhilaw.com" target="_blank">Budhilaw</a>',
                '<a href="https://budhilaw.com/contact" target="_blank">budhilaw.com</a>'
            ); ?>
        </div>
        <?php
    }

    /**
     * Display banned IPs management page
     */
    public function display_banned_ips_page() {
        if (!get_option('wp_login_shield_enable_ip_ban', 0)) {
            echo '<div class="notice notice-error"><p>' . __('IP banning is not enabled. Please enable it in the settings tab.', 'wp-loginshield') . '</p></div>';
            return;
        }
        
        // Handle unban action
        if (isset($_GET['unban_ip']) && isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'unban_ip')) {
            $ip_to_unban = sanitize_text_field($_GET['unban_ip']);
            $this->unban_ip($ip_to_unban);
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(__('IP address %s has been unbanned.', 'wp-loginshield'), $ip_to_unban) . '</p></div>';
        }
        
        // Handle clear all bans action
        if (isset($_POST['clear_all_bans']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'clear_all_bans')) {
            update_option('wp_login_shield_banned_ips', array());
            echo '<div class="notice notice-success is-dismissible"><p>' . __('All IP bans have been cleared.', 'wp-loginshield') . '</p></div>';
        }
        
        // Get banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        if (empty($banned_ips)) {
            echo '<div class="card">';
            echo '<p>' . __('IP addresses are automatically banned when they exceed the maximum number of failed login attempts.', 'wp-loginshield') . '</p>';
            echo '<p>' . __('Each ban lasts for 24 hours from the time of the last failed attempt.', 'wp-loginshield') . '</p>';
            echo '</div>';
            
            echo '<div class="card">';
            echo '<p>' . __('There are no banned IP addresses at this time.', 'wp-loginshield') . '</p>';
            echo '</div>';
        } else {
            echo '<h3>' . __('Currently Banned IP Addresses', 'wp-loginshield') . '</h3>';
            
            echo '<table class="widefat banned-ip-table">';
            echo '<thead><tr>';
            echo '<th>' . __('IP Address', 'wp-loginshield') . '</th>';
            echo '<th>' . __('Failed Attempts', 'wp-loginshield') . '</th>';
            echo '<th>' . __('Last Attempt', 'wp-loginshield') . '</th>';
            echo '<th>' . __('Ban Expires', 'wp-loginshield') . '</th>';
            echo '<th>' . __('Actions', 'wp-loginshield') . '</th>';
            echo '</tr></thead><tbody>';
            
            foreach ($banned_ips as $ip => $data) {
                $time = isset($data['last_attempt']) ? $data['last_attempt'] : time();
                $expires = $time + ($this->ban_duration * HOUR_IN_SECONDS);
                echo '<tr>';
                echo '<td>' . esc_html($ip) . '</td>';
                echo '<td>' . intval($data['attempts']) . '</td>';
                echo '<td>' . esc_html($this->format_datetime($time)) . '</td>';
                echo '<td>' . esc_html($this->format_datetime($expires)) . '</td>';
                echo '<td>';
                echo '<form method="get" action="">';
                echo '<input type="hidden" name="page" value="wp-loginshield">';
                echo '<input type="hidden" name="tab" value="banned-ips">';
                echo '<input type="hidden" name="unban_ip" value="' . esc_attr($ip) . '">';
                wp_nonce_field('unban_ip');
                echo '<button type="submit" class="button button-secondary unban-ip-button">' . __('Unban', 'wp-loginshield') . '</button>';
                echo '</form>';
                echo '</td>';
                echo '</tr>';
            }
            
            echo '</tbody></table>';
            
            // Add form for clearing all bans
            echo '<form method="post" action="" style="margin-top: 20px;">';
            wp_nonce_field('clear_all_bans');
            echo '<button type="submit" name="clear_all_bans" class="button button-secondary">' . __('Clear All Bans', 'wp-loginshield') . '</button>';
            echo '</form>';
        }
    }

    /**
     * Display login tracking page
     */
    public function display_login_tracking_page() {
        if (!get_option('wp_login_shield_enable_login_tracking', 0)) {
            echo '<div class="notice notice-error"><p>' . __('Login tracking is not enabled. Please enable it in the settings tab.', 'wp-loginshield') . '</p></div>';
            return;
        }
        
        // Handle clear all login attempts action
        if (isset($_POST['clear_all_login_attempts']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'clear_all_login_attempts')) {
            update_option('wp_login_shield_login_attempts', array());
            echo '<div class="notice notice-success is-dismissible"><p>' . __('All login attempt records have been cleared.', 'wp-loginshield') . '</p></div>';
        }
        
        // Get login attempts
        $login_attempts = get_option('wp_login_shield_login_attempts', array());
        
        // Display info card
        ?>
        <div class="wp-loginshield-info">
            <p><?php _e('This page shows all tracked login attempts to your WordPress site.', 'wp-loginshield'); ?></p>
            <p><?php _e('Both successful and failed login attempts are recorded with IP address, username, and timestamp.', 'wp-loginshield'); ?></p>
        </div>

        <div class="tablenav top">
            <div class="alignleft actions">
                <a href="<?php echo wp_nonce_url(admin_url('options-general.php?page=wp-loginshield&tab=login-tracking&export_login_attempts=1'), 'export_login_attempts'); ?>" class="button button-primary">
                    <?php _e('Export as CSV', 'wp-loginshield'); ?>
                </a>
            </div>
            
            <form method="post" class="alignright">
                <?php wp_nonce_field('clear_all_login_attempts'); ?>
                <button type="submit" name="clear_all_login_attempts" class="button button-secondary"><?php _e('Clear All Records', 'wp-loginshield'); ?></button>
            </form>
            <br class="clear" />
        </div>

        <?php if (empty($login_attempts)): ?>
            <p><?php _e('There are no login attempts recorded at this time.', 'wp-loginshield'); ?></p>
        <?php else: ?>
            <h3><?php _e('Login Attempt Records', 'wp-loginshield'); ?></h3>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php _e('Date/Time', 'wp-loginshield'); ?></th>
                        <th><?php _e('IP Address', 'wp-loginshield'); ?></th>
                        <th><?php _e('Username', 'wp-loginshield'); ?></th>
                        <th><?php _e('Status', 'wp-loginshield'); ?></th>
                        <th><?php _e('User Agent', 'wp-loginshield'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    // Show newest first
                    $login_attempts = array_reverse($login_attempts);
                    
                    foreach ($login_attempts as $attempt): 
                        $status_class = $attempt['status'] === 'success' ? 'login-success' : 'login-failed';
                    ?>
                        <tr>
                            <td><?php echo $this->format_datetime($attempt['time']); ?></td>
                            <td><?php echo esc_html($attempt['ip']); ?></td>
                            <td><?php echo esc_html($attempt['username']); ?></td>
                            <td><span class="login-status <?php echo esc_attr($status_class); ?>"><?php echo $attempt['status'] === 'success' ? __('Success', 'wp-loginshield') : __('Failed', 'wp-loginshield'); ?></span></td>
                            <td class="user-agent-cell"><?php echo esc_html($attempt['user_agent']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?><?php
    }

    /**
     * Export login attempts as CSV
     */
    public function export_login_attempts() {
        $login_attempts = get_option('wp_login_shield_login_attempts', array());
        
        if (empty($login_attempts)) {
            return;
        }
        
        // Set headers for CSV download
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=login-attempts-' . date('Y-m-d') . '.csv');
        
        // Create output stream
        $output = fopen('php://output', 'w');
        
        // Add CSV headers
        fputcsv($output, array(
            __('Date/Time', 'wp-loginshield'),
            __('IP Address', 'wp-loginshield'),
            __('Username', 'wp-loginshield'),
            __('Status', 'wp-loginshield'),
            __('User Agent', 'wp-loginshield')
        ));
        
        // Add data
        foreach ($login_attempts as $attempt) {
            fputcsv($output, array(
                $this->format_datetime($attempt['time']),
                $attempt['ip'],
                $attempt['username'],
                $attempt['status'] === 'success' ? __('Success', 'wp-loginshield') : __('Failed', 'wp-loginshield'),
                $attempt['user_agent']
            ));
        }
        
        fclose($output);
        exit;
    }

    /**
     * Track successful login attempts
     * 
     * @param string $username Username
     * @param WP_User $user User object
     */
    public function track_successful_login($username, $user) {
        $this->add_login_record($username, 'success');
    }

    /**
     * Track failed login attempts
     * 
     * @param string $username Username
     */
    public function track_failed_login($username) {
        $this->add_login_record($username, 'failed');
    }

    /**
     * Add login record to the tracking list
     *
     * @param string $username The username being used for login
     * @param string $status The login status (success/failed)
     */
    private function add_login_record($username, $status) {
        // Get visitor IP and user agent
        $ip = $this->get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : __('Unknown', 'wp-login-shield');
        
        if (empty($ip)) {
            $ip = __('Unknown', 'wp-login-shield');
        }
        
        // Get current login attempts
        $login_attempts = get_option('wp_login_shield_login_attempts', array());
        
        // Add new record
        $login_attempts[] = array(
            'time' => time(),
            'ip' => $ip,
            'username' => $username,
            'status' => $status,
            'user_agent' => $user_agent
        );
        
        // Limit the number of records we store
        if (count($login_attempts) > $this->max_login_records) {
            $login_attempts = array_slice($login_attempts, -$this->max_login_records);
        }
        
        // Update the option
        update_option('wp_login_shield_login_attempts', $login_attempts);
    }

    /**
     * Unban a specific IP address
     * 
     * @param string $ip IP address to unban
     */
    public function unban_ip($ip) {
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        if (isset($banned_ips[$ip])) {
            unset($banned_ips[$ip]);
            update_option('wp_login_shield_banned_ips', $banned_ips);
            return true;
        }
        return false;
    }

    /**
     * Handle failed login attempts
     * 
     * @param string $username Username or email
     */
    public function handle_failed_login($username) {
        // First, track this login attempt if tracking is enabled
        if (get_option('wp_login_shield_enable_login_tracking', 0)) {
            $this->track_failed_login($username);
        }
        
        // Get visitor IP
        $ip = $this->get_client_ip();
        
        if (empty($ip)) {
            return;
        }
        
        // Get current banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        // If IP already exists, increment attempts
        if (isset($banned_ips[$ip])) {
            $banned_ips[$ip]['attempts']++;
            $banned_ips[$ip]['last_attempt'] = time();
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
     * @param string $password Password
     * @return null|WP_User|WP_Error
     */
    public function check_banned_ip($user, $username, $password) {
        // If already authenticated or no username/password, return
        if ($user instanceof WP_User || empty($username) || empty($password)) {
            return $user;
        }

        // Get visitor IP
        $ip = $this->get_client_ip();
        
        if (empty($ip)) {
            return $user;
        }
        
        // Get banned IPs
        $banned_ips = get_option('wp_login_shield_banned_ips', array());
        
        // Check if current IP is banned
        if (isset($banned_ips[$ip])) {
            $data = $banned_ips[$ip];
            
            // Check if attempts exceeded limit
            if ($data['attempts'] >= $this->max_login_attempts) {
                // Check if ban period has expired
                $ban_expiry = $data['last_attempt'] + ($this->ban_duration * HOUR_IN_SECONDS);
                
                if (time() < $ban_expiry) {
                    // Still banned
                    $time_left = $ban_expiry - time();
                    $hours = floor($time_left / 3600);
                    $minutes = floor(($time_left / 60) % 60);
                    
                    // Return error with remaining time
                    return new WP_Error(
                        'ip_banned',
                        sprintf(
                            __('Your IP has been temporarily banned due to too many failed login attempts. Please try again in %d hours and %d minutes.', 'wp-login-shield'),
                            $hours,
                            $minutes
                        )
                    );
                } else {
                    // Ban expired, remove from list
                    unset($banned_ips[$ip]);
                    update_option('wp_login_shield_banned_ips', $banned_ips);
                }
            }
        }
        
        return $user;
    }

    /**
     * Get client IP address
     * 
     * @return string|null IP address or null if not found
     */
    public function get_client_ip() {
        // Check for proxy
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key]) && filter_var($_SERVER[$key], FILTER_VALIDATE_IP)) {
                return $_SERVER[$key];
            }
        }
        
        // If no IP found
        return null;
    }

    /**
     * Change the login URL
     *
     * @param string $url The URL
     * @param string $path The path
     * @param string $scheme The URL scheme
     * @param int $blog_id The blog ID
     * @return string
     */
    public function change_login_url($url, $path, $scheme, $blog_id) {
        if ($path == 'wp-login.php') {
            return site_url($this->login_path, $scheme);
        }
        return $url;
    }

    /**
     * Block direct access to wp-login.php
     */
    public function block_wp_login() {
        global $pagenow;
        
        $request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        // If someone is trying to access wp-login.php directly
        if ($pagenow == 'wp-login.php' && trim($request_uri, '/') != $this->login_path && !isset($_GET['action']) && !isset($_GET['wp-loginshield'])) {
            // Record the access attempt if monitoring is enabled
            if ($this->login_access_monitoring_enabled) {
                $this->record_login_page_access();
            }
            
            // Block access to wp-login.php
            wp_redirect(home_url('404'));
            exit;
        }
        
        // If someone is accessing our custom login URL
        if (!is_admin() && (trim($request_uri, '/') == $this->login_path)) {
            // Check IP whitelist if enabled
            if ($this->ip_whitelist_enabled) {
                $this->check_ip_whitelist();
            }
            
            // Record the access attempt if monitoring is enabled
            if ($this->login_access_monitoring_enabled) {
                $this->record_login_page_access();
            }
            
            // Set a flag
            $_GET['custom-login'] = 1;
            
            // Include the wp-login.php file
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Add custom rewrite rules
     */
    public function add_rewrite_rules() {
        add_rewrite_rule(
            '^' . $this->login_path . '/?$',
            'wp-login.php',
            'top'
        );
        
        add_rewrite_rule(
            '^' . $this->login_path . '/(.+)/?$',
            'wp-login.php?action=$1',
            'top'
        );
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook) {
        if ('settings_page_wp-loginshield' != $hook) {
            return;
        }
        
        // Enqueue JavaScript
        wp_enqueue_script(
            'wp-loginshield-admin',
            plugin_dir_url(dirname(__FILE__)) . 'admin/js/wp-login-shield-admin.js',
            array('jquery'),
            WP_LOGINSHIELD_VERSION,
            true
        );
        
        // Enqueue CSS
        wp_enqueue_style(
            'wp-loginshield-admin',
            plugin_dir_url(dirname(__FILE__)) . 'admin/css/wp-login-shield-admin.css',
            array(),
            WP_LOGINSHIELD_VERSION
        );
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Add default option if it doesn't exist
        if (!get_option('wp_login_shield')) {
            add_option('wp_login_shield', $this->default_path);
        }

        // Add IP ban option if it doesn't exist
        if (!get_option('wp_login_shield_enable_ip_ban')) {
            add_option('wp_login_shield_enable_ip_ban', 0);
        }

        // Add login tracking option if it doesn't exist
        if (!get_option('wp_login_shield_enable_login_tracking')) {
            add_option('wp_login_shield_enable_login_tracking', 0);
        }

        // Add timezone option if it doesn't exist
        if (!get_option('wp_login_shield_timezone')) {
            add_option('wp_login_shield_timezone', '');
        }

        // Add time format option if it doesn't exist
        if (!get_option('wp_login_shield_time_format')) {
            add_option('wp_login_shield_time_format', '24');
        }

        // Add IP whitelist option if it doesn't exist
        if (!get_option('wp_login_shield_enable_ip_whitelist')) {
            add_option('wp_login_shield_enable_ip_whitelist', 0);
        }
        
        // Add IP whitelist IPs if it doesn't exist
        if (!get_option('wp_login_shield_whitelist_ips')) {
            // Add current user's IP by default to prevent lockout
            $current_ip = $this->get_client_ip();
            add_option('wp_login_shield_whitelist_ips', $current_ip);
        }

        // Add login access monitoring option if it doesn't exist
        if (!get_option('wp_login_shield_enable_login_access_monitoring')) {
            add_option('wp_login_shield_enable_login_access_monitoring', 0);
        }

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Format datetime according to plugin settings
     *
     * @param int $timestamp Unix timestamp
     * @return string Formatted date and time
     */
    public function format_datetime($timestamp) {
        // Ensure timestamp is valid and not empty
        if (empty($timestamp) || !is_numeric($timestamp) || $timestamp <= 0) {
            $timestamp = time(); // Use current time as fallback
        }
        
        // Get current timezone
        $timezone_string = $this->timezone;
        
        // If using WordPress default, get the WordPress timezone
        if (empty($timezone_string)) {
            $timezone_string = get_option('timezone_string');
            
            // If no timezone string, use offset
            if (empty($timezone_string)) {
                $gmt_offset = get_option('gmt_offset');
                $timezone_string = $gmt_offset >= 0 ? "+$gmt_offset" : "$gmt_offset";
                $timezone_string = 'UTC' . $timezone_string;
            }
        }
        
        // Set the timezone if it's not empty
        if (!empty($timezone_string)) {
            $timezone = new DateTimeZone($timezone_string);
            
            // Convert timestamp to DateTime
            $datetime = new DateTime();
            $datetime->setTimestamp($timestamp);
            $datetime->setTimezone($timezone);
            
            // Format according to WordPress date format
            $date_format = get_option('date_format');
            
            // Use selected time format
            $time_format = $this->time_format === '12' ? 'g:i A' : 'H:i';
            
            return $datetime->format($date_format . ' ' . $time_format);
        } else {
            // Fallback to WordPress default formatting
            $date_format = get_option('date_format');
            $time_format = $this->time_format === '12' ? 'g:i A' : 'H:i';
            
            return date_i18n($date_format . ' ' . $time_format, $timestamp);
        }
    }

    /**
     * Sanitize the whitelist IPs
     *
     * @param string $input The input string of IPs
     * @return string Sanitized list of IPs
     */
    public function sanitize_whitelist_ips($input) {
        // Split by line breaks
        $ips = preg_split('/\r\n|\r|\n/', $input);
        $valid_ips = array();
        
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (empty($ip)) continue;
            
            // Validate IP address format
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid_ips[] = $ip;
            }
        }
        
        // Make sure current IP is always in the list to prevent lockout
        $current_ip = $this->get_client_ip();
        if (!in_array($current_ip, $valid_ips)) {
            $valid_ips[] = $current_ip;
        }
        
        return implode("\n", $valid_ips);
    }

    /**
     * Check if the current IP is whitelisted
     */
    public function check_ip_whitelist() {
        // Skip if IP whitelist is not enabled
        if (!$this->ip_whitelist_enabled) {
            return;
        }
        
        $client_ip = $this->get_client_ip();
        if (empty($client_ip)) {
            return;
        }
        
        // Get whitelisted IPs
        $whitelist_ips = $this->whitelist_ips;
        
        // Convert string to array if needed
        if (is_string($whitelist_ips)) {
            $whitelist_ips = preg_split('/\r\n|\r|\n/', $whitelist_ips);
            $whitelist_ips = array_map('trim', $whitelist_ips);
            $whitelist_ips = array_filter($whitelist_ips);
        }
        
        // If whitelist is empty, don't block anyone
        if (empty($whitelist_ips)) {
            return;
        }
        
        // If IP is not in the whitelist, block access
        if (!in_array($client_ip, $whitelist_ips)) {
            wp_die(
                __('Access to the login page from your IP address is not allowed.', 'wp-loginshield'),
                __('Access Denied', 'wp-loginshield'),
                array('response' => 403)
            );
        }
    }

    /**
     * Record login page access attempt
     */
    public function record_login_page_access() {
        // Get visitor information
        $ip = $this->get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : __('Unknown', 'wp-loginshield');
        $http_referrer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : __('Direct access', 'wp-loginshield');
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : __('Unknown', 'wp-loginshield');
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : __('Unknown', 'wp-loginshield');
        $remote_host = isset($_SERVER['REMOTE_HOST']) ? $_SERVER['REMOTE_HOST'] : gethostbyaddr($ip);
        
        // Check if the IP is whitelisted
        $is_whitelisted = false;
        if ($this->ip_whitelist_enabled) {
            // Convert whitelist to array if needed
            $whitelist_ips = $this->whitelist_ips;
            if (is_string($whitelist_ips)) {
                $whitelist_ips = preg_split('/\r\n|\r|\n/', $whitelist_ips);
                $whitelist_ips = array_map('trim', $whitelist_ips);
                $whitelist_ips = array_filter($whitelist_ips);
            }
            
            $is_whitelisted = in_array($ip, $whitelist_ips);
        }
        
        // Get query parameters (for security analysis)
        $query_params = $_GET;
        // Remove sensitive data
        if (isset($query_params['pwd'])) {
            $query_params['pwd'] = '[REDACTED]';
        }
        if (isset($query_params['password'])) {
            $query_params['password'] = '[REDACTED]';
        }
        
        // Get current login access records
        $access_records = get_option('wp_login_shield_access_records', array());
        
        // Add new record
        $access_records[] = array(
            'time' => time(),
            'ip' => $ip,
            'user_agent' => $user_agent,
            'http_referrer' => $http_referrer,
            'request_uri' => $request_uri,
            'request_method' => $request_method,
            'remote_host' => $remote_host,
            'is_whitelisted' => $is_whitelisted,
            'query_params' => json_encode($query_params)
        );
        
        // Limit the number of records we store
        if (count($access_records) > $this->max_login_access_records) {
            $access_records = array_slice($access_records, -$this->max_login_access_records);
        }
        
        // Update the option
        update_option('wp_login_shield_access_records', $access_records);
    }

    /**
     * Display access monitoring page
     */
    public function display_access_monitoring_page() {
        // Add custom styling for access monitoring page
        ?>
        <style>
            /* Info box styling */
            .access-info-box {
                background-color: #f8f9fa;
                border-left: 4px solid #0073aa;
                padding: 15px 20px;
                margin-bottom: 25px;
                border-radius: 3px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            }
            
            /* Table layout improvements */
            .access-monitoring-table {
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
            }
            
            .access-monitoring-table th {
                background-color: #f1f1f1;
                padding: 12px 15px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid #ddd;
            }
            
            .access-monitoring-table td {
                padding: 10px 15px;
                border-bottom: 1px solid #eee;
                vertical-align: middle;
            }
            
            .access-monitoring-table tr:hover {
                background-color: #f9f9f9;
            }
            
            /* Fixed width columns for better layout */
            .access-monitoring-table .column-date {
                width: 150px;
            }
            
            .access-monitoring-table .column-ip {
                width: 120px;
            }
            
            .access-monitoring-table .column-host {
                width: 120px;
            }
            
            .access-monitoring-table .column-uri {
                width: 150px;
            }
            
            .access-monitoring-table .column-referrer {
                width: 150px;
            }
            
            .access-monitoring-table .column-whitelist {
                width: 100px;
                text-align: center;
            }
            
            .access-monitoring-table .column-details {
                width: 80px;
                text-align: center;
            }
            
            /* Status indicators */
            .access-status {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: 500;
            }
            
            .access-status-yes {
                background-color: #d4edda;
                color: #155724;
            }
            
            .access-status-no {
                background-color: #f8d7da;
                color: #721c24;
            }
            
            /* User agent column with ellipsis */
            .user-agent-cell {
                max-width: 250px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            /* View details button */
            .view-details-button {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                color: #0073aa;
                border-radius: 3px;
                padding: 4px 10px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s ease;
            }
            
            .view-details-button:hover {
                background-color: #0073aa;
                border-color: #0073aa;
                color: #fff;
            }
            
            /* Details modal styling */
            #access-details-modal {
                position: fixed;
                z-index: 100000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0, 0, 0, 0.5);
                display: none;
            }
            
            .modal-content {
                background-color: #fefefe;
                margin: 5% auto;
                padding: 25px;
                border: 1px solid #ddd;
                width: 80%;
                max-width: 800px;
                border-radius: 4px;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
                position: relative;
            }
            
            .close-modal {
                position: absolute;
                top: 15px;
                right: 20px;
                color: #aaa;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
                transition: color 0.2s ease;
            }
            
            .close-modal:hover {
                color: #333;
            }
            
            #access-details-content {
                margin-top: 15px;
            }
            
            #access-details-content table {
                width: 100%;
                border-collapse: collapse;
            }
            
            #access-details-content th {
                width: 25%;
                text-align: left;
                padding: 10px;
                background-color: #f8f9fa;
                border: 1px solid #eee;
            }
            
            #access-details-content td {
                padding: 10px;
                border: 1px solid #eee;
                word-break: break-word;
            }
            
            /* Action buttons */
            .action-buttons {
                margin: 20px 0;
                display: flex;
                justify-content: space-between;
            }
            
            .action-buttons .export-button {
                background-color: #0073aa;
                color: #fff;
                border: none;
                padding: 8px 16px;
                border-radius: 3px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                transition: background-color 0.2s ease;
            }
            
            .action-buttons .export-button:hover {
                background-color: #005f8b;
            }
            
            .action-buttons .clear-button {
                background-color: #f8f9fa;
                color: #333;
                border: 1px solid #ddd;
                padding: 8px 16px;
                border-radius: 3px;
                cursor: pointer;
                transition: all 0.2s ease;
            }
            
            .action-buttons .clear-button:hover {
                background-color: #f1f1f1;
                border-color: #ccc;
            }
            
            /* Title styling */
            .access-records-title {
                font-size: 18px;
                margin: 30px 0 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #eee;
            }
            
            /* Empty state */
            .no-records {
                background-color: #f8f9fa;
                padding: 25px;
                text-align: center;
                border-radius: 4px;
                color: #555;
                margin: 30px 0;
                border: 1px solid #eee;
            }
        </style>
        <?php
        
        if (!get_option('wp_login_shield_enable_login_access_monitoring', 0)) {
            echo '<div class="notice notice-error"><p>' . __('Login access monitoring is not enabled. Please enable it in the settings tab.', 'wp-loginshield') . '</p></div>';
            return;
        }
        
        // Handle clear all records action
        if (isset($_POST['clear_all_access_records']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'clear_all_access_records')) {
            update_option('wp_login_shield_access_records', array());
            echo '<div class="notice notice-success is-dismissible"><p>' . __('All access monitoring records have been cleared.', 'wp-loginshield') . '</p></div>';
        }
        
        // Get access records
        $access_records = get_option('wp_login_shield_access_records', array());
        
        // Display info card
        ?>
        <div class="wp-loginshield-info">
            <p><?php _e('This page shows all recorded attempts to access your login page.', 'wp-loginshield'); ?></p>
            <p><?php _e('Both standard wp-login.php and your custom login path are monitored.', 'wp-loginshield'); ?></p>
        </div>

        <div class="access-info-box">
            <p><?php _e('Total Access Records:', 'wp-loginshield'); ?> <strong><?php echo count($access_records); ?></strong></p>
            <div class="action-buttons">
                <a href="<?php echo wp_nonce_url(admin_url('options-general.php?page=wp-loginshield&tab=access-monitoring&export_access_records=1'), 'export_access_records'); ?>" class="export-button">
                    <?php _e('Export as CSV', 'wp-loginshield'); ?>
                </a>
                <button type="button" class="clear-button" onclick="confirmClearAccessRecords()"><?php _e('Clear All Records', 'wp-loginshield'); ?></button>
            </div>
        </div>

        <?php if (empty($access_records)): ?>
            <div class="no-records"><?php _e('No access records found.', 'wp-loginshield'); ?></div>
        <?php else: ?>
            <table class="access-monitoring-table">
                <thead>
                    <tr>
                        <th class="column-date"><?php _e('Date/Time', 'wp-loginshield'); ?></th>
                        <th class="column-ip"><?php _e('IP Address', 'wp-loginshield'); ?></th>
                        <th class="column-host"><?php _e('Host', 'wp-loginshield'); ?></th>
                        <th class="column-uri"><?php _e('Request URI', 'wp-loginshield'); ?></th>
                        <th class="column-referrer"><?php _e('Referrer', 'wp-loginshield'); ?></th>
                        <th class="column-whitelist"><?php _e('Whitelisted', 'wp-loginshield'); ?></th>
                        <th class="column-details"><?php _e('Details', 'wp-loginshield'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    // Show newest first
                    $access_records = array_reverse($access_records);
                    
                    foreach ($access_records as $record): 
                        $whitelist_class = !empty($record['is_whitelisted']) ? 'access-status-yes' : 'access-status-no';
                    ?>
                        <tr>
                            <td><?php echo $this->format_datetime($record['time']); ?></td>
                            <td><?php echo esc_html($record['ip']); ?></td>
                            <td><?php echo esc_html($record['remote_host']); ?></td>
                            <td><?php echo esc_html($record['request_uri']); ?></td>
                            <td><?php echo esc_html($record['http_referrer']); ?></td>
                            <td><span class="access-status <?php echo esc_attr($whitelist_class); ?>"><?php echo !empty($record['is_whitelisted']) ? __('Yes', 'wp-loginshield') : __('No', 'wp-loginshield'); ?></span></td>
                            <td class="user-agent-cell"><?php echo esc_html($record['user_agent']); ?></td>
                            <td>
                                <button type="button" class="button button-small view-details-button" data-details="<?php echo esc_attr(json_encode($record)); ?>">
                                    <?php _e('View', 'wp-loginshield'); ?>
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        
        <!-- Details Modal -->
        <div id="access-details-modal" style="display: none; position: fixed; z-index: 999; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
            <div style="background-color: #fefefe; margin: 10% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 800px;">
                <span style="color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer;" class="close-modal">&times;</span>
                <h3><?php _e('Access Attempt Details', 'wp-loginshield'); ?></h3>
                <div id="access-details-content"></div>
            </div>
        </div>
        
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // View details button
                $('.view-details-button').click(function() {
                    var details = $(this).data('details');
                    var content = '<table class="widefat">';
                    
                    // Timestamp
                    content += '<tr><th><?php _e('Date/Time', 'wp-loginshield'); ?></th><td>' + details.formatted_time + '</td></tr>';
                    
                    // IP and host
                    content += '<tr><th><?php _e('IP Address', 'wp-loginshield'); ?></th><td>' + details.ip + '</td></tr>';
                    content += '<tr><th><?php _e('Remote Host', 'wp-loginshield'); ?></th><td>' + details.remote_host + '</td></tr>';
                    
                    // Request details
                    content += '<tr><th><?php _e('Request Method', 'wp-loginshield'); ?></th><td>' + details.request_method + '</td></tr>';
                    content += '<tr><th><?php _e('Request URI', 'wp-loginshield'); ?></th><td>' + details.request_uri + '</td></tr>';
                    content += '<tr><th><?php _e('HTTP Referrer', 'wp-loginshield'); ?></th><td>' + details.http_referrer + '</td></tr>';
                    
                    // Query params if available
                    if (details.query_params) {
                        try {
                            var params = JSON.parse(details.query_params);
                            var paramStr = '';
                            for (var key in params) {
                                if (params.hasOwnProperty(key)) {
                                    paramStr += key + ': ' + params[key] + '<br>';
                                }
                            }
                            content += '<tr><th><?php _e('Query Parameters', 'wp-loginshield'); ?></th><td>' + (paramStr || 'None') + '</td></tr>';
                        } catch(e) {
                            content += '<tr><th><?php _e('Query Parameters', 'wp-loginshield'); ?></th><td>Error parsing parameters</td></tr>';
                        }
                    }
                    
                    // User agent
                    content += '<tr><th><?php _e('User Agent', 'wp-loginshield'); ?></th><td>' + details.user_agent + '</td></tr>';
                    
                    // Whitelist status
                    content += '<tr><th><?php _e('Whitelisted IP', 'wp-loginshield'); ?></th><td>' + (details.is_whitelisted ? '<?php _e('Yes', 'wp-loginshield'); ?>' : '<?php _e('No', 'wp-loginshield'); ?>') + '</td></tr>';
                    
                    content += '</table>';
                    
                    $('#access-details-content').html(content);
                    $('#access-details-modal').show();
                });
                
                // Close modal
                $('.close-modal').click(function() {
                    $('#access-details-modal').hide();
                });
                
                // Close modal when clicking outside
                $(window).click(function(e) {
                    if ($(e.target).is('#access-details-modal')) {
                        $('#access-details-modal').hide();
                    }
                });
            });
        </script>

        <?php
    }

    /**
     * Export access records as CSV
     */
    public function export_access_records() {
        // Check nonce and permissions
        if (!current_user_can('manage_options') || !check_admin_referer('export_access_records')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'wp-loginshield'));
        }
        
        $access_records = get_option('wp_login_shield_access_records', array());
        
        if (empty($access_records)) {
            return;
        }
        
        // Set headers for CSV download
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=login-access-records-' . date('Y-m-d') . '.csv');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        // Create output stream
        $output = fopen('php://output', 'w');
        
        // Add CSV headers
        fputcsv($output, array(
            __('Date/Time', 'wp-loginshield'),
            __('IP Address', 'wp-loginshield'),
            __('Remote Host', 'wp-loginshield'),
            __('Request URI', 'wp-loginshield'),
            __('Request Method', 'wp-loginshield'),
            __('HTTP Referrer', 'wp-loginshield'),
            __('Whitelisted', 'wp-loginshield'),
            __('User Agent', 'wp-loginshield'),
            __('Query Parameters', 'wp-loginshield')
        ));
        
        // Sort records by time (newest first)
        usort($access_records, function($a, $b) {
            return $b['time'] - $a['time'];
        });
        
        // Add data
        foreach ($access_records as $record) {
            fputcsv($output, array(
                $this->format_datetime($record['time']),
                $record['ip'],
                $record['remote_host'],
                $record['request_uri'],
                $record['request_method'],
                $record['http_referrer'],
                !empty($record['is_whitelisted']) ? __('Yes', 'wp-loginshield') : __('No', 'wp-loginshield'),
                $record['user_agent'],
                isset($record['query_params']) ? $record['query_params'] : ''
            ));
        }
        
        fclose($output);
        exit;
    }

    /**
     * Display about page
     */
    public function display_about_page() {
        ?>
        <style>
            .wls-about-wrapper {
                max-width: 1100px;
                margin: 25px 0;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            }
            /* Professional header */
            .wls-about-header {
                margin-bottom: 30px;
            }
            .wls-about-header h2 {
                font-size: 24px;
                font-weight: 500;
                margin: 0;
                color: #1d2327;
                padding-bottom: 10px;
                border-bottom: 1px solid #eee;
            }
            /* Author card with modern design */
            .wls-author-card {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                margin-bottom: 40px;
                overflow: hidden;
                display: flex;
            }
            .wls-author-sidebar {
                width: 260px;
                padding: 30px;
                background: linear-gradient(135deg, #0073aa, #005280);
                color: #fff;
                text-align: center;
            }
            .wls-author-sidebar .wls-avatar {
                width: 120px;
                height: 120px;
                border-radius: 50%;
                margin: 0 auto 20px;
                overflow: hidden;
                border: 4px solid rgba(255,255,255,0.3);
                position: relative;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }
            
            .wls-author-sidebar .wls-avatar img {
                width: 100%;
                height: 100%;
                object-fit: cover;
                object-position: center;
                position: absolute;
                top: 0;
                left: 0;
            }
            .wls-author-name {
                font-size: 20px;
                font-weight: 600;
                margin-bottom: 5px;
                text-shadow: 0 1px 2px rgba(0,0,0,0.1);
            }
            .wls-author-title {
                font-size: 14px;
                opacity: 0.9;
                margin-bottom: 15px;
                text-shadow: 0 1px 2px rgba(0,0,0,0.1);
            }
            .wls-content {
                flex: 1;
                padding: 35px 40px;
                background: linear-gradient(to bottom, #f9f9f9, #fff);
            }
            .wls-bio {
                color: #333;
                font-size: 15px;
                line-height: 1.7;
                margin-bottom: 30px;
            }
            .wls-bio p {
                margin: 0 0 15px 0;
            }
            .wls-cta-buttons {
                display: flex;
                gap: 15px;
            }
            .wls-cta-button {
                display: inline-flex;
                align-items: center;
                padding: 10px 22px;
                border-radius: 5px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.2s ease;
                box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            }
            .wls-cta-button .dashicons {
                margin-right: 8px;
                font-size: 16px;
                width: 16px;
                height: 16px;
            }
            .wls-cta-button.primary {
                background: #0073aa;
                color: #fff;
                border: none;
            }
            .wls-cta-button.primary:hover {
                background: #005f8b;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            .wls-cta-button.secondary {
                background: #f8f9fa;
                color: #2c3338;
                border: 1px solid #dcdcde;
            }
            .wls-cta-button.secondary:hover {
                background: #f0f0f1;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }
            
            /* Sections with common styling */
            .wls-section {
                margin: 80px 0;
                clear: both;
                padding-top: 20px;
            }
            .wls-section-title {
                font-size: 20px;
                font-weight: 600;
                margin: 0 0 35px 0;
                padding-bottom: 15px;
                border-bottom: 1px solid #eee;
                color: #1d2327;
                position: relative;
                clear: both;
            }
            .wls-section-title:after {
                content: "";
                position: absolute;
                bottom: -1px;
                left: 0;
                width: 60px;
                height: 3px;
                background: #0073aa;
            }
            
            /* Services section with card layout */
            .wls-services-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 30px;
                margin-bottom: 40px;
            }
            .wls-service-card {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                padding: 25px;
                transition: all 0.3s ease;
                border: 1px solid #f0f0f1;
                height: 100%;
                display: flex;
                flex-direction: column;
            }
            .wls-service-card:hover {
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                transform: translateY(-3px);
            }
            .wls-service-icon {
                color: #0073aa;
                font-size: 26px;
                margin-bottom: 18px;
                display: inline-block;
                background: rgba(0,115,170,0.1);
                width: 50px;
                height: 50px;
                line-height: 50px;
                text-align: center;
                border-radius: 50%;
            }
            .wls-service-title {
                font-size: 16px;
                font-weight: 600;
                margin: 0 0 12px 0;
                color: #1d2327;
            }
            .wls-service-desc {
                font-size: 14px;
                line-height: 1.6;
                color: #555;
                margin: 0;
                flex-grow: 1;
            }
            
            /* Features section with elegant design */
            .wls-features-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 30px;
                margin-bottom: 40px;
            }
            .wls-feature-card {
                background: #fff;
                border-radius: 8px;
                padding: 25px;
                transition: all 0.3s ease;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                border: 1px solid #f0f0f1;
                position: relative;
                height: 100%;
                display: flex;
                flex-direction: column;
            }
            .wls-feature-card:hover {
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                transform: translateY(-3px);
            }
            .wls-feature-icon {
                width: 50px;
                height: 50px;
                border-radius: 50%;
                background: rgba(0,115,170,0.1);
                display: flex;
                align-items: center;
                justify-content: center;
                margin-bottom: 18px;
            }
            .wls-feature-icon .dashicons {
                color: #0073aa;
                font-size: 20px;
            }
            .wls-feature-title {
                font-size: 16px;
                font-weight: 600;
                margin: 0 0 12px 0;
                color: #1d2327;
            }
            .wls-feature-desc {
                font-size: 14px;
                line-height: 1.6;
                color: #555;
                margin: 0;
                flex-grow: 1;
            }
            
            /* Review section with clean design */
            .wls-review-section {
                margin: 80px 0;
                padding-top: 20px;
                clear: both;
            }
            .wls-review-card {
                background: #fff;
                border-radius: 8px;
                padding: 25px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                margin-bottom: 20px;
                border-left: 4px solid #0073aa;
                position: relative;
            }
            .wls-review-card:before {
                content: "\201C"; /* Unicode for left double quotation mark */
                position: absolute;
                top: 15px;
                left: 15px;
                font-size: 60px;
                line-height: 1;
                font-family: Georgia, serif;
                color: rgba(0,115,170,0.1);
            }
            .wls-review-text {
                font-size: 15px;
                line-height: 1.7;
                color: #333;
                font-style: italic;
                margin-bottom: 20px;
                padding-left: 40px;
            }
            .wls-review-author {
                display: flex;
                align-items: center;
                justify-content: flex-end;
                font-weight: 600;
                color: #555;
            }
            
            /* Call to action section */
            .wls-cta-section {
                background: #f9f9f9;
                border-radius: 8px;
                padding: 40px;
                text-align: center;
                margin: 80px 0 40px;
                border: 1px solid #eee;
                clear: both;
            }
            .wls-cta-section h3 {
                font-size: 18px;
                font-weight: 600;
                margin: 0 0 15px 0;
                color: #1d2327;
            }
            .wls-cta-section p {
                font-size: 15px;
                line-height: 1.6;
                margin: 0 0 20px 0;
                color: #555;
            }
            
            /* Footer credit */
            .wls-footer-credit {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #777;
                font-size: 13px;
                text-align: center;
            }
            .wls-footer-credit a {
                color: #0073aa;
                text-decoration: none;
            }
            .wls-footer-credit a:hover {
                color: #0096dd;
                text-decoration: underline;
            }

            /* Responsive design */
            @media screen and (max-width: 782px) {
                .wls-author-card {
                    flex-direction: column;
                }
                .wls-author-sidebar {
                    width: 100%;
                    box-sizing: border-box;
                }
                .wls-services-grid, .wls-features-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
            }
            @media screen and (max-width: 600px) {
                .wls-services-grid, .wls-features-grid {
                    grid-template-columns: 1fr;
                }
                .wls-cta-buttons {
                    flex-direction: column;
                }
            }
        </style>
        
        <div class="wls-about-wrapper">
            <div class="wls-about-header">
                <h2><?php _e('About WP LoginShield', 'wp-loginshield'); ?></h2>
            </div>
            
            <div class="wls-author-card">
                <div class="wls-author-sidebar">
                    <div class="wls-avatar">
                        <img src="<?php echo plugins_url('/admin/images/author-avatar.jpeg', dirname(__FILE__)); ?>" 
                             alt="<?php _e('Budhilaw - WordPress Developer', 'wp-loginshield'); ?>"
                             onerror="this.src='<?php echo admin_url('images/wordpress-logo.svg'); ?>'; this.style.background='#0073aa'; this.style.padding='10px';">
                    </div>
                    <div class="wls-author-name"><?php _e('Budhilaw', 'wp-loginshield'); ?></div>
                    <div class="wls-author-title"><?php _e('Software Engineer', 'wp-loginshield'); ?></div>
                </div>
                <div class="wls-content">
                    <div class="wls-bio">
                        <p><?php _e('Hi, I\'m Ericsson Budhilaw, a WordPress developer specializing in custom themes, plugins, and security solutions. With extensive experience in WordPress development, I create high-quality, secure, and efficient solutions for businesses of all sizes.', 'wp-loginshield'); ?></p>
                        <p><?php _e('WP LoginShield is just one of my security-focused plugins designed to help website owners protect their WordPress installations from common attack vectors.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-cta-buttons">
                        <a href="https://budhilaw.com/contact" class="wls-cta-button primary" target="_blank">
                            <span class="dashicons dashicons-email"></span>
                            <?php _e('Hire Me for Custom Work', 'wp-loginshield'); ?>
                        </a>
                        <a href="https://budhilaw.com/portfolio" class="wls-cta-button secondary" target="_blank">
                            <span class="dashicons dashicons-portfolio"></span>
                            <?php _e('View My Portfolio', 'wp-loginshield'); ?>
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="wls-section">
                <h3 class="wls-section-title"><?php _e('Professional WordPress Services', 'wp-loginshield'); ?></h3>
                <div class="wls-services-grid">
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-admin-appearance"></span>
                        <h4 class="wls-service-title"><?php _e('Custom Theme Development', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Unique, responsive themes tailored to your brand identity and business requirements.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-admin-plugins"></span>
                        <h4 class="wls-service-title"><?php _e('Custom Plugin Development', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Specialized plugins to add custom functionality to your WordPress website.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-shield"></span>
                        <h4 class="wls-service-title"><?php _e('WordPress Security', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Comprehensive security audits and hardening to protect your site from threats.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-performance"></span>
                        <h4 class="wls-service-title"><?php _e('Performance Optimization', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Speed up your WordPress site and improve user experience with expert optimization.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-cart"></span>
                        <h4 class="wls-service-title"><?php _e('WooCommerce Solutions', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Custom e-commerce development, payment gateways, and shopping cart optimizations.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-service-card">
                        <span class="wls-service-icon dashicons dashicons-hammer"></span>
                        <h4 class="wls-service-title"><?php _e('Maintenance & Support', 'wp-loginshield'); ?></h4>
                        <p class="wls-service-desc"><?php _e('Ongoing maintenance, updates, and support to keep your WordPress site running smoothly.', 'wp-loginshield'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="wls-section">
                <h3 class="wls-section-title wls-section-title-key-features"><?php _e('Key Features of WP LoginShield', 'wp-loginshield'); ?></h3>
                <div class="wls-features-grid">
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-admin-network"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('Custom Login URL', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('Hide your login page from bots and attackers by using a custom login URL.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-shield"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('IP Banning', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('Automatically block IP addresses after multiple failed login attempts.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-chart-line"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('Login Monitoring', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('Track and analyze all login attempts to your WordPress site.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-lock"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('IP Whitelist', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('Restrict login page access to only trusted IP addresses.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-visibility"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('Access Monitoring', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('See who attempts to access your login page, even before they log in.', 'wp-loginshield'); ?></p>
                    </div>
                    <div class="wls-feature-card">
                        <div class="wls-feature-icon">
                            <span class="dashicons dashicons-chart-bar"></span>
                        </div>
                        <h4 class="wls-feature-title"><?php _e('Data Export', 'wp-loginshield'); ?></h4>
                        <p class="wls-feature-desc"><?php _e('Export security data as CSV files for further analysis and reporting.', 'wp-loginshield'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="wls-review-section">
                <div class="wls-review-card">
                    <div class="wls-review-text"><?php _e('"WP LoginShield has been a game-changer for our website security. The custom login URL feature alone has dramatically reduced bot attacks. Highly recommended!"', 'wp-loginshield'); ?></div>
                    <div class="wls-review-author"><?php _e('— John Smith, Website Owner', 'wp-loginshield'); ?></div>
                </div>
            </div>
            
            <div class="wls-cta-section">
                <h3><?php _e('Enjoying WP LoginShield?', 'wp-loginshield'); ?></h3>
                <p><?php _e('If you find this plugin useful, please consider rating it on WordPress.org or supporting future development.', 'wp-loginshield'); ?></p>
                <div class="wls-cta-buttons" style="justify-content: center;">
                    <a href="https://wordpress.org/support/plugin/wp-loginshield/reviews/#new-post" class="wls-cta-button primary" target="_blank">
                        <span class="dashicons dashicons-star-filled"></span>
                        <?php _e('Leave a Review', 'wp-loginshield'); ?>
                    </a>
                    <a href="https://budhilaw.com/donate" class="wls-cta-button secondary" target="_blank">
                        <span class="dashicons dashicons-heart"></span>
                        <?php _e('Support Development', 'wp-loginshield'); ?>
                    </a>
                </div>
            </div>
            
            <div class="wls-footer-credit">
                <p>
                    <?php echo sprintf(__('WP LoginShield by %s - For custom WordPress development, please visit %s', 'wp-loginshield'), 
                        '<a href="https://budhilaw.com" target="_blank">Budhilaw</a>',
                        '<a href="https://budhilaw.com" target="_blank">budhilaw.com</a>'
                    ); ?>
                </p>
            </div>
        </div>
        <?php
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
        
        $request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $request_path = trim($request_uri, '/');
        
        // If accessing wp-login.php or custom login path, record it
        if ($pagenow == 'wp-login.php' || $request_path == $this->login_path || 
            strpos($request_uri, 'wp-login.php') !== false) {
            $this->record_login_page_access();
        }
    }
} 