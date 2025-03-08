<?php

/**
 * Login Tracking Database Class
 * 
 * Handles database operations for login tracking
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

class WP_LoginShield_Login_Tracking_DB {
    
    /**
     * Table name
     *
     * @var string
     */
    private $table_name;
    
    /**
     * Initialize the class
     */
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'loginshield_login_tracking';
    }
    
    /**
     * Generate UUID v4
     * 
     * @return string UUID v4
     */
    private function generate_uuid() {
        // Generate 16 bytes (128 bits) of random data
        if (function_exists('random_bytes')) {
            $data = random_bytes(16);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $data = openssl_random_pseudo_bytes(16);
        } else {
            // Fallback to mt_rand if no better method is available
            $data = '';
            for ($i = 0; $i < 16; $i++) {
                $data .= chr(mt_rand(0, 255));
            }
        }

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        // Output the 36 character UUID
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
    
    /**
     * Create the database table
     */
    public function create_table() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id char(36) NOT NULL,
            time datetime NOT NULL,
            ip varchar(45) NOT NULL,
            username varchar(255) NOT NULL,
            status varchar(20) NOT NULL,
            user_agent text NOT NULL,
            PRIMARY KEY (id),
            KEY ip (ip),
            KEY status (status),
            KEY time (time)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    /**
     * Add a login record
     * 
     * @param array $data Login record data
     * @return bool|int The number of rows inserted, or false on error
     */
    public function add_record($data) {
        global $wpdb;
        
        $uuid = $this->generate_uuid();
        
        return $wpdb->insert(
            $this->table_name,
            array(
                'id' => $uuid,
                'time' => date('Y-m-d H:i:s', $data['time']),
                'ip' => $data['ip'],
                'username' => $data['username'],
                'status' => $data['status'],
                'user_agent' => $data['user_agent']
            ),
            array(
                '%s', // id (UUID)
                '%s', // time
                '%s', // ip
                '%s', // username
                '%s', // status
                '%s'  // user_agent
            )
        );
    }
    
    /**
     * Get login records with pagination
     * 
     * @param int $per_page Number of records per page
     * @param int $page_number Page number
     * @return array Login records
     */
    public function get_records($per_page = 20, $page_number = 1) {
        global $wpdb;
        
        $sql = "SELECT * FROM {$this->table_name} ORDER BY time DESC";
        
        if ($per_page > 0) {
            $sql .= $wpdb->prepare(
                " LIMIT %d OFFSET %d",
                $per_page,
                ($page_number - 1) * $per_page
            );
        }
        
        return $wpdb->get_results($sql, ARRAY_A);
    }
    
    /**
     * Get total number of records
     * 
     * @return int Total number of records
     */
    public function get_total_records() {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name}");
    }
    
    /**
     * Delete old records
     * 
     * @param int $days Number of days to keep records for
     * @return int|false The number of rows deleted, or false on error
     */
    public function cleanup_old_records($days = 30) {
        global $wpdb;
        
        $date = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        
        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table_name} WHERE time < %s",
                $date
            )
        );
    }
    
    /**
     * Clear all records
     * 
     * @return int|false The number of rows deleted, or false on error
     */
    public function clear_all_records() {
        global $wpdb;
        return $wpdb->query("TRUNCATE TABLE {$this->table_name}");
    }
} 