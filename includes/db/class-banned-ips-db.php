<?php

/**
 * Banned IPs Database Class
 * 
 * Handles database operations for banned IPs
 *
 * @since      1.0.1
 * @package    WP_LoginShield
 */

class WP_LoginShield_Banned_IPs_DB {
    
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
        $this->table_name = $wpdb->prefix . 'loginshield_banned_ips';
    }
    
    /**
     * Generate UUID v4
     * 
     * @return string UUID v4
     */
    private function generate_uuid() {
        if (function_exists('random_bytes')) {
            $data = random_bytes(16);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $data = openssl_random_pseudo_bytes(16);
        } else {
            $data = '';
            for ($i = 0; $i < 16; $i++) {
                $data .= chr(mt_rand(0, 255));
            }
        }

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

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
            ip_address varchar(45) NOT NULL,
            banned_at datetime NOT NULL,
            banned_until datetime NOT NULL,
            reason text NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY banned_until (banned_until)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    /**
     * Add a banned IP record
     * 
     * @param string $ip_address The IP address to ban
     * @param string $reason The reason for banning
     * @param int $ban_duration Duration in hours (default 24 hours)
     * @return bool|int The number of rows inserted, or false on error
     */
    public function add_banned_ip($ip_address, $reason = '', $ban_duration = 24) {
        global $wpdb;
        
        $uuid = $this->generate_uuid();
        $now = current_time('mysql');
        $banned_until = date('Y-m-d H:i:s', strtotime("+{$ban_duration} hours", strtotime($now)));
        
        // Remove any existing ban for this IP
        $this->remove_banned_ip($ip_address);
        
        return $wpdb->insert(
            $this->table_name,
            array(
                'id' => $uuid,
                'ip_address' => $ip_address,
                'banned_at' => $now,
                'banned_until' => $banned_until,
                'reason' => $reason
            ),
            array(
                '%s', // id
                '%s', // ip_address
                '%s', // banned_at
                '%s', // banned_until
                '%s'  // reason
            )
        );
    }
    
    /**
     * Check if an IP is banned
     * 
     * @param string $ip_address The IP address to check
     * @return bool|array False if not banned, ban data if banned
     */
    public function is_ip_banned($ip_address) {
        global $wpdb;
        
        $now = current_time('mysql');
        
        $sql = $wpdb->prepare(
            "SELECT * FROM {$this->table_name} 
            WHERE ip_address = %s 
            AND banned_until > %s",
            $ip_address,
            $now
        );
        
        $result = $wpdb->get_row($sql, ARRAY_A);
        
        return $result ? $result : false;
    }
    
    /**
     * Remove a banned IP
     * 
     * @param string $ip_address The IP address to unban
     * @return bool|int The number of rows deleted, or false on error
     */
    public function remove_banned_ip($ip_address) {
        global $wpdb;
        
        return $wpdb->delete(
            $this->table_name,
            array('ip_address' => $ip_address),
            array('%s')
        );
    }
    
    /**
     * Get all banned IPs
     * 
     * @param bool $active_only Whether to get only active bans
     * @return array Array of banned IP records
     */
    public function get_banned_ips($active_only = true) {
        global $wpdb;
        
        $sql = "SELECT * FROM {$this->table_name}";
        
        if ($active_only) {
            $now = current_time('mysql');
            $sql .= $wpdb->prepare(" WHERE banned_until > %s", $now);
        }
        
        $sql .= " ORDER BY banned_at DESC";
        
        return $wpdb->get_results($sql, ARRAY_A);
    }
    
    /**
     * Clean up expired bans
     * 
     * @return int|false The number of rows deleted, or false on error
     */
    public function cleanup_expired_bans() {
        global $wpdb;
        
        $now = current_time('mysql');
        
        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table_name} WHERE banned_until <= %s",
                $now
            )
        );
    }
    
    /**
     * Clear all banned IPs
     * 
     * @return int|false The number of rows deleted, or false on error
     */
    public function clear_all_bans() {
        global $wpdb;
        return $wpdb->query("TRUNCATE TABLE {$this->table_name}");
    }
} 