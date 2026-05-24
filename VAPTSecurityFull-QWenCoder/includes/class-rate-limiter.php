<?php
/**
 * Rate Limiter.
 *
 * @package VAPT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class VAPT_Rate_Limiter {

    const OPTION_KEY          = 'vapt_rate_limit';
    const CRON_OPTION_KEY     = 'vapt_cron_rate_limit';
    const LOGIN_OPTION_KEY    = 'vapt_login_rate_limit';
    const BLOCKED_IPS_KEY     = 'vapt_blocked_ips';
    const WINDOW_MINUTES      = 1;          // 1 minute
    const CRON_WINDOW_HOURS   = 1;          // 1 hour
    const LOGIN_WINDOW_MINUTES = 15;        // 15 minutes
    const MAX_REQUESTS_PER_MIN = 10;        // default
    const MAX_CRON_REQUESTS_PER_HOUR = 60;  // default
    const MAX_LOGIN_ATTEMPTS = 5;           // default

    private $data = [];
    private $cron_data = [];
    private $login_data = [];

    public function __construct() {
        $stored = get_option( self::OPTION_KEY, '[]' );
        $this->data = json_decode( $stored, true );
        if ( ! is_array( $this->data ) ) {
            $this->data = [];
        }

        $stored_cron = get_option( self::CRON_OPTION_KEY, '[]' );
        $this->cron_data = json_decode( $stored_cron, true );
        if ( ! is_array( $this->cron_data ) ) {
            $this->cron_data = [];
        }

        $stored_login = get_option( self::LOGIN_OPTION_KEY, '[]' );
        $this->login_data = json_decode( $stored_login, true );
        if ( ! is_array( $this->login_data ) ) {
            $this->login_data = [];
        }
    }

    /**
     * Check if a regular request is allowed
     */
    public function allow_request(): bool {
        $ip   = $this->get_current_ip();
        $now  = time();

        // Skip rate limiting for localhost/internal requests
        if ( $this->is_local_or_loopback( $ip ) ) {
            return true;
        }

        if ( ! isset( $this->data[ $ip ] ) ) {
            $this->data[ $ip ] = [];
        }

        // Get settings
        $options = get_option( 'vapt_security_options', [] );
        $window_minutes = isset( $options['rate_limit_window'] ) ? absint( $options['rate_limit_window'] ) : self::WINDOW_MINUTES;
        $max_requests = isset( $options['rate_limit_max'] ) ? absint( $options['rate_limit_max'] ) : self::MAX_REQUESTS_PER_MIN;

        // Keep only timestamps within the window
        $this->data[ $ip ] = array_filter(
            $this->data[ $ip ],
            fn( $ts ) => ( $now - $ts ) <= $window_minutes * 60
        );

        // Check if limit exceeded
        if ( count( $this->data[ $ip ] ) >= $max_requests ) {
            // Block IP if too many violations
            $this->check_and_block_ip( $ip );
            return false;
        }

        $this->data[ $ip ][] = $now;
        $this->save();
        return true;
    }

    /**
     * Check if a cron request is allowed
     */
    public function allow_cron_request(): bool {
        $ip   = $this->get_current_ip();
        $now  = time();

        // Skip rate limiting for localhost/internal requests
        if ( $this->is_local_or_loopback( $ip ) ) {
            return true;
        }

        if ( ! isset( $this->cron_data[ $ip ] ) ) {
            $this->cron_data[ $ip ] = [];
        }

        // Get settings
        $options = get_option( 'vapt_security_options', [] );
        $max_cron_requests = isset( $options['cron_rate_limit'] ) ? absint( $options['cron_rate_limit'] ) : self::MAX_CRON_REQUESTS_PER_HOUR;

        // Keep only timestamps within the window (1 hour)
        $this->cron_data[ $ip ] = array_filter(
            $this->cron_data[ $ip ],
            fn( $ts ) => ( $now - $ts ) <= self::CRON_WINDOW_HOURS * 3600
        );

        // Check if limit exceeded
        if ( count( $this->cron_data[ $ip ] ) >= $max_cron_requests ) {
            // Block IP
            $this->block_ip( $ip );
            return false;
        }

        $this->cron_data[ $ip ][] = $now;
        $this->save_cron_data();
        return true;
    }

    /**
     * Check if a login request is allowed
     */
    public function allow_login_request(): bool {
        $ip   = $this->get_current_ip();
        $now  = time();

        // Skip for whitelisted IPs
        if ( defined( 'VAPT_WHITELISTED_IPS' ) && in_array( $ip, VAPT_WHITELISTED_IPS ) ) {
            return true;
        }

        if ( ! isset( $this->login_data[ $ip ] ) ) {
            $this->login_data[ $ip ] = [];
        }

        // Get settings
        $options = get_option( 'vapt_security_options', [] );
        $window_minutes = isset( $options['login_lockout_duration'] ) ? absint( $options['login_lockout_duration'] ) : self::LOGIN_WINDOW_MINUTES;
        $max_attempts = isset( $options['login_max_attempts'] ) ? absint( $options['login_max_attempts'] ) : self::MAX_LOGIN_ATTEMPTS;

        // Keep only timestamps within the window
        $this->login_data[ $ip ] = array_filter(
            $this->login_data[ $ip ],
            fn( $ts ) => ( $now - $ts ) <= $window_minutes * 60
        );

        // Check if limit exceeded
        if ( count( $this->login_data[ $ip ] ) >= $max_attempts ) {
            // Block IP
            $this->block_ip( $ip );
            return false;
        }

        return true;
    }

    /**
     * Track a failed login attempt
     */
    public function track_login_failure() {
        $ip   = $this->get_current_ip();
        $now  = time();

        if ( ! isset( $this->login_data[ $ip ] ) ) {
            $this->login_data[ $ip ] = [];
        }

        $this->login_data[ $ip ][] = $now;
        $this->save_login_data();
    }

    /**
     * Clean old entries
     */
    public function clean_old_entries() {
        $now = time();
        $changed = false;
        $cron_changed = false;
        $login_changed = false;

        // Get settings for windows
        $options = get_option( 'vapt_security_options', [] );
        $login_window = isset( $options['login_lockout_duration'] ) ? absint( $options['login_lockout_duration'] ) : self::LOGIN_WINDOW_MINUTES;

        // Clean regular rate limit data
        foreach ( $this->data as $ip => $timestamps ) {
            $new = array_filter(
                $timestamps,
                fn( $ts ) => ( $now - $ts ) <= self::WINDOW_MINUTES * 60
            );
            if ( count( $new ) !== count( $timestamps ) ) {
                $changed = true;
                $this->data[ $ip ] = $new;
            }
        }

        // Clean cron rate limit data
        foreach ( $this->cron_data as $ip => $timestamps ) {
            $new = array_filter(
                $timestamps,
                fn( $ts ) => ( $now - $ts ) <= self::CRON_WINDOW_HOURS * 3600
            );
            if ( count( $new ) !== count( $timestamps ) ) {
                $cron_changed = true;
                $this->cron_data[ $ip ] = $new;
            }
        }

        // Clean login rate limit data
        foreach ( $this->login_data as $ip => $timestamps ) {
            $new = array_filter(
                $timestamps,
                fn( $ts ) => ( $now - $ts ) <= $login_window * 60
            );
            if ( count( $new ) !== count( $timestamps ) ) {
                $login_changed = true;
                $this->login_data[ $ip ] = $new;
            }
        }

        if ( $changed ) {
            $this->save();
        }

        if ( $cron_changed ) {
            $this->save_cron_data();
        }

        if ( $login_changed ) {
            $this->save_login_data();
        }
    }

    /**
     * Check if IP should be blocked and block if necessary
     */
    private function check_and_block_ip( $ip ) {
        // Count violations for this IP
        $violations = get_option( 'vapt_ip_violations', [] );
        
        if ( ! isset( $violations[ $ip ] ) ) {
            $violations[ $ip ] = 0;
        }
        
        $violations[ $ip ]++;
        
        // Block IP if too many violations (more than 5 in an hour)
        if ( $violations[ $ip ] > 5 ) {
            $this->block_ip( $ip );
        }
        
        update_option( 'vapt_ip_violations', $violations, false );
    }

    /**
     * Block an IP address
     */
    public function block_ip( $ip ) {
        $blocked_ips = get_option( self::BLOCKED_IPS_KEY, [] );
        $blocked_ips[ $ip ] = time(); // Store timestamp of blocking
        update_option( self::BLOCKED_IPS_KEY, $blocked_ips, false );
        
        // Log the blocking event
        if ( class_exists( 'VAPT_Security_Logger' ) ) {
            $logger = new VAPT_Security_Logger();
            $logger->log_event( 'ip_blocked', [
                'ip' => $ip,
                'reason' => 'rate_limit_violation'
            ] );
        }
    }

    /**
     * Check if the request is local or loopback
     * 
     * @param string $ip
     * @return bool
     */
    private function is_local_or_loopback( $ip ): bool {
        // Always allow installation and import processes
        if ( ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) || ( defined( 'WP_IMPORTING' ) && WP_IMPORTING ) ) {
            return true;
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $server_addr = $_SERVER['SERVER_ADDR'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Allow WordPress loopback requests specifically by User Agent
        if ( ! empty( $user_agent ) && strpos( $user_agent, 'WordPress/' ) !== false ) {
            return true;
        }

        // Local environment check (Allow empty host for CLI/Internal calls)
        if ( empty( $host ) ||
             strpos( $host, '.local' ) !== false || 
             strpos( $host, '.test' ) !== false || 
             strpos( $host, 'localhost' ) !== false ||
             $ip === '127.0.0.1' || 
             $ip === '::1'
        ) {
            return true;
        }

        // Loopback check (Server talking to itself)
        if ( ! empty( $server_addr ) && $ip === $server_addr ) {
            return true;
        }

        // Additional Loopback check
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return true;
        }

        // Flywheel Local specifically uses certain headers or patterns
        if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) && ( $_SERVER['HTTP_X_REAL_IP'] === '127.0.0.1' || $_SERVER['HTTP_X_REAL_IP'] === '::1' ) ) {
            return true;
        }

        return false;
    }

    /**
     * Get current IP address
     */
    public function get_current_ip(): string {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        
        // Handle Cloudflare
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( $_SERVER['HTTP_CF_CONNECTING_IP'] );
        }
        // Handle proxy
        elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', sanitize_text_field( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
            $ip  = trim( $ips[0] );
        }
        // Handle alternative proxy header
        elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = sanitize_text_field( $_SERVER['HTTP_X_REAL_IP'] );
        }
        
        return $ip;
    }

    /**
     * Save regular rate limit data
     */
    private function save() {
        update_option( self::OPTION_KEY, wp_json_encode( $this->data ), false );
    }

    /**
     * Save cron rate limit data
     */
    private function save_cron_data() {
        update_option( self::CRON_OPTION_KEY, wp_json_encode( $this->cron_data ), false );
    }

    /**
     * Save login rate limit data
     */
    private function save_login_data() {
        update_option( self::LOGIN_OPTION_KEY, wp_json_encode( $this->login_data ), false );
    }

    /**
     * Get rate limit statistics
     */
    public function get_stats() {
        return [
            'regular_requests' => $this->data,
            'cron_requests' => $this->cron_data,
            'login_requests' => $this->login_data
        ];
    }

    /**
     * Reset rate limit data for an IP
     */
    public function reset_ip_data( $ip ) {
        if ( isset( $this->data[ $ip ] ) ) {
            unset( $this->data[ $ip ] );
            $this->save();
        }

        if ( isset( $this->cron_data[ $ip ] ) ) {
            unset( $this->cron_data[ $ip ] );
            $this->save_cron_data();
        }

        if ( isset( $this->login_data[ $ip ] ) ) {
            unset( $this->login_data[ $ip ] );
            $this->save_login_data();
        }

        // Remove from violations
        $violations = get_option( 'vapt_ip_violations', [] );
        if ( isset( $violations[ $ip ] ) ) {
            unset( $violations[ $ip ] );
            update_option( 'vapt_ip_violations', $violations, false );
        }

        // Remove from blocked IPs
        $blocked_ips = get_option( self::BLOCKED_IPS_KEY, [] );
        if ( isset( $blocked_ips[ $ip ] ) ) {
            unset( $blocked_ips[ $ip ] );
            update_option( self::BLOCKED_IPS_KEY, $blocked_ips, false );
        }
    }
}