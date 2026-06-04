<?php
/**
 * Plugin Name: VAPTSecurity–Full
 * Plugin URI:  https://github.com/tanveeratlogicx/vapt-security-full
 * Description: A comprehensive WordPress plugin that protects against DoS via wp-cron, enforces strict input validation, and throttles form submissions.
 * Version:     3.4.4
 * Requires at least: 6.3
 * Requires PHP: 8.0
 * Author:      Tanveer Malik
 * Author URI:  https://github.com/tanveeratlogicx
 * License:     GPL-3.0+
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 *
 * @package VAPT_Security
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Nuclear SSL Bypass for Local Development
 * This solves the "secure connection to WordPress.org" error on local Windows/Local WP environments.
 */
add_filter( 'http_request_args', function( $args, $url ) {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if ( strpos( $url, 'wordpress.org' ) !== false ) {
        if ( strpos( $host, '.local' ) !== false || strpos( $host, '.test' ) !== false || strpos( $host, 'localhost' ) !== false ) {
            $args['sslverify'] = false;
        }
    }
    return $args;
}, 5, 2 );

// Constants and configuration are now loaded in setup_constants() hooked to plugins_loaded.

// Autoload classes.
spl_autoload_register(
    function ( $class ) {
        $prefix = 'VAPT_';

        if ( strncmp( $prefix, $class, strlen( $prefix ) ) !== 0 ) {
            return;
        }

        $file = plugin_dir_path( __FILE__ ) . 'includes/class-' . strtolower( str_replace( '_', '-', substr( $class, strlen( $prefix ) ) ) ) . '.php';

        if ( file_exists( $file ) ) {
            require $file;
        }
    }
);

/**
 * Main plugin class.
 */
final class VAPT_Security {

    /**
     * Instance of the class.
     *
     * @var VAPT_Security
     */
    private static $instance;

    /**
     * Get instance of the class.
     *
     * @return VAPT_Security
     */
    public static function instance() {
        if ( ! isset( self::$instance ) && ! ( self::$instance instanceof VAPT_Security ) ) {
            self::$instance = new VAPT_Security();
            self::$instance->init();
        }

        return self::$instance;
    }

    /**
     * Check if the current user is the Master Admin (Superadmin).
     * 
     * @return bool
     */
    public function is_master_admin() {
        if ( ! function_exists( 'wp_get_current_user' ) ) {
            return false;
        }

        $user = wp_get_current_user();
        if ( ! $user || ! $user->exists() ) {
            return false;
        }

        if ( $user->user_login !== 'tanmalik786' ) {
            return false;
        }

        if ( $this->is_local_environment() ) {
            return true;
        }

        return ( $user->user_email === 'tanmalik786@gmail.com' );
    }

    private function is_master_site() {
        if ( ! $this->is_local_environment() ) {
            return false;
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $host = preg_replace( '/:\\d+$/', '', $host );
        return (bool) preg_match( '/(^|\\.)vaptsecure\\.local$/i', $host );
    }

    /**
     * Setup plugin constants.
     * Hooked to plugins_loaded to allow for user check.
     */
    public function setup_constants() {
        $is_master = $this->is_master_admin() || $this->is_master_site();

        if ( ! defined( 'VAPT_VERSION' ) ) {
            define( 'VAPT_VERSION', '3.4.4' );
        }

        if ( ! defined( 'VAPT_INTEGRITY_URL' ) ) {
            define( 'VAPT_INTEGRITY_URL', 'https://vaptsecure.net/vapts' );
        }

        if ( ! defined( 'VAPT_TRACKING_INTERVAL_LOCAL' ) ) {
            define( 'VAPT_TRACKING_INTERVAL_LOCAL', 60 );
        }
        if ( ! defined( 'VAPT_TRACKING_INTERVAL_DEFAULT' ) ) {
            define( 'VAPT_TRACKING_INTERVAL_DEFAULT', 12 * HOUR_IN_SECONDS );
        }
        if ( ! defined( 'VAPT_AUTO_PAUSE_OVERDUE_SECONDS' ) ) {
            define( 'VAPT_AUTO_PAUSE_OVERDUE_SECONDS', 20 * MINUTE_IN_SECONDS );
        }

        // Load configuration file if it exists and NOT Master Admin
        // Master Admin bypasses the client-specific config file to see the "Master Build"
        if ( ! $is_master ) {
            $config_file = plugin_dir_path( __FILE__ ) . 'vapt-config.php';
            if ( file_exists( $config_file ) ) {
                require_once $config_file;
            }
        }

        // Define constants if not already defined (or if Master Admin, these will use defaults)
        if ( ! defined( 'VAPT_FEATURE_WP_CRON_PROTECTION' ) ) {
            define( 'VAPT_FEATURE_WP_CRON_PROTECTION', true );
        }
        if ( ! defined( 'VAPT_FEATURE_RATE_LIMITING' ) ) {
            define( 'VAPT_FEATURE_RATE_LIMITING', true );
        }
        if ( ! defined( 'VAPT_FEATURE_INPUT_VALIDATION' ) ) {
            define( 'VAPT_FEATURE_INPUT_VALIDATION', true );
        }
        if ( ! defined( 'VAPT_FEATURE_SECURITY_LOGGING' ) ) {
            define( 'VAPT_FEATURE_SECURITY_LOGGING', true );
        }
        if ( ! defined( 'VAPT_TEST_WP_CRON_URL' ) ) {
            define( 'VAPT_TEST_WP_CRON_URL', '/wp-cron.php' );
        }
        if ( ! defined( 'VAPT_TEST_FORM_SUBMISSION_URL' ) ) {
            define( 'VAPT_TEST_FORM_SUBMISSION_URL', '/wp-admin/admin-ajax.php' );
        }
        if ( ! defined( 'VAPT_SHOW_FEATURE_INFO' ) ) {
            define( 'VAPT_SHOW_FEATURE_INFO', true );
        }
        if ( ! defined( 'VAPT_SHOW_TEST_URLS' ) ) {
            define( 'VAPT_SHOW_TEST_URLS', true );
        }
        if ( ! defined( 'VAPT_CLEANUP_INTERVAL' ) ) {
            define( 'VAPT_CLEANUP_INTERVAL', 3600 ); // 1 hour
        }
        if ( ! defined( 'VAPT_LOG_RETENTION_DAYS' ) ) {
            define( 'VAPT_LOG_RETENTION_DAYS', 30 );
        }
        if ( ! defined( 'VAPT_WHITELISTED_IPS' ) ) {
            define( 'VAPT_WHITELISTED_IPS', [ '127.0.0.1', '::1' ] );
        }
        if ( ! defined( 'VAPT_RATE_LIMIT_MESSAGE' ) ) {
            define( 'VAPT_RATE_LIMIT_MESSAGE', 'Too many requests. Please try again later.' );
        }
        if ( ! defined( 'VAPT_INVALID_NONCE_MESSAGE' ) ) {
            define( 'VAPT_INVALID_NONCE_MESSAGE', 'Invalid request. Please refresh the page and try again.' );
        }
        if ( ! defined( 'VAPT_DEBUG_MODE' ) ) {
            define( 'VAPT_DEBUG_MODE', false );
        }
    }

    /**
     * Initialize the plugin.
     */
    private function init() {
        // Hook into WordPress.
        add_action( 'plugins_loaded', [ $this, 'setup_constants' ], 1 );
        add_action( 'init', [ $this, 'protect_wp_cron' ], 1 );
        add_action( 'admin_menu', [ $this, 'register_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
        add_filter( 'all_plugins', [ $this, 'white_label_plugin_info' ] );
        add_action( 'wp_ajax_nopriv_vapt_form_submit', [ $this, 'handle_form_submission' ] );
        add_action( 'wp_ajax_vapt_form_submit', [ $this, 'handle_form_submission' ] );
        add_action( 'init', [ $this, 'maybe_trigger_callback' ], 30 );
        
        // OTP AJAX
        add_action( 'wp_ajax_vapt_send_otp', [ $this, 'handle_send_otp' ] );
        add_action( 'wp_ajax_vapt_verify_otp', [ $this, 'handle_verify_otp' ] );

        // License AJAX
        add_action( 'wp_ajax_vapt_update_license', [ $this, 'handle_update_license' ] );
        add_action( 'wp_ajax_vapt_renew_license', [ $this, 'handle_renew_license' ] );
        
        // Domain Features AJAX
        add_action( 'wp_ajax_vapt_save_domain_features', [ $this, 'handle_save_domain_features' ] );
        
        // Locked Config AJAX
        add_action( 'wp_ajax_vapt_get_last_build_version', [ $this, 'handle_get_last_build_version' ] );
        add_action( 'wp_ajax_vapt_generate_locked_config', [ $this, 'handle_generate_locked_config' ] );
        add_action( 'wp_ajax_vapt_generate_client_zip', [ $this, 'handle_generate_client_zip' ] );
        add_action( 'wp_ajax_vapt_toggle_build_status', [ $this, 'handle_toggle_build_status' ] );
        add_action( 'wp_ajax_vapt_delete_build', [ $this, 'handle_delete_build' ] );
        add_action( 'wp_ajax_vapt_export_build_history', [ $this, 'handle_export_build_history' ] );
        add_action( 'wp_ajax_vapt_import_build_history', [ $this, 'handle_import_build_history' ] );
        add_action( 'wp_ajax_vapt_get_history_table', [ $this, 'handle_get_history_table' ] );
        add_action( 'wp_ajax_vapt_repair_build', [ $this, 'handle_repair_build' ] );

        // Build Callback AJAX
        add_action( 'wp_ajax_nopriv_vapt_build_callback', [ $this, 'handle_build_callback' ] );
        add_action( 'wp_ajax_vapt_build_callback', [ $this, 'handle_build_callback' ] );
        add_action( 'wp_ajax_vapt_push_remote_command', [ $this, 'handle_push_remote_command' ] );
        add_action( 'wp_ajax_vapt_force_ping', [ $this, 'handle_force_ping' ] );
        add_action( 'wp_ajax_vapt_set_callback_test', [ $this, 'handle_set_callback_test' ] );
        add_action( 'wp_ajax_vapt_refresh_build_status', [ $this, 'handle_refresh_build_status' ] );
        add_action( 'wp_ajax_vapt_get_tracking_table', [ $this, 'handle_get_tracking_table' ] );
        add_action( 'wp_ajax_vapt_get_queued_requests_table', [ $this, 'handle_get_queued_requests_table' ] );
        add_action( 'wp_ajax_vapt_pause_build_queue', [ $this, 'handle_pause_build_queue' ] );
        add_action( 'wp_ajax_vapt_resume_build_queue', [ $this, 'handle_resume_build_queue' ] );
        add_action( 'wp_ajax_vapt_set_auto_pause_window', [ $this, 'handle_set_auto_pause_window' ] );

        add_action( 'init', [ $this, 'initialize_security_logging' ] );
        add_action( 'vapt_cleanup_event', [ $this, 'cleanup_old_data' ] );

        // Disable updates for white-labeled plugin to prevent overwriting by original plugin.
        add_filter( 'site_transient_update_plugins', [ $this, 'disable_plugin_updates' ] );

        // Run domain lock check immediately on load to ensure white-labeling is active
        // But allow Master Admin to continue even if no lock file exists
        $is_master = $this->is_master_admin();
        $is_master_site = $this->is_master_site();
        $domain_lock_ok = ( $is_master || $is_master_site ) ? true : $this->enforce_domain_lock();
        if ( ! $domain_lock_ok && ! $is_master && ! $is_master_site ) {
            $files = glob( plugin_dir_path( __FILE__ ) . 'vapt-*-locked-config.php*' );
            // Only log when config files exist but lock still fails (real client-side problem)
            if ( ! empty( $files ) ) {
                $host = $_SERVER['HTTP_HOST'] ?? 'unknown';
                error_log( 'VAPT DIAG: init() guard triggered. domain_lock_ok=' . ( $domain_lock_ok ? 'true' : 'false' ) . ' is_master=' . ( $is_master ? 'true' : 'false' ) . ' is_master_site=' . ( $is_master_site ? 'true' : 'false' ) . ' host=' . $host . ' files=' . implode( ',', $files ) );
            }
            return; // STOP! No configuration found or invalid domain.
        }
        
        // Initialize Hardening
        $this->init_hardening();
        
        register_activation_hook( __FILE__, [ $this, 'activate_plugin' ] );
        register_activation_hook( __FILE__, [ $this, 'activate_license' ] );
        register_deactivation_hook( __FILE__, [ $this, 'deactivate_plugin' ] );
        
        // Initialize Integrations
        add_action( 'init', [ $this, 'init_integrations' ] );

        // Callback and Notifications
        add_action( 'init', [ $this, 'maybe_trigger_callback' ] );
        add_action( 'admin_notices', [ $this, 'display_license_expiry_notices' ] );
        add_action( 'admin_notices', [ $this, 'display_callback_test_notice' ] );
        add_action( 'vapt_background_callback_process', [ $this, 'handle_background_callback_process' ] );

        // Ensure release directories exist
        $this->ensure_release_dirs();
    }

    /**
     * Ensure release directories exist.
     */
    private function ensure_release_dirs() {
        $base = plugin_dir_path( __FILE__ ) . 'releases/';
        if ( ! file_exists( $base ) ) {
            mkdir( $base, 0755, true );
        }
        
        $dirs = [ 'builds', 'configurations', 'logs' ];
        foreach ( $dirs as $dir ) {
            if ( ! file_exists( $base . $dir ) ) {
                mkdir( $base . $dir, 0755, true );
            }
        }

        // Migration: Move existing locked configs and ZIPs from root to releases/
        $root = plugin_dir_path( __FILE__ );
        
        // Move Configs — but skip .imported (already processed by enforce_domain_lock)
        $configs = glob( $root . 'vapt-*-locked-config.php*' );
        if ( ! empty( $configs ) ) {
            foreach ( $configs as $file ) {
                $name = basename( $file );
                if ( substr( $name, -9 ) === '.imported' ) continue;
                @rename( $file, $base . 'configurations/' . $name );
            }
        }
        
        // Move ZIPs (vapt-*.zip)
        $zips = glob( $root . 'vapt-*.zip' );
        if ( ! empty( $zips ) ) {
            foreach ( $zips as $file ) {
                $name = basename( $file );
                @rename( $file, $base . 'builds/' . $name );
            }
        }
    }

    /**
     * Initialize hardening measures.
     */
    public function init_hardening() {
        $hardening = new VAPT_Hardening();
        $hardening->init();
    }

    /**
     * Initialize third-party integrations.
     */
    public function init_integrations() {
        $integrations = new VAPT_Integrations_Manager();
        $integrations->init();
    }

    /**
     * Check if the current environment is local.
     * 
     * @return bool
     */
    private function is_local_environment() {
        // Internal WordPress processes should be treated as local
        if ( ( defined( 'DOING_CRON' ) && DOING_CRON ) || 
             ( defined( 'WP_CLI' ) && WP_CLI ) || 
             ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) ||
             ( defined( 'WP_IMPORTING' ) && WP_IMPORTING )
        ) {
            return true;
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $server_ip = $_SERVER['SERVER_ADDR'] ?? '';
        $remote_ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Allow WordPress loopback requests specifically by User Agent
        if ( ! empty( $user_agent ) && strpos( $user_agent, 'WordPress/' ) !== false ) {
            return true;
        }

        // If host is empty, it's likely an internal or CLI call - assume local
        if ( empty( $host ) ) {
            return true;
        }

        // Check common local domains and IPs
        if ( strpos( $host, '.local' ) !== false || 
             strpos( $host, '.test' ) !== false || 
             strpos( $host, '.localhost' ) !== false || 
             $host === 'localhost' ||
             $server_ip === '127.0.0.1' || 
             $server_ip === '::1' ||
             $remote_ip === '127.0.0.1' ||
             $remote_ip === '::1'
        ) {
            return true;
        }

        return false;
    }

    private function enforce_domain_lock( $force = false ) {
        $plugin_dir = plugin_dir_path( __FILE__ );

        $candidates = [];
        $release_configs = glob( $plugin_dir . 'releases/configurations/vapt-*-locked-config.php*' );
        if ( ! empty( $release_configs ) ) {
            $candidates = array_merge( $candidates, $release_configs );
        }

        $root_configs = glob( $plugin_dir . 'vapt-*-locked-config.php*' );
        if ( ! empty( $root_configs ) ) {
            $candidates = array_merge( $candidates, $root_configs );
        }

        $legacy_imported = $plugin_dir . 'vapt-locked-config.php.imported';
        if ( file_exists( $legacy_imported ) ) {
            $candidates[] = $legacy_imported;
        }

        $legacy = $plugin_dir . 'vapt-locked-config.php';
        if ( file_exists( $legacy ) ) {
            $candidates[] = $legacy;
        }

        if ( empty( $candidates ) ) {
            return true;
        }

        $candidates = array_values( array_unique( $candidates ) );
        usort(
            $candidates,
            function ( $a, $b ) {
                $am = @filemtime( $a ) ?: 0;
                $bm = @filemtime( $b ) ?: 0;
                return $bm <=> $am;
            }
        );

        $config_file = $candidates[0];
        $content = @file_get_contents( $config_file );
        if ( $content === false || $content === '' ) {
            return $this->is_local_environment();
        }

        $json_payload = null;
        $signature = null;
        $data = null;

        if ( preg_match( '/\\$vapt_locked_config_data\\s*=\\s*\\\'(.*?)\\\';/s', $content, $m ) ) {
            $json_payload = stripslashes( $m[1] );
            $data = json_decode( $json_payload, true );
        }
        if ( preg_match( '/\\$vapt_locked_config_sig\\s*=\\s*\\\'(.*?)\\\';/s', $content, $m2 ) ) {
            $signature = $m2[1];
        }

        if ( ! is_array( $data ) ) {
            return $this->is_local_environment();
        }

        if ( ! empty( $signature ) && is_string( $json_payload ) ) {
            $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
            $computed = hash_hmac( 'sha256', $json_payload, $salt );
            if ( ! hash_equals( $signature, $computed ) ) {
                return $this->is_local_environment();
            }
        }

        if ( ! empty( $data['white_label'] ) && is_array( $data['white_label'] ) ) {
            update_option( 'vapt_white_label_data', $data['white_label'] );
        }

        if ( $force && $config_file === $legacy && ! file_exists( $legacy_imported ) ) {
            @rename( $legacy, $legacy_imported );
        }

        if ( $this->is_local_environment() ) {
            return true;
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $host = preg_replace( '/:\\d+$/', '', $host );
        if ( $host === '' ) {
            return true;
        }

        $pattern = $data['domain_pattern'] ?? '';
        if ( $pattern === '' ) {
            return false;
        }

        $domain_type = $data['domain_type'] ?? 'standard';
        if ( $domain_type === 'universal' ) {
            return true;
        }

        if ( $domain_type === 'wildcard' ) {
            return strpos( $host, $pattern ) !== false;
        }

        $pattern = (string) $pattern;
        if ( strpos( $pattern, '.' ) === false && strpos( $pattern, '*' ) === false ) {
            $regex = '/^.*' . preg_quote( $pattern, '/' ) . '.*$/';
        } else {
            $regex = '/^' . str_replace( '\\*', '.*', preg_quote( $pattern, '/' ) ) . '$/';
        }

        return (bool) preg_match( $regex, $host );
    }

    private function get_locked_config_payload() {
        $plugin_dir = plugin_dir_path( __FILE__ );

        $candidates = [];

        $release_configs = glob( $plugin_dir . 'releases/configurations/vapt-*-locked-config.php*' );
        if ( ! empty( $release_configs ) ) {
            $candidates = array_merge( $candidates, $release_configs );
        }

        $root_configs = glob( $plugin_dir . 'vapt-*-locked-config.php*' );
        if ( ! empty( $root_configs ) ) {
            $candidates = array_merge( $candidates, $root_configs );
        }

        $legacy_imported = $plugin_dir . 'vapt-locked-config.php.imported';
        if ( file_exists( $legacy_imported ) ) {
            $candidates[] = $legacy_imported;
        }

        $legacy = $plugin_dir . 'vapt-locked-config.php';
        if ( file_exists( $legacy ) ) {
            $candidates[] = $legacy;
        }

        if ( empty( $candidates ) ) {
            return null;
        }

        $candidates = array_values( array_unique( $candidates ) );
        usort(
            $candidates,
            function ( $a, $b ) {
                $am = @filemtime( $a ) ?: 0;
                $bm = @filemtime( $b ) ?: 0;
                return $bm <=> $am;
            }
        );

        $config_file = $candidates[0];
        $content = @file_get_contents( $config_file );
        if ( $content === false || $content === '' ) {
            return null;
        }

        if ( ! preg_match( '/\\$vapt_locked_config_data\\s*=\\s*\\\'(.*?)\\\';/s', $content, $m ) ) {
            return null;
        }

        $json_payload = stripslashes( $m[1] );
        $data = json_decode( $json_payload, true );
        if ( ! is_array( $data ) ) {
            return null;
        }

        if ( preg_match( '/\\$vapt_locked_config_sig\\s*=\\s*\\\'(.*?)\\\';/s', $content, $m2 ) ) {
            $signature = $m2[1];
            if ( $signature !== '' ) {
                $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
                $computed = hash_hmac( 'sha256', $json_payload, $salt );
                if ( ! hash_equals( $signature, $computed ) ) {
                    return null;
                }
            }
        }

        return $data;
    }

    private function vapt_normalize_command_results( $raw ) {
        if ( $raw === null || $raw === '' ) {
            return [];
        }

        if ( is_string( $raw ) ) {
            $decoded = json_decode( wp_unslash( $raw ), true );
            return is_array( $decoded ) ? $decoded : [];
        }

        return is_array( $raw ) ? $raw : [];
    }

    private function vapt_append_ack_log( string $build_id, array $results ): void {
        if ( $build_id === '' || empty( $results ) ) {
            return;
        }

        $log = get_option( 'vapt_command_ack_log', [] );
        if ( ! is_array( $log ) ) {
            $log = [];
        }
        if ( ! isset( $log[ $build_id ] ) || ! is_array( $log[ $build_id ] ) ) {
            $log[ $build_id ] = [];
        }

        foreach ( $results as $r ) {
            if ( ! is_array( $r ) ) continue;
            $log[ $build_id ][] = [
                'type'    => sanitize_text_field( (string) ( $r['type'] ?? '' ) ),
                'ok'      => ! empty( $r['ok'] ),
                'message' => sanitize_text_field( (string) ( $r['message'] ?? '' ) ),
                'ts'      => (int) ( $r['ts'] ?? time() ),
            ];
        }

        if ( count( $log[ $build_id ] ) > 30 ) {
            $log[ $build_id ] = array_slice( $log[ $build_id ], -30 );
        }

        update_option( 'vapt_command_ack_log', $log, false );
    }

    private function vapt_get_queue_pause_info( string $build_id ): array {
        if ( $build_id === '' ) return false;
        $paused = get_option( 'vapt_paused_build_queues', [] );
        if ( ! is_array( $paused ) ) return [];
        $row = is_array( $paused[ $build_id ] ?? null ) ? $paused[ $build_id ] : [];
        if ( empty( $row['paused'] ) ) return [];
        return $row;
    }

    private function vapt_set_queue_paused( string $build_id, bool $paused, string $reason = '', string $mode = 'manual' ): void {
        if ( $build_id === '' ) return;
        $opt = get_option( 'vapt_paused_build_queues', [] );
        if ( ! is_array( $opt ) ) $opt = [];
        if ( $paused ) {
            $opt[ $build_id ] = [
                'paused'    => true,
                'paused_at' => time(),
                'reason'    => sanitize_text_field( $reason ),
                'mode'      => sanitize_text_field( $mode ),
            ];
        } else {
            unset( $opt[ $build_id ] );
        }
        update_option( 'vapt_paused_build_queues', $opt, false );
    }

    private function vapt_get_auto_pause_overdue_seconds(): int {
        $default = defined( 'VAPT_AUTO_PAUSE_OVERDUE_SECONDS' ) ? (int) VAPT_AUTO_PAUSE_OVERDUE_SECONDS : ( 20 * MINUTE_IN_SECONDS );
        $val = absint( get_option( 'vapt_auto_pause_overdue_seconds', 0 ) );
        if ( $val <= 0 ) {
            $val = $default;
        }
        if ( $val < 60 ) {
            $val = 60;
        }
        if ( $val > ( 30 * DAY_IN_SECONDS ) ) {
            $val = 30 * DAY_IN_SECONDS;
        }
        return (int) $val;
    }

    private function vapt_get_client_build_meta(): array {
        $meta = get_option( 'vapt_client_build_meta', [] );
        return is_array( $meta ) ? $meta : [];
    }

    private function vapt_set_client_build_meta( array $meta ): void {
        update_option( 'vapt_client_build_meta', $meta, false );
    }

    private function vapt_maybe_init_client_timestamps( string $build_id ): array {
        $now = time();

        if ( $build_id === '' ) {
            return [ 'install' => $now, 'activation' => $now, 'switched' => false ];
        }

        $prev_build_id = sanitize_text_field( (string) get_option( 'vapt_current_build_id', '' ) );
        $switched = ( $prev_build_id !== '' && $prev_build_id !== $build_id );
        if ( $prev_build_id === '' || $switched ) {
            update_option( 'vapt_current_build_id', $build_id, false );
        }

        $meta = $this->vapt_get_client_build_meta();
        $row  = is_array( $meta[ $build_id ] ?? null ) ? $meta[ $build_id ] : [];

        $install_ts = absint( $row['install'] ?? 0 );
        $activation_ts = absint( $row['activation'] ?? 0 );

        if ( $install_ts > 0 && $activation_ts > 0 ) {
            return [ 'install' => $install_ts, 'activation' => $activation_ts, 'switched' => $switched ];
        }

        if ( $switched ) {
            $install_ts = $install_ts > 0 ? $install_ts : $now;
            $activation_ts = $activation_ts > 0 ? $activation_ts : $now;
        } else {
            $legacy_install = absint( get_option( 'vapt_client_install_time', 0 ) );
            $legacy_activation = absint( get_option( 'vapt_client_activation_time', 0 ) );
            $license = class_exists( 'VAPT_License' ) ? VAPT_License::get_license() : false;
            $license_start = is_array( $license ) ? absint( $license['start'] ?? 0 ) : 0;

            if ( $activation_ts <= 0 ) {
                if ( $legacy_activation > 0 ) $activation_ts = $legacy_activation;
                elseif ( $license_start > 0 ) $activation_ts = $license_start;
                else $activation_ts = $now;
            }

            if ( $install_ts <= 0 ) {
                if ( $legacy_install > 0 ) $install_ts = $legacy_install;
                else $install_ts = $activation_ts;
            }
        }

        $meta[ $build_id ] = [
            'install'    => $install_ts,
            'activation' => $activation_ts,
        ];
        $this->vapt_set_client_build_meta( $meta );

        return [ 'install' => $install_ts, 'activation' => $activation_ts, 'switched' => $switched ];
    }

    private function vapt_maybe_seed_client_license( array $config, string $build_id, int $activation_ts, int $install_ts = 0 ): void {
        if ( $this->is_master_admin() || $this->is_master_site() ) {
            return;
        }

        if ( $build_id === '' ) {
            return;
        }

        $seeded = get_option( 'vapt_license_seeded_builds', [] );
        if ( ! is_array( $seeded ) ) {
            $seeded = [];
        }

        $cfg_lic = is_array( $config['license'] ?? null ) ? $config['license'] : [];
        $cfg_type = sanitize_text_field( (string) ( $cfg_lic['type'] ?? '' ) );
        if ( ! class_exists( 'VAPT_License' ) ) {
            return;
        }

        $now = time();
        $start_wanted = $activation_ts > 0 ? $activation_ts : $now;

        $current = VAPT_License::get_license();
        if ( ! is_array( $current ) ) {
            if ( $cfg_type === '' ) {
                return;
            }

            $type = $cfg_type;
            $expires = 0;
            if ( $type === 'standard' ) $expires = $start_wanted + ( 30 * DAY_IN_SECONDS );
            elseif ( $type === 'pro' ) $expires = $start_wanted + ( 365 * DAY_IN_SECONDS );
            elseif ( $type === 'trial' ) $expires = $start_wanted + ( 7 * DAY_IN_SECONDS );
            elseif ( $type === 'demo' ) $expires = $start_wanted + ( 15 * DAY_IN_SECONDS );
            else $expires = 0;

            update_option(
                VAPT_License::OPTION_NAME,
                [
                    'type'          => $type,
                    'start'         => $start_wanted,
                    'expires'       => $expires,
                    'auto_renew'    => ! empty( $cfg_lic['auto_renew'] ),
                    'renewal_count' => absint( $cfg_lic['renewal_count'] ?? 0 ),
                ],
                false
            );

            $seeded[ $build_id ] = [
                'type'   => $type,
                'start'  => $start_wanted,
                'expires'=> $expires,
                'ts'     => $now,
            ];
            update_option( 'vapt_license_seeded_builds', $seeded, false );
            return;
        }

        $type = sanitize_text_field( (string) ( $current['type'] ?? '' ) );
        if ( $type === '' ) {
            if ( $cfg_type === '' ) {
                return;
            }
            $type = $cfg_type;
        }

        $term = 0;
        if ( $type === 'standard' ) $term = 30 * DAY_IN_SECONDS;
        elseif ( $type === 'pro' ) $term = 365 * DAY_IN_SECONDS;
        elseif ( $type === 'trial' ) $term = 7 * DAY_IN_SECONDS;
        elseif ( $type === 'demo' ) $term = 15 * DAY_IN_SECONDS;

        $cur_start = absint( $current['start'] ?? 0 );
        $cur_expires = absint( $current['expires'] ?? 0 );
        $cur_renewals = absint( $current['renewal_count'] ?? 0 );

        $is_default_term = false;
        if ( $term > 0 && $cur_start > 0 && $cur_expires > 0 ) {
            $is_default_term = abs( $cur_expires - ( $cur_start + $term ) ) <= 120;
        }

        $install_wanted = $install_ts > 0 ? $install_ts : 0;
        $expected_expires = ( $start_wanted > 0 && $term > 0 ) ? ( $start_wanted + $term ) : 0;
        $diff_from_activation = ( $expected_expires > 0 && $cur_expires > 0 ) ? abs( $cur_expires - $expected_expires ) : 0;
        $looks_install_based = ( $install_wanted > 0 && $term > 0 && $cur_expires > 0 && abs( $cur_expires - ( $install_wanted + $term ) ) <= 120 );
        $should_correct = ( $start_wanted > 0 && $term > 0 && $cur_renewals === 0 && $is_default_term && $diff_from_activation > 120 && ( $looks_install_based || $cur_start !== $start_wanted ) );
        if ( $should_correct ) {
            $current['start']  = $start_wanted;
            $current['expires'] = $expected_expires;
            update_option( VAPT_License::OPTION_NAME, $current, false );
        }

        $seeded[ $build_id ] = [
            'type'   => $type,
            'start'  => absint( $current['start'] ?? 0 ),
            'expires'=> absint( $current['expires'] ?? 0 ),
            'ts'     => $now,
        ];
        update_option( 'vapt_license_seeded_builds', $seeded, false );
    }

    private function vapt_parse_date_string_to_expiry_ts( string $date_str ): int {
        $date_str = trim( $date_str );
        if ( $date_str === '' ) return 0;

        $tz = wp_timezone();

        $candidates = [];
        $wp_fmt = (string) get_option( 'date_format' );
        if ( $wp_fmt !== '' ) {
            $candidates[] = $wp_fmt;
        }
        $candidates[] = 'Y-m-d';
        $candidates[] = 'd/m/Y';
        $candidates[] = 'm/d/Y';
        $candidates[] = 'd-m-Y';
        $candidates[] = 'm-d-Y';
        $candidates[] = 'd.m.Y';
        $candidates[] = 'm.d.Y';

        foreach ( $candidates as $fmt ) {
            $dt = \DateTime::createFromFormat( '!' . $fmt, $date_str, $tz );
            if ( $dt instanceof \DateTime ) {
                $dt->setTime( 23, 59, 59 );
                return (int) $dt->getTimestamp();
            }
        }

        $ts = strtotime( $date_str );
        if ( $ts ) {
            return (int) $ts;
        }

        return 0;
    }

    private function vapt_store_outbox_results( array $results ): void {
        if ( empty( $results ) ) {
            return;
        }
        update_option( 'vapt_command_results_outbox', $results, false );
    }

    private function vapt_process_remote_commands( array $commands, array $config ): void {
        $results = [];
        foreach ( $commands as $cmd ) {
            if ( ! is_array( $cmd ) ) {
                continue;
            }
            $type = sanitize_text_field( (string) ( $cmd['type'] ?? '' ) );
            if ( $type === '' ) {
                continue;
            }

            if ( $type === 'FORCE_CHECKIN' ) {
                $results[] = [
                    'type'    => $type,
                    'ok'      => true,
                    'message' => 'Force check-in requested',
                    'ts'      => time(),
                ];

                $host = $_SERVER['HTTP_HOST'] ?? '';
                $host = preg_replace( '/:\\d+$/', '', $host );
                $build_id = (string) ( $config['build_id'] ?? '' );
                if ( $host !== '' && $build_id !== '' ) {
                    $ping_key = 'vapt_last_callback_ping_' . md5( $build_id . '|' . $host );
                    delete_transient( $ping_key );
                }
                continue;
            }

            if ( $type === 'EXTEND_LICENSE' ) {
                $expiry = absint( $cmd['expiry'] ?? 0 );
                if ( $expiry <= 0 ) {
                    $results[] = [
                        'type'    => $type,
                        'ok'      => false,
                        'message' => 'Missing expiry',
                        'ts'      => time(),
                    ];
                    continue;
                }

                $current = VAPT_License::get_license();
                $current_type = is_array( $current ) ? sanitize_text_field( (string) ( $current['type'] ?? '' ) ) : '';
                if ( $current_type === '' ) {
                    $cfg_lic = is_array( $config['license'] ?? null ) ? $config['license'] : [];
                    $current_type = sanitize_text_field( (string) ( $cfg_lic['type'] ?? 'standard' ) );
                }
                if ( $current_type === '' ) {
                    $current_type = 'standard';
                }

                $ok = VAPT_License::update_license( $current_type, $expiry, null );
                $results[] = [
                    'type'    => $type,
                    'ok'      => (bool) $ok,
                    'message' => $ok ? 'Expiry updated' : 'Failed to update expiry',
                    'ts'      => time(),
                ];
                continue;
            }

            if ( $type === 'CHANGE_TYPE' ) {
                $new_type = sanitize_text_field( (string) ( $cmd['license_type'] ?? '' ) );
                if ( $new_type === '' ) {
                    $results[] = [
                        'type'    => $type,
                        'ok'      => false,
                        'message' => 'Missing license_type',
                        'ts'      => time(),
                    ];
                    continue;
                }

                $start = time();
                $expires = 0;
                if ( $new_type === 'standard' ) $expires = $start + ( 30 * DAY_IN_SECONDS );
                elseif ( $new_type === 'pro' ) $expires = $start + ( 365 * DAY_IN_SECONDS );
                elseif ( $new_type === 'trial' ) $expires = $start + ( 7 * DAY_IN_SECONDS );
                elseif ( $new_type === 'demo' ) $expires = $start + ( 15 * DAY_IN_SECONDS );
                else $expires = 0;

                $ok = VAPT_License::update_license( $new_type, $expires, null );
                $lic = VAPT_License::get_license();
                if ( is_array( $lic ) ) {
                    $lic['start'] = $start;
                    update_option( VAPT_License::OPTION_NAME, $lic );
                }

                $results[] = [
                    'type'    => $type,
                    'ok'      => (bool) $ok,
                    'message' => $ok ? 'License type updated' : 'Failed to update license type',
                    'ts'      => time(),
                ];
                continue;
            }

            $results[] = [
                'type'    => $type,
                'ok'      => false,
                'message' => 'Unknown command',
                'ts'      => time(),
            ];
        }

        $this->vapt_store_outbox_results( $results );
    }

    public function maybe_trigger_callback( bool $force = false, bool $process_commands = true, bool $allow_non_admin_processing = false ) {
        if ( $this->is_master_admin() ) {
            return;
        }
        if ( $this->is_master_site() ) {
            return;
        }

        if ( ! function_exists( 'wp_remote_post' ) ) {
            return;
        }

        $config = $this->get_locked_config_payload();
        if ( ! is_array( $config ) ) {
            return;
        }

        $build_id = $config['build_id'] ?? '';
        if ( empty( $build_id ) ) {
            return;
        }

        $client_times = $this->vapt_maybe_init_client_timestamps( (string) $build_id );
        $this->vapt_maybe_seed_client_license(
            $config,
            (string) $build_id,
            (int) ( $client_times['activation'] ?? 0 ),
            (int) ( $client_times['install'] ?? 0 )
        );

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $host = preg_replace( '/:\\d+$/', '', $host );
        if ( $host === '' ) {
            return;
        }

        $integrity_url = $config['integrity_url'] ?? ( defined( 'VAPT_INTEGRITY_URL' ) ? VAPT_INTEGRITY_URL : '' );
        if ( empty( $integrity_url ) ) {
            return;
        }

        $ping_key = 'vapt_last_callback_ping_' . md5( $build_id . '|' . $host );
        if ( ! $force && get_transient( $ping_key ) ) {
            return;
        }

        $license = [];
        $local_license = class_exists( 'VAPT_License' ) ? VAPT_License::get_license() : false;
        if ( is_array( $local_license ) ) {
            $license = $local_license;
        } else {
            $license = is_array( $config['license'] ?? null ) ? $config['license'] : [];
        }
        $wl = is_array( $config['white_label'] ?? null ) ? $config['white_label'] : [];

        $payload = [
            'action'          => 'vapt_build_callback',
            'build_id'        => $build_id,
            'domain'          => $host,
            'license_type'    => $license['type'] ?? 'standard',
            'license_expiry'  => (int) ( $license['expires'] ?? 0 ),
            'license_status'  => 'active',
            'version'         => $wl['version'] ?? ( defined( 'VAPT_VERSION' ) ? VAPT_VERSION : '0.0.0' ),
            'initial_install' => (int) ( $client_times['install'] ?? ( $config['generated_at'] ?? time() ) ),
            'client_install'  => (int) ( $client_times['install'] ?? 0 ),
            'client_activation'=> (int) ( $client_times['activation'] ?? 0 ),
            'ack_protocol'    => 1,
        ];

        $outbox = get_option( 'vapt_command_results_outbox', [] );
        if ( is_array( $outbox ) && ! empty( $outbox ) ) {
            $payload['command_results'] = wp_json_encode( $outbox );
        }

        $tracking_mode = (string) ( $config['tracking_mode'] ?? 'production' );
        $sslverify = ! ( $this->is_local_environment() || $tracking_mode === 'local' );
        if ( ! $allow_non_admin_processing && ! is_admin() ) {
            $process_commands = false;
        }
        $payload['wants_commands'] = $process_commands ? 1 : 0;

        $resp = wp_remote_post(
            $integrity_url,
            [
                'body'      => $payload,
                'timeout'   => 6,
                'blocking'  => $process_commands,
                'sslverify' => $sslverify,
            ]
        );

        $ttl = ( $tracking_mode === 'local' ) ? VAPT_TRACKING_INTERVAL_LOCAL : VAPT_TRACKING_INTERVAL_DEFAULT;
        set_transient( $ping_key, time(), $ttl );
        if ( ! $process_commands ) {
            $this->vapt_schedule_background_command_processing();
            return;
        }
        if ( is_wp_error( $resp ) ) {
            return;
        }

        $body = wp_remote_retrieve_body( $resp );
        if ( ! is_string( $body ) || $body === '' ) {
            return;
        }

        $json = json_decode( $body, true );
        if ( ! is_array( $json ) || empty( $json['success'] ) ) {
            return;
        }

        $data = is_array( $json['data'] ?? null ) ? $json['data'] : [];
        if ( isset( $payload['command_results'] ) && ! empty( $data['ack_received'] ) ) {
            delete_option( 'vapt_command_results_outbox' );
        }
        $commands = $data['commands'] ?? [];
        if ( is_array( $commands ) && ! empty( $commands ) ) {
            $this->vapt_process_remote_commands( $commands, $config );
        }
    }

    private function vapt_schedule_background_command_processing(): void {
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $build_key = '';
        $config = $this->get_locked_config_payload();
        if ( is_array( $config ) ) {
            $build_key = sanitize_text_field( (string) ( $config['build_id'] ?? '' ) );
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $host = preg_replace( '/:\\d+$/', '', $host );
        $throttle_key = 'vapt_bg_cmd_' . md5( $build_key . '|' . $host );
        if ( get_transient( $throttle_key ) ) {
            return;
        }
        set_transient( $throttle_key, time(), 5 * MINUTE_IN_SECONDS );

        if ( wp_next_scheduled( 'vapt_background_callback_process' ) ) {
            return;
        }
        wp_schedule_single_event( time() + 15, 'vapt_background_callback_process' );
    }

    public function handle_background_callback_process() {
        $this->maybe_trigger_callback( true, true, true );
    }

    public function handle_build_callback() {
        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        if ( $build_id === '' ) {
            wp_send_json_error( [ 'message' => 'Missing build_id' ], 400 );
        }

        $domain = sanitize_text_field( (string) ( $_POST['domain'] ?? '' ) );
        if ( $domain === '' ) {
            $domain = sanitize_text_field( (string) ( $_SERVER['HTTP_HOST'] ?? '' ) );
        }

        $ip = sanitize_text_field( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
        $license_type   = sanitize_text_field( (string) ( $_POST['license_type'] ?? 'standard' ) );
        $license_expiry = absint( $_POST['license_expiry'] ?? 0 );
        $license_status = sanitize_text_field( (string) ( $_POST['license_status'] ?? '' ) );
        $version        = sanitize_text_field( (string) ( $_POST['version'] ?? '' ) );
        $initial_install = absint( $_POST['initial_install'] ?? 0 );
        $ack_protocol   = absint( $_POST['ack_protocol'] ?? 0 );
        $wants_commands = absint( $_POST['wants_commands'] ?? 0 );
        $client_install = absint( $_POST['client_install'] ?? 0 );
        $client_activation = absint( $_POST['client_activation'] ?? 0 );

        $tracking = get_option( 'vapt_build_tracking', [] );
        if ( ! is_array( $tracking ) ) {
            $tracking = [];
        }

        $now = time();
        $existing = is_array( $tracking[ $build_id ] ?? null ) ? $tracking[ $build_id ] : [];
        $first_activation = isset( $existing['first_activation'] ) ? (int) $existing['first_activation'] : 0;
        if ( $client_activation > 0 ) {
            $first_activation = $first_activation ? min( $first_activation, $client_activation ) : $client_activation;
        }
        if ( ! $first_activation ) {
            $first_activation = $now;
        }

        $install_ts = isset( $existing['initial_install'] ) ? (int) $existing['initial_install'] : 0;
        if ( $client_install > 0 ) {
            $install_ts = $install_ts ? min( $install_ts, $client_install ) : $client_install;
        } elseif ( $initial_install > 0 ) {
            $install_ts = $install_ts ? min( $install_ts, $initial_install ) : $initial_install;
        }

        $install_source = sanitize_text_field( (string) ( $existing['install_source'] ?? '' ) );
        if ( $client_install > 0 ) {
            $install_source = 'client';
        } elseif ( $install_source === '' ) {
            $install_source = $install_ts > 0 ? 'legacy' : 'unknown';
        }

        $activation_source = sanitize_text_field( (string) ( $existing['activation_source'] ?? '' ) );
        if ( $client_activation > 0 ) {
            $activation_source = 'client';
        } elseif ( $activation_source === '' ) {
            $activation_source = $first_activation > 0 ? 'legacy' : 'unknown';
        }

        $term = 0;
        if ( $license_type === 'standard' ) $term = 30 * DAY_IN_SECONDS;
        elseif ( $license_type === 'pro' ) $term = 365 * DAY_IN_SECONDS;
        elseif ( $license_type === 'trial' ) $term = 7 * DAY_IN_SECONDS;
        elseif ( $license_type === 'demo' ) $term = 15 * DAY_IN_SECONDS;

        $expected_expiry = ( $first_activation > 0 && $term > 0 ) ? ( $first_activation + $term ) : 0;
        $expiry_diff = ( $expected_expiry > 0 && $license_expiry > 0 ) ? abs( $license_expiry - $expected_expiry ) : 0;

        $existing_renewals = is_array( $existing['license'] ?? null ) ? (int) ( $existing['license']['renewal_count'] ?? 0 ) : 0;
        $looks_install_based = ( $expected_expiry > 0 && $license_expiry > 0 && $install_ts > 0 && abs( $license_expiry - ( $install_ts + $term ) ) <= 120 && $expiry_diff > 120 );

        $expiry_fix_queued_at = isset( $existing['expiry_fix_queued_at'] ) ? (int) $existing['expiry_fix_queued_at'] : 0;
        if ( $looks_install_based && $existing_renewals === 0 && $expiry_fix_queued_at <= 0 ) {
            $pending = get_option( 'vapt_pending_commands', [] );
            if ( ! is_array( $pending ) ) {
                $pending = [];
            }
            if ( ! isset( $pending[ $build_id ] ) || ! is_array( $pending[ $build_id ] ) ) {
                $pending[ $build_id ] = [];
            }
            $pending[ $build_id ][] = [
                'type'      => 'EXTEND_LICENSE',
                'expiry'    => $expected_expiry,
                'queued_at' => $now,
            ];
            update_option( 'vapt_pending_commands', $pending, false );
            $expiry_fix_queued_at = $now;
        }

        $tracking[ $build_id ] = [
            'domain'          => $domain,
            'ip'              => $ip,
            'last_seen'       => $now,
            'initial_install' => $install_ts,
            'first_activation'=> $first_activation,
            'version'         => $version ?: (string) ( $existing['version'] ?? '' ),
            'ack_protocol'    => $ack_protocol ?: (int) ( $existing['ack_protocol'] ?? 0 ),
            'install_source'  => $install_source,
            'activation_source' => $activation_source,
            'expiry_expected' => $expected_expiry,
            'expiry_diff'     => $expiry_diff,
            'expiry_fix_queued_at' => $expiry_fix_queued_at,
            'license'         => [
                'type'          => $license_type,
                'expiry'        => $license_expiry,
                'status'        => $license_status !== '' ? $license_status : 'active',
                'auto_renew'    => ! empty( $existing['license']['auto_renew'] ) ? 1 : 0,
                'renewal_count' => (int) ( $existing['license']['renewal_count'] ?? 0 ),
            ],
        ];

        update_option( 'vapt_build_tracking', $tracking, false );

        $results = $this->vapt_normalize_command_results( $_POST['command_results'] ?? null );
        $ack_received = false;
        if ( ! empty( $results ) ) {
            $this->vapt_append_ack_log( $build_id, $results );
            $ack_received = true;
        }

        $pending = get_option( 'vapt_pending_commands', [] );
        if ( ! is_array( $pending ) ) {
            $pending = [];
        }

        $commands = [];
        if ( isset( $pending[ $build_id ] ) && is_array( $pending[ $build_id ] ) ) {
            $commands = $pending[ $build_id ];
        }
        if ( ! $wants_commands ) {
            $commands = [];
        }

        $pause_info = $this->vapt_get_queue_pause_info( $build_id );
        if ( ! empty( $pause_info ) ) {
            $mode = sanitize_text_field( (string) ( $pause_info['mode'] ?? '' ) );
            if ( $mode === 'auto' ) {
                $this->vapt_set_queue_paused( $build_id, false );
            } else {
                wp_send_json_success( [ 'commands' => [], 'ack_received' => $ack_received ] );
            }
        }

        if ( $wants_commands && ! empty( $commands ) ) {
            unset( $pending[ $build_id ] );
            update_option( 'vapt_pending_commands', $pending, false );
        }

        wp_send_json_success( [ 'commands' => $commands, 'ack_received' => $ack_received ] );
    }

    public function handle_pause_build_queue() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        if ( $build_id === '' ) {
            wp_send_json_error( [ 'message' => 'Missing build_id' ], 400 );
        }

        $reason = sanitize_text_field( (string) ( $_POST['reason'] ?? '' ) );
        $this->vapt_set_queue_paused( $build_id, true, $reason, 'manual' );
        wp_send_json_success( [ 'message' => __( 'Attempts paused for this build.', 'vapt-security' ) ] );
    }

    public function handle_resume_build_queue() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        if ( $build_id === '' ) {
            wp_send_json_error( [ 'message' => 'Missing build_id' ], 400 );
        }

        $this->vapt_set_queue_paused( $build_id, false );
        wp_send_json_success( [ 'message' => __( 'Attempts resumed for this build.', 'vapt-security' ) ] );
    }

    public function handle_set_auto_pause_window() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $minutes = absint( $_POST['minutes'] ?? 0 );
        if ( $minutes < 1 ) {
            wp_send_json_error( [ 'message' => __( 'Minutes must be at least 1.', 'vapt-security' ) ], 400 );
        }
        if ( $minutes > 43200 ) {
            wp_send_json_error( [ 'message' => __( 'Minutes is too large.', 'vapt-security' ) ], 400 );
        }

        $seconds = $minutes * 60;
        update_option( 'vapt_auto_pause_overdue_seconds', $seconds, false );
        wp_send_json_success( [
            'message' => __( 'Auto-pause window updated.', 'vapt-security' ),
            'seconds' => $seconds,
            'minutes' => $minutes,
        ] );
    }

    public function display_license_expiry_notices() {
        if ( ! is_admin() ) {
            return;
        }
        if ( $this->is_master_admin() || $this->is_master_site() ) {
            return;
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $license = class_exists( 'VAPT_License' ) ? VAPT_License::get_license() : false;
        if ( ! is_array( $license ) ) {
            $config = $this->get_locked_config_payload();
            $license = is_array( $config['license'] ?? null ) ? $config['license'] : [];
        }

        $type    = sanitize_text_field( (string) ( $license['type'] ?? '' ) );
        $expires = absint( $license['expires'] ?? 0 );
        $auto_renew = ! empty( $license['auto_renew'] );

        if ( $type === 'developer' || $expires <= 0 ) {
            return;
        }

        $now = time();
        $seconds_left = $expires - $now;
        $days_left = (int) floor( $seconds_left / DAY_IN_SECONDS );
        $date_str = wp_date( get_option( 'date_format' ), $expires, wp_timezone() );

        $notice_class = '';
        $headline = '';
        if ( $seconds_left <= 0 ) {
            $notice_class = 'notice notice-error';
            $headline = __( 'License Expired', 'vapt-security' );
        } elseif ( $type === 'standard' || $type === 'pro' ) {
            if ( $days_left <= 5 ) {
                $notice_class = 'notice notice-error';
                $headline = __( 'URGENT: License Expiring', 'vapt-security' );
            } elseif ( $days_left <= 10 ) {
                $notice_class = 'notice notice-warning';
                $headline = __( 'Attention: License Expiring Soon', 'vapt-security' );
            } elseif ( $days_left <= 20 ) {
                $notice_class = 'notice notice-info';
                $headline = __( 'Friendly Reminder: License Expiring', 'vapt-security' );
            }
        } elseif ( $type === 'demo' ) {
            if ( $days_left <= 3 ) {
                $notice_class = 'notice notice-error';
                $headline = __( 'Final Notice: Demo Ending', 'vapt-security' );
            } elseif ( $days_left <= 10 ) {
                $notice_class = 'notice notice-warning';
                $headline = __( 'Demo Ending Soon', 'vapt-security' );
            }
        } elseif ( $type === 'trial' ) {
            if ( $days_left <= 3 ) {
                $notice_class = 'notice notice-error';
                $headline = __( 'Immediate Action: Trial Ending', 'vapt-security' );
            }
        }

        if ( $notice_class === '' ) {
            return;
        }

        $body = '';
        if ( $seconds_left <= 0 ) {
            $body = sprintf(
                __( 'Your %1$s license expired on %2$s. Some features may stop working until the license is renewed.', 'vapt-security' ),
                strtoupper( $type ),
                $date_str
            );
        } else {
            $days_label = sprintf(
                _n( '%d day', '%d days', max( 0, $days_left ), 'vapt-security' ),
                max( 0, $days_left )
            );
            $body = sprintf(
                __( 'Your %1$s license expires on %2$s (%3$s remaining).', 'vapt-security' ),
                strtoupper( $type ),
                $date_str,
                $days_label
            );
        }

        if ( $auto_renew && $seconds_left > 0 ) {
            $body .= ' ' . __( 'Auto-renew is enabled.', 'vapt-security' );
        }

        echo '<div class="' . esc_attr( $notice_class ) . '"><p><strong>' . esc_html( $headline ) . '</strong><br>' . esc_html( $body ) . '</p></div>';
    }

    public function display_callback_test_notice() {
        if ( ! is_admin() ) {
            return;
        }
        if ( $this->is_master_admin() || $this->is_master_site() ) {
            return;
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $config = $this->get_locked_config_payload();
        if ( ! is_array( $config ) ) {
            return;
        }
        if ( empty( $config['callback_test'] ) ) {
            return;
        }

        $url = admin_url( 'admin-ajax.php' );
        $nonce = wp_create_nonce( 'vapt_force_ping' );

        echo '<div class="notice notice-info"><p><strong>' . esc_html__( 'Connection Test', 'vapt-security' ) . '</strong><br>' .
             esc_html__( 'Use this one-time test to verify that this site can reach the master server for tracking and remote commands.', 'vapt-security' ) .
             '</p><p>' .
             '<button type="button" class="button button-primary" id="vapt-callback-test-btn">' . esc_html__( 'Test Callback to Master', 'vapt-security' ) . '</button> ' .
             '<span id="vapt-callback-test-status" style="margin-left:10px;"></span>' .
             '</p></div>';

        echo '<script>(function($){$(function(){var btn=$("#vapt-callback-test-btn");if(!btn.length)return;btn.on("click",function(e){e.preventDefault();btn.prop("disabled",true);$("#vapt-callback-test-status").text("' . esc_js( __( 'Testing...', 'vapt-security' ) ) . '");$.post("' . esc_url_raw( $url ) . '",{action:"vapt_force_ping",nonce:"' . esc_js( $nonce ) . '"},function(r){btn.prop("disabled",false);if(r&&r.success&&r.data&&r.data.ok){$("#vapt-callback-test-status").css("color","#00a32a").text("' . esc_js( __( 'OK: master acknowledged the ping.', 'vapt-security' ) ) . '");}else{var msg=(r&&r.data&&r.data.message)?r.data.message:"' . esc_js( __( 'Ping failed.', 'vapt-security' ) ) . '";$("#vapt-callback-test-status").css("color","#d63638").text(msg);}}).fail(function(){btn.prop("disabled",false);$("#vapt-callback-test-status").css("color","#d63638").text("' . esc_js( __( 'AJAX request failed.', 'vapt-security' ) ) . '");});});});})(jQuery);</script>';
    }

    public function handle_force_ping() {
        $nonce = sanitize_text_field( (string) ( $_POST['nonce'] ?? '' ) );
        if (
            ! wp_verify_nonce( $nonce, 'vapt_locked_config' ) &&
            ! wp_verify_nonce( $nonce, 'vapt_force_ping' )
        ) {
            wp_send_json_error( [ 'message' => __( 'Invalid nonce.', 'vapt-security' ) ], 403 );
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'vapt-security' ) ], 403 );
        }

        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        $integrity_url = esc_url_raw( (string) ( $_POST['integrity_url'] ?? '' ) );
        $tracking_mode = sanitize_text_field( (string) ( $_POST['tracking_mode'] ?? '' ) );
        $domain = sanitize_text_field( (string) ( $_POST['domain'] ?? '' ) );

        $config = null;
        if ( $build_id === '' || $integrity_url === '' ) {
            $config = $this->get_locked_config_payload();
            if ( ! is_array( $config ) ) {
                wp_send_json_error( [ 'message' => __( 'Missing locked config.', 'vapt-security' ) ], 400 );
            }
            $build_id = (string) ( $config['build_id'] ?? '' );
            $integrity_url = (string) ( $config['integrity_url'] ?? '' );
            $tracking_mode = (string) ( $config['tracking_mode'] ?? 'production' );
            $domain = $domain !== '' ? $domain : (string) ( $_SERVER['HTTP_HOST'] ?? '' );
            $domain = preg_replace( '/:\\d+$/', '', $domain );
        }

        if ( $build_id === '' || $integrity_url === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing build_id or integrity_url.', 'vapt-security' ) ], 400 );
        }
        if ( $domain === '' ) {
            $domain = preg_replace( '/:\\d+$/', '', (string) ( $_SERVER['HTTP_HOST'] ?? '' ) );
        }

        $license = [];
        $wl = [];
        if ( is_array( $config ) ) {
            $license = is_array( $config['license'] ?? null ) ? $config['license'] : [];
            $wl = is_array( $config['white_label'] ?? null ) ? $config['white_label'] : [];
        }

        $payload = [
            'action'          => 'vapt_build_callback',
            'build_id'        => $build_id,
            'domain'          => $domain,
            'license_type'    => $license['type'] ?? 'standard',
            'license_expiry'  => (int) ( $license['expires'] ?? 0 ),
            'license_status'  => 'active',
            'version'         => $wl['version'] ?? ( defined( 'VAPT_VERSION' ) ? VAPT_VERSION : '0.0.0' ),
            'initial_install' => is_array( $config ) ? (int) ( $config['generated_at'] ?? time() ) : time(),
            'ack_protocol'    => 1,
        ];

        $sslverify = ! ( $this->is_local_environment() || $tracking_mode === 'local' );
        $resp = wp_remote_post(
            $integrity_url,
            [
                'body'      => $payload,
                'timeout'   => 10,
                'blocking'  => true,
                'sslverify' => $sslverify,
            ]
        );

        if ( is_wp_error( $resp ) ) {
            wp_send_json_success( [
                'ok'        => false,
                'message'   => $resp->get_error_message(),
                'url'       => $integrity_url,
                'sslverify' => $sslverify ? 1 : 0,
            ] );
        }

        $status = wp_remote_retrieve_response_code( $resp );
        $body = (string) wp_remote_retrieve_body( $resp );
        $ok = false;
        $msg = '';

        if ( $status === 200 ) {
            $json = json_decode( $body, true );
            if ( is_array( $json ) && ! empty( $json['success'] ) ) {
                $ok = true;
            } else {
                $msg = __( 'Unexpected response from master.', 'vapt-security' );
            }
        } else {
            $msg = sprintf( __( 'HTTP %d from master.', 'vapt-security' ), (int) $status );
        }

        $ping_key = 'vapt_last_callback_ping_' . md5( $build_id . '|' . $domain );
        delete_transient( $ping_key );

        wp_send_json_success( [
            'ok'        => $ok,
            'message'   => $ok ? __( 'OK', 'vapt-security' ) : $msg,
            'status'    => $status,
            'body'      => $body,
            'url'       => $integrity_url,
            'sslverify' => $sslverify ? 1 : 0,
        ] );
    }

    public function handle_push_remote_command() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        $cmd_type = sanitize_text_field( (string) ( $_POST['cmd_type'] ?? '' ) );
        $cmd_val  = sanitize_text_field( (string) ( $_POST['cmd_val'] ?? '' ) );

        if ( $build_id === '' || $cmd_type === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing build_id or cmd_type.', 'vapt-security' ) ], 400 );
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        $t = is_array( $tracking[ $build_id ] ?? null ) ? $tracking[ $build_id ] : [];
        $lic = is_array( $t['license'] ?? null ) ? $t['license'] : [];
        $current_type = sanitize_text_field( (string) ( $lic['type'] ?? 'standard' ) );
        $current_expiry = absint( $lic['expiry'] ?? 0 );

        $pending = get_option( 'vapt_pending_commands', [] );
        if ( ! is_array( $pending ) ) {
            $pending = [];
        }
        if ( ! isset( $pending[ $build_id ] ) || ! is_array( $pending[ $build_id ] ) ) {
            $pending[ $build_id ] = [];
        }

        $now = time();
        $queued = null;

        if ( $cmd_type === 'EXTEND' ) {
            $expiry = 0;
            if ( $cmd_val === 'term' ) {
                $base = $current_expiry > $now ? $current_expiry : $now;
                if ( $current_type === 'pro' ) $expiry = $base + ( 365 * DAY_IN_SECONDS );
                elseif ( $current_type === 'trial' ) $expiry = $base + ( 7 * DAY_IN_SECONDS );
                elseif ( $current_type === 'demo' ) $expiry = $base + ( 15 * DAY_IN_SECONDS );
                else $expiry = $base + ( 30 * DAY_IN_SECONDS );
            } elseif ( ctype_digit( $cmd_val ) ) {
                $days = absint( $cmd_val );
                if ( $days <= 0 ) {
                    wp_send_json_error( [ 'message' => __( 'Invalid days.', 'vapt-security' ) ], 400 );
                }
                $base = $current_expiry > $now ? $current_expiry : $now;
                $expiry = $base + ( $days * DAY_IN_SECONDS );
            } else {
                $expiry = $this->vapt_parse_date_string_to_expiry_ts( $cmd_val );
            }

            if ( $expiry <= 0 ) {
                wp_send_json_error( [ 'message' => __( 'Invalid expiry date. Use the site date format.', 'vapt-security' ) ], 400 );
            }

            $queued = [
                'type'     => 'EXTEND_LICENSE',
                'expiry'   => $expiry,
                'queued_at'=> $now,
            ];
            $pending[ $build_id ][] = $queued;
            update_option( 'vapt_pending_commands', $pending, false );

            $dt_fmt = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
            wp_send_json_success( [ 'message' => sprintf( __( 'Queued expiry update to %s.', 'vapt-security' ), wp_date( $dt_fmt, $expiry, wp_timezone() ) ) ] );
        }

        if ( $cmd_type === 'CHANGE_TYPE' ) {
            $new_type = sanitize_text_field( $cmd_val );
            if ( ! in_array( $new_type, [ 'standard', 'pro', 'developer', 'trial', 'demo' ], true ) ) {
                wp_send_json_error( [ 'message' => __( 'Invalid license type.', 'vapt-security' ) ], 400 );
            }
            $queued = [
                'type'        => 'CHANGE_TYPE',
                'license_type'=> $new_type,
                'queued_at'   => $now,
            ];
            $pending[ $build_id ][] = $queued;
            update_option( 'vapt_pending_commands', $pending, false );
            wp_send_json_success( [ 'message' => __( 'Queued license type change.', 'vapt-security' ) ] );
        }

        if ( $cmd_type === 'SUSPEND' ) {
            $queued = [
                'type'      => 'SUSPEND',
                'queued_at' => $now,
            ];
            $pending[ $build_id ][] = $queued;
            update_option( 'vapt_pending_commands', $pending, false );
            wp_send_json_success( [ 'message' => __( 'Queued suspend request.', 'vapt-security' ) ] );
        }

        wp_send_json_error( [ 'message' => __( 'Unknown command type.', 'vapt-security' ) ], 400 );
    }

    public function handle_set_callback_test() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( (string) ( $_POST['build_id'] ?? '' ) );
        $enabled  = ! empty( $_POST['enabled'] );
        if ( $build_id === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing build_id', 'vapt-security' ) ], 400 );
        }

        $history = get_option( 'vapt_build_history', [] );
        if ( ! is_array( $history ) ) {
            $history = [];
        }

        $updated = false;
        foreach ( $history as $i => $b ) {
            if ( ! is_array( $b ) ) continue;
            if ( (string) ( $b['id'] ?? '' ) !== $build_id ) continue;
            $history[ $i ]['callback_test'] = $enabled ? 1 : 0;
            $updated = true;
            break;
        }

        if ( $updated ) {
            update_option( 'vapt_build_history', $history, false );
        }

        wp_send_json_success( [ 'message' => __( 'Updated.', 'vapt-security' ), 'updated' => $updated ? 1 : 0 ] );
    }

    public function protect_wp_cron() {
        // Only apply protection if feature is enabled
        if ( ! VAPT_FEATURE_WP_CRON_PROTECTION || $this->is_local_environment() ) {
            return;
        }

        // Check if we're accessing wp-cron.php
        if ( strpos( $_SERVER['REQUEST_URI'] ?? '', 'wp-cron.php' ) !== false ) {
            $rate_limiter = new VAPT_Rate_Limiter();
            
            // Check if IP is whitelisted
            $current_ip = $rate_limiter->get_current_ip();
            if ( in_array( $current_ip, VAPT_WHITELISTED_IPS ) ) {
                return; // Allow whitelisted IPs
            }
            
            // Apply rate limiting for cron requests
            if ( ! $rate_limiter->allow_cron_request() ) {
                // Log the blocked request if logging is enabled
                if ( VAPT_FEATURE_SECURITY_LOGGING ) {
                    $logger = new VAPT_Security_Logger();
                    $logger->log_event( 'blocked_cron_request', [
                        'ip' => $current_ip,
                        'reason' => 'rate_limit_exceeded'
                    ]);
                }
                
                // Send 429 Too Many Requests response
                http_response_code( 429 );
                wp_die( esc_html__( VAPT_RATE_LIMIT_MESSAGE, 'vapt-security' ), '', [ 'response' => 429 ] );
            }
        }

        // Disable default WP-Cron if option is enabled
        $opts = $this->get_config();
        if ( isset( $opts['enable_cron'] ) && $opts['enable_cron'] ) {
            define( 'DISABLE_WP_CRON', true );
        }
    }

    /**
     * Disable updates for white-labeled plugin to prevent overwriting by original plugin.
     * 
     * @param object $value The transient value.
     * @return object Modified transient value.
     */
    public function disable_plugin_updates( $value ) {
        if ( ! is_object( $value ) || ! isset( $value->response ) ) {
            return $value;
        }

        // Bypass for Master Admin
        if ( $this->is_master_admin() ) {
            return $value;
        }

        $wl = get_option( 'vapt_white_label_data', [] );
        if ( empty( $wl ) ) {
            return $value;
        }

        $plugin_file = plugin_basename( __FILE__ );
        if ( isset( $value->response[ $plugin_file ] ) ) {
            unset( $value->response[ $plugin_file ] );
        }

        return $value;
    }

    /**
     * Get decrypted configuration.
     * 
     * @return array
     */
    public function get_config() {
        $raw = get_option( 'vapt_security_options', [] );
        
        // If it's an array, it's not encrypted yet (legacy or fresh install before save)
        if ( is_array( $raw ) ) {
            return $raw;
        }
        
        // It's a string, so decrypt it
        $json = VAPT_Encryption::decrypt( $raw );
        if ( $json ) {
            return json_decode( $json, true ) ?: [];
        }
        
        return [];
    }

    /**
     * White-label the plugin info in the WordPress Plugins list.
     * 
     * @param array $plugins Array of all plugins.
     * @return array Modified array of plugins.
     */
    public function white_label_plugin_info( $plugins ) {
        // Bypass for Master Admin
        if ( $this->is_master_admin() || $this->is_master_site() ) {
            return $plugins;
        }

        $wl = get_option( 'vapt_white_label_data', [] );
        if ( empty( $wl ) ) {
            return $plugins;
        }

        $plugin_file = plugin_basename( __FILE__ );
        if ( isset( $plugins[ $plugin_file ] ) ) {
            if ( ! empty( $wl['name'] ) ) {
                $plugins[ $plugin_file ]['Name'] = $wl['name'];
                $plugins[ $plugin_file ]['Title'] = $wl['name'];
            }
            if ( ! empty( $wl['author'] ) ) {
                $plugins[ $plugin_file ]['Author'] = $wl['author'];
                $plugins[ $plugin_file ]['AuthorName'] = $wl['author'];
            }
            if ( ! empty( $wl['description'] ) ) {
                $plugins[ $plugin_file ]['Description'] = $wl['description'];
            }
            if ( ! empty( $wl['version'] ) ) {
                $plugins[ $plugin_file ]['Version'] = $wl['version'];
            }
            if ( ! empty( $wl['company'] ) ) {
                $plugins[ $plugin_file ]['Description'] = str_replace( 'Tanveer Malik', $wl['author'], $plugins[ $plugin_file ]['Description'] );
            }
        }
        return $plugins;
    }

    /**
     * Get white labeled plugin name if available.
     */
    private function get_plugin_name() {
        if ( $this->is_master_site() ) {
            return __( 'VAPTSecurity–Full', 'vapt-security' );
        }

        $wl = get_option( 'vapt_white_label_data', [] );
        if ( ! empty( $wl['name'] ) ) {
            return $wl['name'];
        }

        return __( 'VAPTSecurity–Full', 'vapt-security' );
    }

    /**
     * Register the admin menu.
     */
    public function register_admin_menu() {
        $plugin_name = $this->get_plugin_name();
        
        // Add top-level menu page above Appearance
        add_menu_page(
            $plugin_name,
            $plugin_name,
            'manage_options',
            'vapt-security',
            [ $this, 'render_settings_page' ],
            'dashicons-shield',
            65 
        );

        // Domain Control Page (Conditionally Visible Submenu for Superadmin)
        $user = wp_get_current_user();
        if ( $user->exists() && $user->user_login === 'tanmalik786' ) {
            // Strict ID check: Must be 'tanmalik786@gmail.com' UNLESS local
            $is_local = $this->is_local_environment();
            if ( $is_local || $user->user_email === 'tanmalik786@gmail.com' ) {
                add_submenu_page(
                    'vapt-security', // Parent slug
                    __( 'VAPT Domain Admin', 'vapt-security' ),
                    __( 'Domain Admin', 'vapt-security' ),
                    'manage_options',
                    'vapt-domain-control',
                    [ $this, 'render_domain_control_page' ]
                );
            }
        }
    }

    /**
     * Enqueue assets that are only needed on the plugin settings page.
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_admin_assets( $hook ) {
        // Enqueue on both main page and Domain Control page
        if ( 'toplevel_page_vapt-security' !== $hook && 'admin_page_vapt-domain-control' !== $hook ) {
            return;
        }

        // jQuery UI Tabs is part of core WP.
        wp_enqueue_script( 'jquery-ui-tabs' );
        wp_enqueue_style( 'jquery-ui', includes_url( 'css/jquery-ui.css' ) );

        // Enqueue WordPress React and Components for professional message boxes
        wp_enqueue_script( 'wp-element' );
        wp_enqueue_script( 'wp-components' );
        wp_enqueue_style( 'wp-components' );

        // Custom CSS for the plugin.
        wp_enqueue_style( 'vapt-security-admin', plugin_dir_url( __FILE__ ) . 'assets/admin.css', [], '2.6.0' );
    }

    /**
     * Render the settings page (Standard Admin View).
     */
    public function render_settings_page() {
        // App Settings for Admins
        // No OTP required here. Just standard ACL check (handled by WP routing).
        
        include plugin_dir_path( __FILE__ ) . 'templates/admin-settings.php';
    }

    /**
     * Render the Domain Control page (Superadmin View).
     */
    public function render_domain_control_page() {
        // Strict Authorization Check
        $user = wp_get_current_user();
        $is_local = $this->is_local_environment();
        
        if ( $user->user_login !== 'tanmalik786' ) {
            wp_die( __( 'Access Denied: Invalid Username.', 'vapt-security' ) );
        }
        
        if ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) {
             wp_die( __( 'Access Denied: Invalid Superadmin Email. Please ensure your email is tanmalik786@gmail.com or access from a local environment.', 'vapt-security' ) );
        }

        include plugin_dir_path( __FILE__ ) . 'templates/admin-domain-control.php';
    }

    /**
     * Register settings, sections, and fields.
     */
    public function register_settings() {
        register_setting(
            'vapt_security_options_group',
            'vapt_security_options',
            [ $this, 'sanitize_options' ]
        );

        /* ------------------------------------------------------------------ */
        /* General tab                                                        */
        /* ------------------------------------------------------------------ */
        add_settings_section(
            'vapt_security_general',
            __( 'General Settings', 'vapt-security' ),
            function() {
                if ( VAPT_SHOW_FEATURE_INFO ) {
                    echo '<p>' . esc_html__( 'General settings for the VAPT Security plugin.', 'vapt-security' ) . '</p>';
                }
                if ( VAPT_SHOW_TEST_URLS ) {
                    echo '<p><strong>' . esc_html__( 'Test URL:', 'vapt-security' ) . '</strong> <a href="' . esc_url( home_url( '/' ) ) . '" target="_blank">' . esc_url( home_url( '/' ) ) . '</a></p>';
                }
            },
            'vapt_security_general'
        );

        add_settings_field(
            'enable_cron',
            __( 'Disable WP├â┬ó├óΓÇÜ┬¼├óΓé¼╦£Cron', 'vapt-security' ),
            [ $this, 'render_enable_cron_cb' ],
            'vapt_security_general',
            'vapt_security_general'
        );

        /* ------------------------------------------------------------------ */
        /* Rate Limiter tab                                                  */
        /* ------------------------------------------------------------------ */
        // Only register if feature is enabled
        if ( VAPT_FEATURE_RATE_LIMITING ) {
            add_settings_section(
                'vapt_security_rate_limiter',
                __( 'Rate Limiter', 'vapt-security' ),
                function() {
                    if ( VAPT_SHOW_FEATURE_INFO ) {
                        echo '<p>' . esc_html__( 'Controls the rate limiting for form submissions to prevent abuse.', 'vapt-security' ) . '</p>';
                    }
                    if ( VAPT_SHOW_TEST_URLS ) {
                        echo '<p><strong>' . esc_html__( 'Test URL:', 'vapt-security' ) . '</strong> <a href="' . esc_url( home_url( '/test-form/' ) ) . '" target="_blank">' . esc_url( home_url( '/test-form/' ) ) . '</a></p>';
                        echo '<p class="description">' . esc_html__( 'Note: Create a test form on this page to verify rate limiting functionality.', 'vapt-security' ) . '</p>';
                    }
                },
                'vapt_security_rate_limiter'
            );

            add_settings_field(
                'rate_limit_max',
                __( 'Max Requests per Minute', 'vapt-security' ),
                [ $this, 'render_rate_limit_max_cb' ],
                'vapt_security_rate_limiter',
                'vapt_security_rate_limiter'
            );

            add_settings_field(
                'rate_limit_window',
                __( 'Rate Limit Window (minutes)', 'vapt-security' ),
                [ $this, 'render_rate_limit_window_cb' ],
                'vapt_security_rate_limiter',
                'vapt_security_rate_limiter'
            );
        }

        /* ------------------------------------------------------------------ */
        /* Input Validation tab                                            */
        /* ------------------------------------------------------------------ */
        // Only register if feature is enabled
        if ( VAPT_FEATURE_INPUT_VALIDATION ) {
            add_settings_section(
                'vapt_security_validation',
                __( 'Input Validation', 'vapt-security' ),
                function() {
                    if ( VAPT_SHOW_FEATURE_INFO ) {
                        echo '<p>' . esc_html__( 'Validates and sanitizes user input to prevent XSS and injection attacks.', 'vapt-security' ) . '</p>';
                    }
                    if ( VAPT_SHOW_TEST_URLS ) {
                        echo '<p><strong>' . esc_html__( 'Test URL:', 'vapt-security' ) . '</strong> <a href="' . esc_url( home_url( '/test-form/' ) ) . '" target="_blank">' . esc_url( home_url( '/test-form/' ) ) . '</a></p>';
                        echo '<p class="description">' . esc_html__( 'Note: Create a test form on this page to verify input validation functionality.', 'vapt-security' ) . '</p>';
                    }
                },
                'vapt_security_validation'
            );

            add_settings_field(
                'validation_email',
                __( 'Require Valid Email?', 'vapt-security' ),
                [ $this, 'render_validation_email_cb' ],
                'vapt_security_validation',
                'vapt_security_validation'
            );

            add_settings_field(
                'validation_sanitization_level',
                __( 'Sanitization Level', 'vapt-security' ),
                [ $this, 'render_sanitization_level_cb' ],
                'vapt_security_validation',
                'vapt_security_validation'
            );
        }
        
        /* ------------------------------------------------------------------ */
        /* Form Integrations tab                                            */
        /* ------------------------------------------------------------------ */
        // Only register if Input Validation is enabled
        if ( VAPT_FEATURE_INPUT_VALIDATION ) {
            add_settings_section(
                'vapt_security_integrations',
                __( 'Form Integrations', 'vapt-security' ),
                function() {
                    echo '<p>' . esc_html__( 'Automatically apply Input Validation to third-party form plugins.', 'vapt-security' ) . '</p>';
                    echo '<div class="notice notice-info inline"><p>';
                    echo '<strong>' . esc_html__( 'Note for Administrators:', 'vapt-security' ) . '</strong><br>';
                    echo esc_html__( 'Enabling these integrations will enforcement security checks on form submissions. If "Strict" sanitization is selected, submissions containing HTML or scripts may be blocked or sanitized depending on the hook availability.', 'vapt-security' );
                    echo '</p></div>';
                },
                'vapt_security_validation' // Add to Input Validation tab for now, or create new tab if needed. Using same slug as Validation tab to check settings
            );
            
            // To keep it clean, maybe just append to 'vapt_security_validation' section or create a new one on the same page? 
            // The render_settings_page uses `do_settings_sections( 'vapt_security_validation' )` ? 
            // Wait, standard WP settings API logic:
            // add_settings_section( $id, $title, $callback, $page )
            // The $page argument links it to do_settings_sections($page).
            // In templates/admin-settings.php (which I haven't seen fully but I can infer), it likely iterates tabs.
            // Let's stick "Form Integrations" into the 'vapt_security_validation' page for simplicity if the UI puts them together,
            // or better, create a subsection in 'vapt_security_validation' PAGE.
            // Actually, looking at the code above, 'vapt_security_validation' is used as the PAGE ID for Input Validation settings.

            add_settings_field(
                'integration_cf7',
                __( 'Contact Form 7', 'vapt-security' ),
                [ $this, 'render_integration_cf7_cb' ],
                'vapt_security_validation',
                'vapt_security_integrations'
            );

            add_settings_field(
                'integration_elementor',
                __( 'Elementor Forms', 'vapt-security' ),
                [ $this, 'render_integration_elementor_cb' ],
                'vapt_security_validation',
                'vapt_security_integrations'
            );

            add_settings_field(
                'integration_wpforms',
                __( 'WPForms', 'vapt-security' ),
                [ $this, 'render_integration_wpforms_cb' ],
                'vapt_security_validation',
                'vapt_security_integrations'
            );

            add_settings_field(
                'integration_gravity',
                __( 'Gravity Forms', 'vapt-security' ),
                [ $this, 'render_integration_gravity_cb' ],
                'vapt_security_validation',
                'vapt_security_integrations'
            );
        }

        /* ------------------------------------------------------------------ */
        /* WP├â┬ó├óΓÇÜ┬¼├óΓé¼╦£Cron Protection tab                                         */
        /* ------------------------------------------------------------------ */
        // Only register if feature is enabled
        if ( VAPT_FEATURE_WP_CRON_PROTECTION ) {
            add_settings_section(
                'vapt_security_cron',
                __( 'WP├â┬ó├óΓÇÜ┬¼├óΓé¼╦£Cron Protection', 'vapt-security' ),
                function() {
                    if ( VAPT_SHOW_FEATURE_INFO ) {
                        echo '<p>' . esc_html__( 'Protects against DoS attacks targeting the WordPress cron system.', 'vapt-security' ) . '</p>';
                    }
                    if ( VAPT_SHOW_TEST_URLS ) {
                        echo '<p><strong>' . esc_html__( 'Test URL:', 'vapt-security' ) . '</strong> <a href="' . esc_url( home_url( VAPT_TEST_WP_CRON_URL ) ) . '" target="_blank">' . esc_url( home_url( VAPT_TEST_WP_CRON_URL ) ) . '</a></p>';
                        echo '<p class="description">' . esc_html__( 'Warning: Visiting this URL may trigger rate limiting if enabled.', 'vapt-security' ) . '</p>';
                    }
                },
                'vapt_security_cron'
            );

            add_settings_field(
                'cron_protection',
                __( 'Enable Cron Rate Limiting', 'vapt-security' ),
                [ $this, 'render_cron_protection_cb' ],
                'vapt_security_cron',
                'vapt_security_cron'
            );

            add_settings_field(
                'cron_rate_limit',
                __( 'Max Cron Requests per Hour', 'vapt-security' ),
                [ $this, 'render_cron_rate_limit_cb' ],
                'vapt_security_cron',
                'vapt_security_cron'
            );
        }

        /* ------------------------------------------------------------------ */
        /* Security Logging tab                                           */
        /* ------------------------------------------------------------------ */
        // Only register if feature is enabled
        if ( VAPT_FEATURE_SECURITY_LOGGING ) {
            add_settings_section(
                'vapt_security_logging',
                __( 'Security Logging', 'vapt-security' ),
                function() {
                    if ( VAPT_SHOW_FEATURE_INFO ) {
                        echo '<p>' . esc_html__( 'Logs security events for monitoring and analysis.', 'vapt-security' ) . '</p>';
                    }
                    if ( VAPT_SHOW_TEST_URLS ) {
                        echo '<p><strong>' . esc_html__( 'Test URL:', 'vapt-security' ) . '</strong> <a href="' . esc_url( home_url( '/test-form/' ) ) . '" target="_blank">' . esc_url( home_url( '/test-form/' ) ) . '</a></p>';
                        echo '<p class="description">' . esc_html__( 'Note: Create a test form on this page to verify logging functionality.', 'vapt-security' ) . '</p>';
                    }
                },
                'vapt_security_logging'
            );

            add_settings_field(
                'enable_logging',
                __( 'Enable Security Logging', 'vapt-security' ),
                [ $this, 'render_enable_logging_cb' ],
                'vapt_security_logging',
                'vapt_security_logging'
            );
        }

        /* ------------------------------------------------------------------ */
        /* Hardening tab - High Risk                                       */
        /* ------------------------------------------------------------------ */
        add_settings_section(
            'vapt_security_hardening_high',
            __( 'High Risk Mitigations', 'vapt-security' ),
            function() {
                if ( VAPT_SHOW_FEATURE_INFO ) {
                    echo '<p>' . esc_html__( 'Critical & High Risk vulnerabilities identified in the VAPT report.', 'vapt-security' ) . '</p>';
                }
            },
            'vapt_security_hardening_high'
        );

        add_settings_field(
            'enable_login_protection',
            __( 'Login Brute-Force Protection', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_high',
            'vapt_security_hardening_high',
            [ 
                'label_for' => 'login_protection', 
                'label' => __( 'Enable rate limiting on wp-login.php to prevent brute-force attacks.', 'vapt-security' ),
                'test_url' => wp_login_url(),
                'test_label' => __( 'Verify Login Page', 'vapt-security' )
            ]
        );

        add_settings_field(
            'login_max_attempts',
            __( 'Max Login Attempts', 'vapt-security' ),
            [ $this, 'render_login_max_attempts_cb' ],
            'vapt_security_hardening_high',
            'vapt_security_hardening_high'
        );

        add_settings_field(
            'login_lockout_duration',
            __( 'Login Lockout Duration (minutes)', 'vapt-security' ),
            [ $this, 'render_login_lockout_duration_cb' ],
            'vapt_security_hardening_high',
            'vapt_security_hardening_high'
        );

        add_settings_field(
            'enable_xmlrpc_protection',
            __( 'Disable XML-RPC', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_high',
            'vapt_security_hardening_high',
            [ 
                'label_for' => 'xmlrpc_protection', 
                'label' => __( 'Fully disable XML-RPC and remove pingback headers to prevent SSRF.', 'vapt-security' ),
                'test_url' => home_url( '/xmlrpc.php' ),
                'test_label' => __( 'Verify XML-RPC Block', 'vapt-security' )
            ]
        );

        /* ------------------------------------------------------------------ */
        /* Hardening tab - Medium Risk                                     */
        /* ------------------------------------------------------------------ */
        add_settings_section(
            'vapt_security_hardening_medium',
            __( 'Medium Risk Mitigations', 'vapt-security' ),
            function() {
                if ( VAPT_SHOW_FEATURE_INFO ) {
                    echo '<p>' . esc_html__( 'Medium Risk vulnerabilities identified in the VAPT report.', 'vapt-security' ) . '</p>';
                }
            },
            'vapt_security_hardening_medium'
        );

        add_settings_field(
            'enable_login_enum_protection',
            __( 'Login Username Enumeration', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_medium',
            'vapt_security_hardening_medium',
            [ 
                'label_for' => 'login_enum_protection', 
                'label' => __( 'Hide specific error messages on login failure to prevent username guessing.', 'vapt-security' ),
                'test_url' => wp_login_url(),
                'test_label' => __( 'Verify Error Messages', 'vapt-security' )
            ]
        );

        add_settings_field(
            'enable_directory_listing',
            __( 'Directory Listing', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_medium',
            'vapt_security_hardening_medium',
            [ 
                'label_for' => 'directory_listing', 
                'label' => __( 'Prevent file browsing in uploads and plugin directories.', 'vapt-security' ),
                'test_url' => content_url( '/uploads/' ),
                'test_label' => __( 'Verify Uploads Dir', 'vapt-security' )
            ]
        );

        add_settings_field(
            'enable_banner_grabbing',
            __( 'Banner Grabbing', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_medium',
            'vapt_security_hardening_medium',
            [ 
                'label_for' => 'banner_grabbing', 
                'label' => __( 'Hide WordPress and PHP version identifiers from headers and HTML.', 'vapt-security' ),
                'test_url' => home_url(),
                'test_label' => __( 'Check Page Source', 'vapt-security' )
            ]
        );

        add_settings_field(
            'enable_rest_api_protection',
            __( 'Restrict REST API', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_medium',
            'vapt_security_hardening_medium',
            [ 
                'label_for' => 'rest_api_protection', 
                'label' => __( 'Block unauthenticated access to REST API endpoints using a whitelist approach.', 'vapt-security' ),
                'test_url' => rest_url( 'wp/v2/users' ),
                'test_label' => __( 'Verify REST Users', 'vapt-security' )
            ]
        );

        add_settings_field(
            'rest_api_whitelist',
            __( 'Whitelisted REST Namespaces', 'vapt-security' ),
            [ $this, 'render_rest_api_whitelist_cb' ],
            'vapt_security_hardening_medium',
            'vapt_security_hardening_medium'
        );

        /* ------------------------------------------------------------------ */
        /* Hardening tab - Low Risk                                        */
        /* ------------------------------------------------------------------ */
        add_settings_section(
            'vapt_security_hardening_low',
            __( 'Low Risk Mitigations', 'vapt-security' ),
            function() {
                if ( VAPT_SHOW_FEATURE_INFO ) {
                    echo '<p>' . esc_html__( 'Low Risk vulnerabilities identified in the VAPT report.', 'vapt-security' ) . '</p>';
                }
            },
            'vapt_security_hardening_low'
        );

        add_settings_field(
            'enable_security_headers',
            __( 'Security Headers', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_low',
            'vapt_security_hardening_low',
            [ 
                'label_for' => 'security_headers', 
                'label' => __( 'Add X-Frame-Options (Clickjacking fix), X-Content-Type-Options, etc.', 'vapt-security' ),
                'test_url' => 'https://securityheaders.com/?q=' . urlencode( home_url() ) . '&followRedirects=on',
                'test_label' => __( 'Scan Security Headers', 'vapt-security' )
            ]
        );

        add_settings_field(
            'enable_debug_log_protection',
            __( 'Debug Log Protection', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_low',
            'vapt_security_hardening_low',
            [ 
                'label_for' => 'debug_log_protection', 
                'label' => __( 'Block public access to the WordPress debug.log file.', 'vapt-security' ),
                'test_url' => content_url( '/debug.log' ),
                'test_label' => __( 'Verify debug.log', 'vapt-security' )
            ]
        );

        add_settings_field(
            'enable_readme_protection',
            __( 'readme.html Protection', 'vapt-security' ),
            [ $this, 'render_feature_toggle_cb' ],
            'vapt_security_hardening_low',
            'vapt_security_hardening_low',
            [ 
                'label_for' => 'readme_protection', 
                'label' => __( 'Block public access to the WordPress readme.html file.', 'vapt-security' ),
                'test_url' => home_url( '/readme.html' ),
                'test_label' => __( 'Verify readme.html', 'vapt-security' )
            ]
        );
    }

    /**
     * Sanitize the options array.
     *
     * @param array $input Raw input.
     *
     * @return array Sanitized values.
     */
    public function sanitize_options( $input ) {
        // Create array
        $sanitized = [];
        $sanitized['enable_cron']             = isset( $input['enable_cron'] ) ? 1 : 0;
        $sanitized['rate_limit_max']          = isset( $input['rate_limit_max'] ) ? absint( $input['rate_limit_max'] ) : 10;
        $sanitized['rate_limit_window']       = isset( $input['rate_limit_window'] ) ? absint( $input['rate_limit_window'] ) : 1;
        $sanitized['validation_email']        = isset( $input['validation_email'] ) ? 1 : 0;
        $sanitized['validation_sanitization_level'] = isset( $input['validation_sanitization_level'] ) ? sanitize_text_field( $input['validation_sanitization_level'] ) : 'standard';
        $sanitized['cron_protection']         = isset( $input['cron_protection'] ) ? 1 : 0;
        $sanitized['cron_rate_limit']         = isset( $input['cron_rate_limit'] ) ? absint( $input['cron_rate_limit'] ) : 60;
        $sanitized['enable_logging']          = isset( $input['enable_logging'] ) ? 1 : 0;
        
        $sanitized['vapt_integration_cf7']       = isset( $input['vapt_integration_cf7'] ) ? 1 : 0;
        $sanitized['vapt_integration_elementor'] = isset( $input['vapt_integration_elementor'] ) ? 1 : 0;
        $sanitized['vapt_integration_wpforms']   = isset( $input['vapt_integration_wpforms'] ) ? 1 : 0;
        $sanitized['vapt_integration_gravity']   = isset( $input['vapt_integration_gravity'] ) ? 1 : 0;

        // Hardening Settings
        $sanitized['login_max_attempts']       = isset( $input['login_max_attempts'] ) ? absint( $input['login_max_attempts'] ) : 5;
        $sanitized['login_lockout_duration']   = isset( $input['login_lockout_duration'] ) ? absint( $input['login_lockout_duration'] ) : 15;
        $sanitized['rest_api_whitelist']       = isset( $input['rest_api_whitelist'] ) ? sanitize_text_field( $input['rest_api_whitelist'] ) : '';

        // Generate .htaccess rules on save
        VAPT_Hardening::write_htaccess_rules();

        // Encrypt the data before saving
        $json = json_encode( $sanitized );
        return VAPT_Encryption::encrypt( $json );
    }

    /* ------------------------------------------------------------------ */
    /* Render callbacks for the settings fields                         */
    /* ------------------------------------------------------------------ */

    public function render_enable_cron_cb() {
        $opts   = $this->get_config();
        $checked = isset( $opts['enable_cron'] ) ? checked( 1, $opts['enable_cron'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[enable_cron]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Disable WP├â┬ó├óΓÇÜ┬¼├óΓé¼╦£Cron (recommended for production sites)', 'vapt-security' ); ?>
        </label>
        <p class="description"><?php esc_html_e( 'Prevents abuse of the WordPress cron system by disabling the default behavior and requiring manual cron setup.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_rate_limit_max_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['rate_limit_max'] ) ? absint( $opts['rate_limit_max'] ) : 10;
        ?>
        <input type="number" name="vapt_security_options[rate_limit_max]" value="<?php echo esc_attr( $val ); ?>" min="1" max="1000" />
        <p class="description"><?php esc_html_e( 'Maximum form submissions allowed per minute per IP address.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_rate_limit_window_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['rate_limit_window'] ) ? absint( $opts['rate_limit_window'] ) : 1;
        ?>
        <input type="number" name="vapt_security_options[rate_limit_window]" value="<?php echo esc_attr( $val ); ?>" min="1" max="60" />
        <p class="description"><?php esc_html_e( 'Time window in minutes for rate limiting.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_validation_email_cb() {
        $opts   = $this->get_config();
        $checked = isset( $opts['validation_email'] ) ? checked( 1, $opts['validation_email'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[validation_email]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Require a valid email address for all forms', 'vapt-security' ); ?>
        </label>
        <p class="description"><?php esc_html_e( 'Enforces email validation on all form submissions to prevent spam and invalid data.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_sanitization_level_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['validation_sanitization_level'] ) ? sanitize_text_field( $opts['validation_sanitization_level'] ) : 'standard';
        ?>
        <select name="vapt_security_options[validation_sanitization_level]">
            <option value="basic" <?php selected( $val, 'basic' ); ?>><?php esc_html_e( 'Basic', 'vapt-security' ); ?></option>
            <option value="standard" <?php selected( $val, 'standard' ); ?>><?php esc_html_e( 'Standard', 'vapt-security' ); ?></option>
            <option value="strict" <?php selected( $val, 'strict' ); ?>><?php esc_html_e( 'Strict', 'vapt-security' ); ?></option>
        </select>
        <p class="description"><?php esc_html_e( 'Higher levels provide more security but may block legitimate input.', 'vapt-security' ); ?></p>
        <?php
    }

    /* ------------------------------------------------------------------ */
    /* Integration Callbacks                                            */
    /* ------------------------------------------------------------------ */

    public function render_integration_cf7_cb() {
        $opts = $this->get_config();
        $checked = isset( $opts['vapt_integration_cf7'] ) ? checked( 1, $opts['vapt_integration_cf7'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[vapt_integration_cf7]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable validation for Contact Form 7', 'vapt-security' ); ?>
        </label>
        <?php
    }

    public function render_integration_elementor_cb() {
        $opts = $this->get_config();
        $checked = isset( $opts['vapt_integration_elementor'] ) ? checked( 1, $opts['vapt_integration_elementor'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[vapt_integration_elementor]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable validation for Elementor Forms', 'vapt-security' ); ?>
        </label>
        <?php
    }

    public function render_integration_wpforms_cb() {
        $opts = $this->get_config();
        $checked = isset( $opts['vapt_integration_wpforms'] ) ? checked( 1, $opts['vapt_integration_wpforms'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[vapt_integration_wpforms]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable validation for WPForms', 'vapt-security' ); ?>
        </label>
        <?php
    }

    public function render_integration_gravity_cb() {
        $opts = $this->get_config();
        $checked = isset( $opts['vapt_integration_gravity'] ) ? checked( 1, $opts['vapt_integration_gravity'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[vapt_integration_gravity]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable validation for Gravity Forms', 'vapt-security' ); ?>
        </label>
        <?php
    }

    public function render_cron_protection_cb() {
        $opts   = $this->get_config();
        $checked = isset( $opts['cron_protection'] ) ? checked( 1, $opts['cron_protection'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[cron_protection]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable rate├â┬ó├óΓÇÜ┬¼├óΓé¼╦£limiting on wp-cron endpoints', 'vapt-security' ); ?>
        </label>
        <p class="description"><?php esc_html_e( 'Protects against DoS attacks by limiting requests to wp-cron.php.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_cron_rate_limit_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['cron_rate_limit'] ) ? absint( $opts['cron_rate_limit'] ) : 60;
        ?>
        <input type="number" name="vapt_security_options[cron_rate_limit]" value="<?php echo esc_attr( $val ); ?>" min="1" max="1000" />
        <p class="description"><?php esc_html_e( 'Maximum cron requests allowed per hour.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_enable_logging_cb() {
        $opts   = $this->get_config();
        $checked = isset( $opts['enable_logging'] ) ? checked( 1, $opts['enable_logging'], false ) : '';
        ?>
        <label>
            <input type="checkbox" name="vapt_security_options[enable_logging]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e( 'Enable security event logging', 'vapt-security' ); ?>
        </label>
        <p class="description"><?php esc_html_e( 'Log security events for monitoring and analysis.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_login_max_attempts_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['login_max_attempts'] ) ? absint( $opts['login_max_attempts'] ) : 5;
        ?>
        <input type="number" name="vapt_security_options[login_max_attempts]" value="<?php echo esc_attr( $val ); ?>" min="1" max="100" />
        <p class="description"><?php esc_html_e( 'Maximum failed login attempts before lockout.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_login_lockout_duration_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['login_lockout_duration'] ) ? absint( $opts['login_lockout_duration'] ) : 15;
        ?>
        <input type="number" name="vapt_security_options[login_lockout_duration]" value="<?php echo esc_attr( $val ); ?>" min="1" max="1440" />
        <p class="description"><?php esc_html_e( 'Duration in minutes for which the IP will be blocked.', 'vapt-security' ); ?></p>
        <?php
    }

    public function render_rest_api_whitelist_cb() {
        $opts = $this->get_config();
        $val  = isset( $opts['rest_api_whitelist'] ) ? sanitize_text_field( $opts['rest_api_whitelist'] ) : '';
        ?>
        <textarea name="vapt_security_options[rest_api_whitelist]" rows="3" cols="50" class="large-text"><?php echo esc_textarea( $val ); ?></textarea>
        <p class="description"><?php esc_html_e( 'Comma-separated list of namespaces to whitelist (e.g., "wc/v3, jetpack/v4"). Default allowed: oembed/1.0, wp-site-health/v1, contact-form-7/v1.', 'vapt-security' ); ?></p>
        <?php
    }

    /**
     * Generic render callback for feature toggles that sync with Domain Features.
     */
    public function render_feature_toggle_cb( $args ) {
        $feature_slug = $args['label_for'];
        $label = $args['label'];
        $is_enabled = VAPT_Features::is_enabled( $feature_slug );
        $checked = checked( true, $is_enabled, false );
        ?>
        <label>
            <input type="checkbox" name="vapt_domain_features[<?php echo esc_attr( $feature_slug ); ?>]" value="1" <?php echo $checked; ?> />
            <?php echo esc_html( $label ); ?>
        </label>
        <?php if ( VAPT_SHOW_TEST_URLS && ! empty( $args['test_url'] ) ) : ?>
            <p class="description">
                <strong><?php esc_html_e( 'Test URL:', 'vapt-security' ); ?></strong>
                <a href="<?php echo esc_url( $args['test_url'] ); ?>" target="_blank"><?php echo esc_html( $args['test_label'] ); ?></a>
                <?php if ( ! empty( $args['extra_test_url'] ) ) : ?>
                    | <a href="<?php echo esc_url( $args['extra_test_url'] ); ?>" target="_blank"><?php echo esc_html( $args['extra_test_label'] ); ?></a>
                <?php endif; ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Initialize security logging
     */
    public function initialize_security_logging() {
        // Logging is initialized on demand when needed
    }

    /**
     * Handle plugin activation
     */
    public function activate_plugin() {
        // Schedule cleanup event
        if ( ! wp_next_scheduled( 'vapt_cleanup_event' ) ) {
            wp_schedule_event( time(), 'hourly', 'vapt_cleanup_event' );
        }
        
        // Enforce lock on activation
        if ( ! $this->is_master_admin() && ! $this->is_master_site() ) {
            $this->enforce_domain_lock( true );
            $config = $this->get_locked_config_payload();
            $build_id = is_array( $config ) ? (string) ( $config['build_id'] ?? '' ) : '';
            if ( $build_id !== '' ) {
                $meta = $this->vapt_get_client_build_meta();
                $row  = is_array( $meta[ $build_id ] ?? null ) ? $meta[ $build_id ] : [];
                $now = time();
                if ( empty( $row['install'] ) ) {
                    $row['install'] = $now;
                }
                if ( empty( $row['activation'] ) ) {
                    $row['activation'] = $now;
                }
                $meta[ $build_id ] = $row;
                $this->vapt_set_client_build_meta( $meta );
            }
        }

        // Generate initial .htaccess rules
        VAPT_Hardening::write_htaccess_rules();
    }

    /**
     * Activate the license.
     */
    public function activate_license() {
        if ( $this->is_master_admin() || $this->is_master_site() ) {
            VAPT_License::activate_license();
            return;
        }

        $config = $this->get_locked_config_payload();
        if ( ! is_array( $config ) ) {
            VAPT_License::activate_license();
            return;
        }

        $build_id = (string) ( $config['build_id'] ?? '' );
        $times = $this->vapt_maybe_init_client_timestamps( $build_id );
        $this->vapt_maybe_seed_client_license(
            $config,
            $build_id,
            (int) ( $times['activation'] ?? 0 ),
            (int) ( $times['install'] ?? 0 )
        );
    }

    /**
     * Handle plugin deactivation
     */
    public function deactivate_plugin() {
        // Clear scheduled events
        wp_clear_scheduled_hook( 'vapt_cleanup_event' );
    }

    /**
     * Cleanup old data
     */
    public function cleanup_old_data() {
        $rate_limiter = new VAPT_Rate_Limiter();
        $rate_limiter->clean_old_entries();
        
        $logger = new VAPT_Security_Logger();
        $logger->cleanup_old_logs();
    }

    /* ------------------------------------------------------------------ */
    /* AJAX form handling                                               */
    /* ------------------------------------------------------------------ */

    public function handle_form_submission() {
        // Only process if feature is enabled
        if ( ! VAPT_FEATURE_RATE_LIMITING && ! VAPT_FEATURE_INPUT_VALIDATION ) {
            wp_send_json_error( [ 'message' => __( 'Form processing is disabled.', 'vapt-security' ) ], 400 );
            return;
        }

        // Log the form submission attempt if logging is enabled
        if ( VAPT_FEATURE_SECURITY_LOGGING ) {
            $logger = new VAPT_Security_Logger();
            $rate_limiter = new VAPT_Rate_Limiter();
            $logger->log_event( 'form_submission_attempt', [
                'ip' => $rate_limiter->get_current_ip(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
        }

        // 1. Rate limiting (if enabled)
        if ( VAPT_FEATURE_RATE_LIMITING ) {
            $rate_limiter = new VAPT_Rate_Limiter();
            
            // Check if IP is whitelisted
            $current_ip = $rate_limiter->get_current_ip();
            if ( ! in_array( $current_ip, VAPT_WHITELISTED_IPS ) && ! $rate_limiter->allow_request() ) {
                // Log the blocked request if logging is enabled
                if ( VAPT_FEATURE_SECURITY_LOGGING ) {
                    $logger = new VAPT_Security_Logger();
                    $logger->log_event( 'blocked_form_submission', [
                        'ip' => $current_ip,
                        'reason' => 'rate_limit_exceeded'
                    ]);
                }
                
                wp_send_json_error(
                    [
                        'message' => __( VAPT_RATE_LIMIT_MESSAGE, 'vapt-security' ),
                    ],
                    429
                );
            }
        }

        // 2. Nonce verification
        if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'vapt_form_action' ) ) {
            // Log the invalid nonce if logging is enabled
            if ( VAPT_FEATURE_SECURITY_LOGGING ) {
                $logger = new VAPT_Security_Logger();
                $logger->log_event( 'invalid_nonce', [
                    'ip' => $rate_limiter->get_current_ip()
                ]);
            }
            
            wp_send_json_error(
                [
                    'message' => __( VAPT_INVALID_NONCE_MESSAGE, 'vapt-security' ),
                ],
                400
            );
        }

        // 3. Input validation (if enabled)
        if ( VAPT_FEATURE_INPUT_VALIDATION ) {
            $validator = new VAPT_Input_Validator();
            $schema    = [
                'name'    => [ 'required' => true,  'type' => 'string', 'max' => 50 ],
                'email'   => [ 'required' => true,  'type' => 'email',  'max' => 100 ],
                'message' => [ 'required' => true,  'type' => 'string', 'max' => 500 ],
                'captcha' => [ 'required' => false, 'type' => 'string', 'max' => 10  ],
            ];
            $data = $validator->validate( $_POST, $schema );

            if ( is_wp_error( $data ) ) {
                // Log the validation error if logging is enabled
                if ( VAPT_FEATURE_SECURITY_LOGGING ) {
                    $logger = new VAPT_Security_Logger();
                    $logger->log_event( 'validation_error', [
                        'ip' => $rate_limiter->get_current_ip(),
                        'error' => $data->get_error_message()
                    ]);
                }
                
                wp_send_json_error( [ 'message' => $data->get_error_message() ], 400 );
            }
        } else {
            // Basic sanitization if validation is disabled
            $data = [
                'name'    => sanitize_text_field( $_POST['name'] ?? '' ),
                'email'   => sanitize_email( $_POST['email'] ?? '' ),
                'message' => sanitize_textarea_field( $_POST['message'] ?? '' ),
                'captcha' => sanitize_text_field( $_POST['captcha'] ?? '' ),
            ];
        }

        // 4. Optional CAPTCHA check
        if ( ! empty( $data['captcha'] ) ) {
            $captcha = new VAPT_Captcha();
            if ( ! $captcha->verify( $data['captcha'] ) ) {
                // Log the failed CAPTCHA if logging is enabled
                if ( VAPT_FEATURE_SECURITY_LOGGING ) {
                    $logger = new VAPT_Security_Logger();
                    $logger->log_event( 'failed_captcha', [
                        'ip' => $rate_limiter->get_current_ip()
                    ]);
                }
                
                wp_send_json_error(
                    [
                        'message' => __( 'CAPTCHA verification failed.', 'vapt-security' ),
                    ],
                    400
                );
            }
        }

        // 5. Process the form (e.g., send an email)
        $to      = get_option( 'admin_email' );
        $subject = sprintf(
            __( 'New message from %s', 'vapt-security' ),
            $data['name']
        );
        $body    = sprintf(
            __( "Name: %s\nEmail: %s\n\nMessage:\n%s", 'vapt-security' ),
            $data['name'],
            $data['email'],
            $data['message']
        );

        wp_mail( $to, $subject, $body );

        // Log successful submission if logging is enabled
        if ( VAPT_FEATURE_SECURITY_LOGGING ) {
            $logger = new VAPT_Security_Logger();
            $logger->log_event( 'successful_form_submission', [
                'ip' => $rate_limiter->get_current_ip()
            ]);
        }

        wp_send_json_success( [ 'message' => __( 'Your message was sent successfully.', 'vapt-security' ) ] );
    }

    /* ------------------------------------------------------------------ */
    /* OTP Auth                                                         */
    /* ------------------------------------------------------------------ */

    public function handle_send_otp() {
        $user = wp_get_current_user();
        
        // Check if already verified
        if ( get_transient( 'vapt_auth_' . $user->ID ) ) {
            wp_send_json_success( [ 'message' => __( 'Session already verified.', 'vapt-security' ) ] );
        }

        // Strict Check
        $is_local = $this->is_local_environment();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' ) {
            wp_send_json_error( [ 'message' => 'Unauthorized: Invalid Username' ], 403 );
        }
        if ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) {
            wp_send_json_error( [ 'message' => 'Unauthorized: Invalid Email' ], 403 );
        }

        $res = VAPT_OTP::send_otp( $user->ID );
        if ( is_wp_error( $res ) ) {
            wp_send_json_error( [ 'message' => $res->get_error_message() ] );
        }

        wp_send_json_success( [ 'message' => __( 'OTP sent to your email.', 'vapt-security' ) ] );
    }

    public function handle_verify_otp() {
        $user = wp_get_current_user();
        // Strict Check
        $is_local = $this->is_local_environment();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' ) {
             wp_send_json_error( [ 'message' => 'Unauthorized: Invalid Username' ], 403 );
        }
        if ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) {
             wp_send_json_error( [ 'message' => 'Unauthorized: Invalid Email' ], 403 );
        }

        $otp = sanitize_text_field( $_POST['otp'] ?? '' );
        $res = VAPT_OTP::verify_otp( $user->ID, $otp );

        if ( is_wp_error( $res ) ) {
            wp_send_json_error( [ 'message' => $res->get_error_message() ] );
        }

        // Set transient for 30 minutes (1800s). Extend to 1 hour (3600s) on local systems.
        $duration = $is_local ? 3600 : 1800;
        set_transient( 'vapt_auth_' . $user->ID, true, $duration );

        wp_send_json_success( [ 'message' => __( 'OTP Verified.', 'vapt-security' ) ] );
    }

    public function handle_update_license() {
        $user = wp_get_current_user();
        // Strict Check -- License update is sensitive, so maybe strict? 
        // No, keep consistent for access.
        $is_local = $this->is_local_environment();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' || ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) ) {
             wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $type = sanitize_text_field( $_POST['type'] ?? 'standard' );
        $auto_renew = isset( $_POST['auto_renew'] ) ? (int) $_POST['auto_renew'] : null;

        // Check for Type Change
        $current_license = VAPT_License::get_license();
        $expires = null;

         // Developer Constraint: Auto Renew must be disabled
        if ( $type === 'developer' ) {
            $auto_renew = 0;
        }

        if ( $current_license && isset( $current_license['type'] ) && $current_license['type'] !== $type ) {
            // Type Changed! Recalculate expiry from First Activation (start date).
            $base_time = ! empty( $current_license['start'] ) ? $current_license['start'] : time();
            
            if ( $type === 'standard' ) {
                $expires = $base_time + ( 30 * DAY_IN_SECONDS );
            } elseif ( $type === 'pro' ) {
                $expires = $base_time + ( 365 * DAY_IN_SECONDS );
            } elseif ( $type === 'trial' ) {
                $expires = $base_time + ( 7 * DAY_IN_SECONDS );
            } elseif ( $type === 'demo' ) {
                $expires = $base_time + ( 15 * DAY_IN_SECONDS );
            } else {
                $expires = 0; // Developer
            }
        }

        if ( VAPT_License::update_license( $type, $expires, $auto_renew ) ) {
            $license = VAPT_License::get_license();
            $formatted = $license['expires'] ? wp_date( get_option( 'date_format' ), $license['expires'], wp_timezone() ) : __( 'Never', 'vapt-security' );
            wp_send_json_success( [ 
                'message' => __( 'License updated.', 'vapt-security' ),
                'expires_formatted' => $formatted
            ] );
        } else {
             wp_send_json_error( [ 'message' => __( 'Failed to update license.', 'vapt-security' ) ] );
        }
    }

    public function handle_renew_license() {
        $user = wp_get_current_user();
        // Strict Check
        $is_local = $this->is_local_environment();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' || ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) ) {
             wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        if ( VAPT_License::renew() ) {
            $license = VAPT_License::get_license();
            $formatted = $license['expires'] ? wp_date( get_option( 'date_format' ), $license['expires'], wp_timezone() ) : __( 'Never', 'vapt-security' );
            wp_send_json_success( [ 
                'message' => __( 'License renewed.', 'vapt-security' ),
                'expires_formatted' => $formatted
            ] );
        } else {
             wp_send_json_error( [ 'message' => __( 'Failed to renew license.', 'vapt-security' ) ] );
        }
    }

    public function handle_save_domain_features() {
        $user = wp_get_current_user();
        // Strict Check
        $is_local = $this->is_local_environment();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' || ( ! $is_local && $user->user_email !== 'tanmalik786@gmail.com' ) ) {
             wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }
        
        parse_str( $_POST['data'], $data );
        $features = $data['features'] ?? [];
        
        if ( VAPT_Features::update_features( $features ) ) {
            wp_send_json_success( [ 'message' => 'Features saved.' ] );
        } else {
             // Maybe no change?
             wp_send_json_success( [ 'message' => 'Features saved (no change).' ] );
        }
    }

    /* ------------------------------------------------------------------ */
    /* Locked Config Features                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Get Last Build Version for a Domain Pattern
     */
    public function handle_get_last_build_version() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        $domain = sanitize_text_field( $_POST['domain'] ?? '' );
        if ( empty( $domain ) ) {
            wp_send_json_error( [ 'message' => 'Domain is required' ] );
        }

        $versions = get_option( 'vapt_locked_build_versions', [] );
        $last_version = $versions[$domain] ?? '1.0.0';

        wp_send_json_success( [ 'version' => $last_version ] );
    }

    public function handle_refresh_build_status() {
        // Verify nonce manually to prevent WordPress from dying with -1 on failure.
        // check_ajax_referer() calls wp_die('-1') when nonce is invalid, making debugging impossible.
        if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( $_POST['nonce'], 'vapt_locked_config' ) ) {
            // translators: %s is the action name.
            wp_send_json_error( [ 'message' => sprintf( __( 'Security verification failed for action "%s". Please refresh the page and try again.', 'vapt-security' ), 'vapt_refresh_build_status' ) ], 403 );
        }
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_ids_raw = $_POST['build_ids'] ?? '';
        if ( is_array( $build_ids_raw ) ) {
            $build_ids = array_map( 'sanitize_text_field', $build_ids_raw );
        } else {
            $build_ids_raw = sanitize_text_field( (string) $build_ids_raw );
            $build_ids     = array_map( 'trim', explode( ',', $build_ids_raw ) );
        }

        $build_ids = array_values( array_filter( array_unique( array_map( 'sanitize_text_field', $build_ids ) ) ) );
        if ( empty( $build_ids ) ) {
            wp_send_json_error( [ 'message' => __( 'No builds selected.', 'vapt-security' ) ] );
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        if ( ! is_array( $tracking ) ) {
            $tracking = [];
        }

        $pending = get_option( 'vapt_pending_commands', [] );
        if ( ! is_array( $pending ) ) {
            $pending = [];
        }

        $queued  = [];
        $skipped = [];

        foreach ( $build_ids as $bid ) {
            if ( $bid === '' ) {
                continue;
            }

            if ( empty( $tracking ) || ! array_key_exists( $bid, $tracking ) ) {
                $skipped[] = $bid;
                continue;
            }

            if ( ! isset( $pending[ $bid ] ) || ! is_array( $pending[ $bid ] ) ) {
                $pending[ $bid ] = [];
            }

            $last = end( $pending[ $bid ] );
            if ( is_array( $last ) && ( $last['type'] ?? '' ) === 'FORCE_CHECKIN' ) {
                $queued[] = $bid;
                continue;
            }

            $pending[ $bid ][] = [ 'type' => 'FORCE_CHECKIN', 'queued_at' => time() ];
            $queued[]          = $bid;
        }

        update_option( 'vapt_pending_commands', $pending, false );

        if ( empty( $queued ) ) {
            wp_send_json_error( [ 'message' => __( 'No valid builds to ping.', 'vapt-security' ), 'skipped' => $skipped ] );
        }

        $msg = sprintf(
            _n( 'Queued refresh for %d build.', 'Queued refresh for %d builds.', count( $queued ), 'vapt-security' ),
            count( $queued )
        );

        wp_send_json_success(
            [
                'message'  => $msg,
                'queued'   => count( $queued ),
                'builds'   => $queued,
                'skipped'  => $skipped,
            ]
        );
    }

    public function handle_get_tracking_table() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        if ( ! is_array( $tracking ) ) {
            $tracking = [];
        }

        $build_history  = get_option( 'vapt_build_history', [] );
        $build_versions = [];
        $build_names    = [];

        if ( is_array( $build_history ) ) {
            foreach ( $build_history as $b ) {
                if ( ! is_array( $b ) ) continue;
                if ( empty( $b['id'] ) ) continue;
                $build_versions[ $b['id'] ] = $b['version'] ?? '';
                $build_names[ $b['id'] ]    = $b['name'] ?? '';
            }
        }

        ob_start();

        if ( empty( $tracking ) ) {
            ?>
            <tr><td colspan="14" style="text-align:center; padding: 40px; color: #999;"><?php esc_html_e( 'No active tracking data received yet.', 'vapt-security' ); ?></td></tr>
            <?php
        } else {
            $row_num         = 0;
            $datetime_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

            foreach ( array_reverse( $tracking, true ) as $bid => $t ) {
                $row_num++;
                $t = is_array( $t ) ? $t : [];

                $last_seen  = isset( $t['last_seen'] ) ? (int) $t['last_seen'] : 0;
                $is_online  = $last_seen > 0 && ( time() - $last_seen < 24 * HOUR_IN_SECONDS );
                $row_bg     = $row_num % 2 === 0 ? ' background: #f8f9fa;' : '';

                $domain = $t['domain'] ?? '';
                $ip     = $t['ip'] ?? '';
                $license = is_array( $t['license'] ?? null ) ? $t['license'] : [];

                $install_ts    = isset( $t['initial_install'] ) ? (int) $t['initial_install'] : 0;
                $activation_ts = isset( $t['first_activation'] ) ? (int) $t['first_activation'] : 0;
                $expiry_ts     = isset( $license['expiry'] ) ? (int) $license['expiry'] : 0;
                $expected_expiry = isset( $t['expiry_expected'] ) ? (int) $t['expiry_expected'] : 0;
                $expiry_diff = isset( $t['expiry_diff'] ) ? (int) $t['expiry_diff'] : 0;
                $expiry_fix_queued_at = isset( $t['expiry_fix_queued_at'] ) ? (int) $t['expiry_fix_queued_at'] : 0;

                $install_source = sanitize_text_field( (string) ( $t['install_source'] ?? '' ) );
                if ( $install_source === '' ) {
                    $install_source = $install_ts > 0 ? 'legacy' : 'unknown';
                }
                $activation_source = sanitize_text_field( (string) ( $t['activation_source'] ?? '' ) );
                if ( $activation_source === '' ) {
                    $activation_source = $activation_ts > 0 ? 'legacy' : 'unknown';
                }

                $install_date    = $install_ts ? wp_date( $datetime_format, $install_ts, wp_timezone() ) : 'N/A';
                $activation_date = $activation_ts ? wp_date( $datetime_format, $activation_ts, wp_timezone() ) : 'N/A';
                $expiry_date     = $expiry_ts ? wp_date( $datetime_format, $expiry_ts, wp_timezone() ) : __( 'Never', 'vapt-security' );
                $expiry_warn_badge = '';
                if ( $expected_expiry > 0 && $expiry_ts > 0 && $expiry_diff > 120 ) {
                    $expected_str = wp_date( $datetime_format, $expected_expiry, wp_timezone() );
                    $queued_str = $expiry_fix_queued_at ? ( ' | Fix queued @ ' . wp_date( $datetime_format, $expiry_fix_queued_at, wp_timezone() ) ) : '';
                    $expiry_warn_badge = '<span class="vapt-ts-src vapt-ts-src-warn" title="' . esc_attr( 'Expected: ' . $expected_str . $queued_str ) . '">!</span>';
                }

                $install_src_label = $install_source === 'client' ? 'Client-reported' : ( $install_source === 'legacy' ? 'Legacy/estimated' : 'Unknown source' );
                $activation_src_label = $activation_source === 'client' ? 'Client-reported' : ( $activation_source === 'legacy' ? 'Legacy/estimated' : 'Unknown source' );
                $install_src_key = $install_source === 'client' ? 'client' : ( $install_source === 'legacy' ? 'legacy' : 'unknown' );
                $activation_src_key = $activation_source === 'client' ? 'client' : ( $activation_source === 'legacy' ? 'legacy' : 'unknown' );
                $install_src_badge = '<span class="vapt-ts-src vapt-ts-src-' . esc_attr( $install_src_key ) . '" title="' . esc_attr( $install_src_label ) . '">' . esc_html( strtoupper( substr( $install_src_key, 0, 1 ) ) ) . '</span>';
                $activation_src_badge = '<span class="vapt-ts-src vapt-ts-src-' . esc_attr( $activation_src_key ) . '" title="' . esc_attr( $activation_src_label ) . '">' . esc_html( strtoupper( substr( $activation_src_key, 0, 1 ) ) ) . '</span>';

                $build_version = $build_versions[ $bid ] ?? ( $t['version'] ?? '' );
                $build_label   = $build_names[ $bid ] ?? '';

                $lic_type   = strtoupper( (string) ( $license['type'] ?? '' ) );
                $lic_status = (string) ( $license['status'] ?? '' );
                $lic_status_color = ( $lic_status === 'active' ) ? '#008a20' : '#d63638';
                $auto_renew = ! empty( $license['auto_renew'] );
                $renewals   = $license['renewal_count'] ?? 0;
                ?>
                <tr style="<?php echo esc_attr( $row_bg ); ?>">
                    <td style="text-align:center; color: #888;"><?php echo esc_html( (string) $row_num ); ?></td>
                    <td style="text-align:center;"><input type="checkbox" class="vapt-tracking-checkbox" value="<?php echo esc_attr( (string) $bid ); ?>"></td>
                    <td>
                        <span class="vapt-build-id"><?php echo esc_html( (string) $bid ); ?></span>
                        <?php if ( ! empty( $build_version ) ) : ?>
                            <span style="color: #999; font-size: 10px;"> / v<?php echo esc_html( (string) $build_version ); ?></span>
                        <?php endif; ?>
                    </td>
                    <td style="font-size: 11px;">
                        <?php echo ! empty( $build_label ) ? esc_html( (string) $build_label ) : '<span style="color: #999;">—</span>'; ?>
                    </td>
                    <td>
                        <strong><?php echo esc_html( (string) $domain ); ?></strong>
                        <?php if ( ! empty( $ip ) ) : ?>
                            <span style="color: #999; font-weight: 400;"> / <?php echo esc_html( (string) $ip ); ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge" style="background: #2271b1; color:#fff; padding: 2px 8px; border-radius:10px; font-size:10px;">
                            <?php echo esc_html( $lic_type !== '' ? $lic_type : '—' ); ?>
                        </span>
                        <?php if ( $lic_status !== '' ) : ?>
                            <span style="font-size: 10px; color: <?php echo esc_attr( $lic_status_color ); ?>; margin-left: 4px;">
                                <?php echo esc_html( $lic_status ); ?>
                            </span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="vapt-feature-status" style="background: <?php echo esc_attr( $is_online ? '#edfaef' : '#fcf0f1' ); ?>; color: <?php echo esc_attr( $is_online ? '#008a20' : '#d63638' ); ?>;">
                            <?php echo esc_html( $is_online ? 'ONLINE' : 'OFFLINE' ); ?>
                        </span>
                    </td>
                    <td style="font-size: 11px;"><?php echo esc_html( (string) $install_date ); ?> <?php echo $install_src_badge; ?></td>
                    <td style="font-size: 11px;"><?php echo esc_html( (string) $activation_date ); ?> <?php echo $activation_src_badge; ?></td>
                    <td style="font-size: 11px; color: #666; width: 80px;">
                        <?php echo $auto_renew ? esc_html__( 'Yes', 'vapt-security' ) : esc_html__( 'No', 'vapt-security' ); ?>
                    </td>
                    <td style="font-size: 11px; color: #666; width: 90px;"><?php echo esc_html( (string) $renewals ); ?></td>
                    <td style="font-size: 11px;"><?php echo esc_html( (string) $expiry_date ); ?> <?php echo $expiry_warn_badge; ?></td>
                    <td style="font-size: 11px;">
                        <?php echo $last_seen ? esc_html( human_time_diff( $last_seen, time() ) ) . ' ago' : esc_html__( 'Never', 'vapt-security' ); ?>
                    </td>
                    <td>
                        <button type="button" class="button button-small vapt-refresh-build" data-id="<?php echo esc_attr( (string) $bid ); ?>" title="<?php esc_attr_e( 'Refresh Status', 'vapt-security' ); ?>">
                            <span class="dashicons dashicons-update" style="font-size: 16px; margin-top: 3px;"></span>
                        </button>
                        <button type="button" class="button button-small vapt-manage-build"
                            data-id="<?php echo esc_attr( (string) $bid ); ?>"
                            data-domain="<?php echo esc_attr( (string) $domain ); ?>"
                            data-expiry="<?php echo esc_attr( (string) ( $license['expiry'] ?? '' ) ); ?>"
                            data-expiry-formatted="<?php echo esc_attr( (string) $expiry_date ); ?>"
                            data-type="<?php echo esc_attr( (string) ( $license['type'] ?? '' ) ); ?>"
                            title="<?php esc_attr_e( 'Manage Deployment', 'vapt-security' ); ?>">
                            <span class="dashicons dashicons-admin-settings" style="font-size: 16px; margin-top: 3px;"></span>
                        </button>
                    </td>
                </tr>
                <?php
            }
        }

        $html = trim( (string) ob_get_clean() );
        wp_send_json_success( [ 'html' => $html ] );
    }

    public function handle_get_queued_requests_table() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $pending = get_option( 'vapt_pending_commands', [] );
        if ( ! is_array( $pending ) ) {
            $pending = [];
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        if ( ! is_array( $tracking ) ) {
            $tracking = [];
        }

        $build_history = get_option( 'vapt_build_history', [] );
        $build_meta    = [];
        if ( is_array( $build_history ) ) {
            foreach ( $build_history as $b ) {
                if ( ! is_array( $b ) ) continue;
                if ( empty( $b['id'] ) ) continue;
                $build_meta[ $b['id'] ] = $b;
            }
        }

        $rows  = [];
        $dirty = false;
        foreach ( $pending as $bid => $commands ) {
            if ( ! is_array( $commands ) || empty( $commands ) ) continue;
            foreach ( $commands as $k => $cmd ) {
                if ( ! is_array( $cmd ) ) continue;
                if ( empty( $cmd['queued_at'] ) ) {
                    $pending[ $bid ][ $k ]['queued_at'] = time();
                    $dirty = true;
                }
            }
            $rows[] = [ 'bid' => (string) $bid, 'commands' => $commands ];
        }

        if ( $dirty ) {
            update_option( 'vapt_pending_commands', $pending, false );
        }

        ob_start();

        if ( empty( $rows ) ) {
            ?>
            <tr><td colspan="6" style="text-align:center; padding: 30px; color: #999;"><?php esc_html_e( 'No queued requests.', 'vapt-security' ); ?></td></tr>
            <?php
        } else {
            $datetime_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
            $now             = time();
            $ack_log         = get_option( 'vapt_command_ack_log', [] );
            if ( ! is_array( $ack_log ) ) {
                $ack_log = [];
            }

            foreach ( $rows as $row ) {
                $bid      = $row['bid'];
                $commands = $row['commands'];

                $t          = is_array( $tracking[ $bid ] ?? null ) ? $tracking[ $bid ] : [];
                $domain      = (string) ( $t['domain'] ?? ( $build_meta[ $bid ]['domain'] ?? '' ) );
                $last_seen   = isset( $t['last_seen'] ) ? (int) $t['last_seen'] : 0;
                $supports_ack = ! empty( $t['ack_protocol'] );
                $mode        = (string) ( $build_meta[ $bid ]['tracking_mode'] ?? 'production' );
                $interval = ( $mode === 'local' ) ? VAPT_TRACKING_INTERVAL_LOCAL : VAPT_TRACKING_INTERVAL_DEFAULT;
                $auto_pause_window = $this->vapt_get_auto_pause_overdue_seconds();
                $auto_pause_minutes = (int) max( 1, round( $auto_pause_window / 60 ) );

                $next_ts = $last_seen ? ( $last_seen + $interval ) : 0;
                $pause_info = $this->vapt_get_queue_pause_info( (string) $bid );
                $is_paused = ! empty( $pause_info );
                $paused_reason = sanitize_text_field( (string) ( $pause_info['reason'] ?? '' ) );
                $paused_at = (int) ( $pause_info['paused_at'] ?? 0 );
                $paused_mode = sanitize_text_field( (string) ( $pause_info['mode'] ?? '' ) );

                if ( ! $is_paused && $next_ts && ( $now - $next_ts ) >= $auto_pause_window ) {
                    $this->vapt_set_queue_paused(
                        (string) $bid,
                        true,
                        'Auto-paused after ' . $auto_pause_minutes . ' minutes of inactivity (no client check-in).',
                        'auto'
                    );
                    $pause_info = $this->vapt_get_queue_pause_info( (string) $bid );
                    $is_paused = ! empty( $pause_info );
                    $paused_reason = sanitize_text_field( (string) ( $pause_info['reason'] ?? '' ) );
                    $paused_at = (int) ( $pause_info['paused_at'] ?? 0 );
                    $paused_mode = sanitize_text_field( (string) ( $pause_info['mode'] ?? '' ) );
                }

                $types     = [];
                $latest_ts = 0;
                foreach ( $commands as $cmd ) {
                    if ( ! is_array( $cmd ) ) continue;
                    $type = (string) ( $cmd['type'] ?? '' );
                    if ( $type !== '' ) {
                        $types[] = $type;
                    }
                    $qa = isset( $cmd['queued_at'] ) ? (int) $cmd['queued_at'] : 0;
                    if ( $qa > $latest_ts ) {
                        $latest_ts = $qa;
                    }
                }

                $types_str = ! empty( $types ) ? implode( ', ', array_unique( $types ) ) : '—';
                $queued_at = $latest_ts ? wp_date( $datetime_format, $latest_ts, wp_timezone() ) : '—';

                $last_result = '';
                $ack_items = is_array( $ack_log[ $bid ] ?? null ) ? $ack_log[ $bid ] : [];
                $ack_hit   = null;
                if ( ! empty( $ack_items ) ) {
                    foreach ( array_reverse( $ack_items ) as $a ) {
                        if ( ! is_array( $a ) ) continue;
                        $ats = (int) ( $a['ts'] ?? 0 );
                        if ( $latest_ts && $ats && $ats < $latest_ts ) {
                            continue;
                        }
                        $ack_hit = $a;
                        break;
                    }
                }

                if ( is_array( $ack_hit ) ) {
                    $ok  = ! empty( $ack_hit['ok'] );
                    $ts  = (int) ( $ack_hit['ts'] ?? 0 );
                    $typ = sanitize_text_field( (string) ( $ack_hit['type'] ?? '' ) );
                    $msg = sanitize_text_field( (string) ( $ack_hit['message'] ?? '' ) );

                    $parts = [];
                    $parts[] = $ok ? 'OK' : 'FAIL';
                    if ( $typ !== '' ) $parts[] = $typ;
                    if ( $msg !== '' ) $parts[] = '- ' . $msg;
                    if ( $ts ) $parts[] = '@ ' . wp_date( $datetime_format, $ts, wp_timezone() );
                    $last_result = implode( ' ', $parts );
                } elseif ( ! $last_seen ) {
                    $last_result = __( 'No check-in recorded', 'vapt-security' );
                } elseif ( ! $supports_ack ) {
                    $last_result = __( 'ACK not supported (update build)', 'vapt-security' );
                } else {
                    $last_result = __( 'Pending', 'vapt-security' );
                }

                if ( $is_paused ) {
                    $next_dt  = __( 'Paused', 'vapt-security' );
                    $next_eta = '';
                } elseif ( $next_ts ) {
                    $next_dt = wp_date( $datetime_format, $next_ts, wp_timezone() );
                    $next_eta = '(' . human_time_diff( $now, $next_ts ) . ')';
                } else {
                    $next_dt  = __( 'On next check-in', 'vapt-security' );
                    $next_eta = '';
                }

                $fail_details = [];
                $attempts = 0;
                if ( $is_paused ) {
                    $fail_details[] = [
                        'ts'      => $paused_at ?: time(),
                        'when'    => wp_date( $datetime_format, ( $paused_at ?: time() ), wp_timezone() ),
                        'ok'      => false,
                        'type'    => 'PAUSED',
                        'message' => ( $paused_mode === 'auto' ? 'Auto: ' : '' ) . ( $paused_reason !== '' ? $paused_reason : 'Attempts are paused for this build.' ),
                    ];
                }
                if ( ! $is_paused && $next_ts && $now > $next_ts ) {
                    $fail_details[] = [
                        'ts'      => $now,
                        'when'    => wp_date( $datetime_format, $now, wp_timezone() ),
                        'ok'      => false,
                        'type'    => 'OVERDUE',
                        'message' => 'No expected check-in yet. This is only an estimate (client must visit the site). Auto-pauses after ' . $auto_pause_minutes . ' minutes overdue.',
                    ];
                }
                if ( $last_seen && $latest_ts && $last_seen >= $latest_ts ) {
                    $attempts = 1;
                    $fail_details[] = [
                        'ts'      => $last_seen,
                        'when'    => wp_date( $datetime_format, $last_seen, wp_timezone() ),
                        'ok'      => false,
                        'type'    => $supports_ack ? 'DELIVERY' : 'CAPABILITY',
                        'message' => $supports_ack
                            ? 'Client checked in but did not acknowledge results.'
                            : 'Client is running an older build that does not support acknowledgements. Regenerate and redeploy the latest build to enable ACK.',
                    ];
                }
                if ( isset( $ack_log[ $bid ] ) && is_array( $ack_log[ $bid ] ) ) {
                    foreach ( array_reverse( $ack_log[ $bid ] ) as $a ) {
                        if ( ! is_array( $a ) ) continue;
                        $ats = (int) ( $a['ts'] ?? 0 );
                        if ( $latest_ts && $ats && $ats < $latest_ts ) continue;
                        if ( ! empty( $a['ok'] ) ) continue;
                        $attempts++;
                        $fail_details[] = [
                            'ts'      => $ats ?: time(),
                            'when'    => wp_date( $datetime_format, ( $ats ?: time() ), wp_timezone() ),
                            'ok'      => false,
                            'type'    => sanitize_text_field( (string) ( $a['type'] ?? '' ) ),
                            'message' => sanitize_text_field( (string) ( $a['message'] ?? '' ) ),
                        ];
                    }
                }

                $attempts_label = sprintf(
                    _n( '%d attempt', '%d attempts', $attempts, 'vapt-security' ),
                    $attempts
                );
                $attempts_class = ( $attempts >= 1 ) ? 'vapt-attempts-warn' : 'vapt-attempts-ok';
                $eta_text = $is_paused ? '(paused)' : $next_eta;
                $next_eta_html  = '<span class="vapt-next-exec-eta" data-bid="' . esc_attr( (string) $bid ) . '" data-next-ts="' . esc_attr( (string) $next_ts ) . '" data-details="' . esc_attr( wp_json_encode( $fail_details ) ) . '" data-paused="' . esc_attr( $is_paused ? '1' : '0' ) . '">' . esc_html( $eta_text ) . '</span>';
                $attempts_html  = '<span class="vapt-attempts-count ' . esc_attr( $attempts_class ) . '" data-attempts="' . esc_attr( (string) $attempts ) . '">' . esc_html( $attempts_label ) . '</span>';
                $next_html      = '<span class="vapt-next-exec">' . esc_html( (string) $next_dt ) . '</span> ' . $next_eta_html . ' ' . $attempts_html;
                $attempts_icon = '';
                if ( $attempts >= 1 || $is_paused ) {
                    $attempts_icon = '<span class="dashicons dashicons-info-outline vapt-attempts-info" data-bid="' . esc_attr( (string) $bid ) . '" data-details="' . esc_attr( wp_json_encode( $fail_details ) ) . '" title="View attempt details"></span>';
                }
                ?>
                <tr>
                    <td><span class="vapt-build-id"><?php echo esc_html( $bid ); ?></span></td>
                    <td><?php echo $domain !== '' ? esc_html( $domain ) : '<span style="color:#999;">—</span>'; ?></td>
                    <td style="font-family: monospace; font-size: 12px;"><?php echo esc_html( $types_str ); ?> <span style="color:#666;">(<?php echo esc_html( (string) count( $commands ) ); ?>)</span></td>
                    <td style="font-size: 12px;"><?php echo esc_html( (string) $queued_at ); ?></td>
                    <td style="font-size: 12px;"><?php echo esc_html( (string) $last_result ); ?></td>
                    <td style="font-size: 12px;"><?php echo $next_html; ?> <?php echo $attempts_icon; ?></td>
                </tr>
                <?php
            }
        }

        $html = trim( (string) ob_get_clean() );
        wp_send_json_success( [ 'html' => $html ] );
    }

    /**
     * Generate Domain Locked Configuration File
     */
    public function handle_generate_locked_config() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        // Superadmin Check
        $user = wp_get_current_user();
        // We only check login here because AJAX requests might come from same domain but verify it's the superadmin
        // In reality, this action is only accessible if you can see the page which is guarded.
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $domain_pattern = sanitize_text_field( $_POST['domain'] ?? '' );
        if ( empty( $domain_pattern ) ) {
            wp_send_json_error( [ 'message' => __( 'Domain pattern is required.', 'vapt-security' ) ] );
        }

        $include_settings = ! empty( $_POST['include_settings'] );
        $settings = [];

        if ( $include_settings ) {
            $settings = $this->get_config();
        }

        $domain_type  = sanitize_text_field( $_POST['domain_type'] ?? 'standard' );
        $lic_type     = sanitize_text_field( $_POST['license_type'] ?? 'standard' );
        $lic_renew    = ! empty( $_POST['auto_renew'] );
        
        // Calculate Expiry for history and payload
        $start = time();
        $expires = 0;
        if ( $lic_type === 'trial' ) $expires = $start + ( 7 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'demo' ) $expires = $start + ( 15 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'standard' ) $expires = $start + ( 30 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'pro' ) $expires = $start + ( 365 * DAY_IN_SECONDS );
        
        $wl_name    = sanitize_text_field( $_POST['wl_name'] ?? '' );
        $wl_slug    = sanitize_text_field( $_POST['wl_slug'] ?? '' );
        $wl_desc    = sanitize_text_field( $_POST['wl_description'] ?? '' );
        $wl_author  = sanitize_text_field( $_POST['wl_author'] ?? '' );
        $wl_company = sanitize_text_field( $_POST['wl_company'] ?? '' );
        $wl_version = sanitize_text_field( $_POST['wl_version'] ?? '1.0.0' );
        $wl_wp      = sanitize_text_field( $_POST['wl_wp_version'] ?? '5.6' );
        $wl_php     = sanitize_text_field( $_POST['wl_php_version'] ?? '8.0' );

        $display_name = ! empty( $wl_name ) ? $wl_name : 'VAPT Security';
        $build_id = !empty($_POST['edit_id']) ? sanitize_text_field($_POST['edit_id']) : 'B' . date('ymd') . '-' . substr( md5( microtime() ), 0, 4 );

        // Tracking Mode logic
        $tracking_mode = sanitize_text_field( $_POST['tracking_mode'] ?? 'production' );
        $integrity_url = VAPT_INTEGRITY_URL;
        
        if ( $tracking_mode === 'local' ) {
            $integrity_url = admin_url( 'admin-ajax.php' );
        } elseif ( $tracking_mode === 'custom' ) {
            $custom_url = esc_url_raw( $_POST['custom_url'] ?? '' );
            if ( ! empty( $custom_url ) ) {
                $integrity_url = $custom_url;
            }
        }

        $payload = [
            'build_id'       => $build_id,
            'domain_pattern' => $domain_pattern,
            'domain_type'    => $domain_type,
            'tracking_mode'  => $tracking_mode,
            'integrity_url'  => $integrity_url,
            'callback_test'  => ! empty( $_POST['include_callback_test'] ),
            'license'        => [
                'type'       => $lic_type,
                'auto_renew' => $lic_renew,
                'start'      => $start,
                'expires'    => $expires,
                'renewal_count' => 0
            ],
            'white_label'    => [
                'name'    => $wl_name,
                'slug'    => $wl_slug,
                'description' => $wl_desc,
                'author'  => $wl_author,
                'company' => $wl_company,
                'version' => $wl_version,
                'requires_at_least' => $wl_wp,
                'requires_php'      => $wl_php
            ],
            'settings'       => $settings,
            'generated_at'   => time(),
            'generated_by'   => $user->user_login
        ];

        // Store version for this domain
        $versions = get_option( 'vapt_locked_build_versions', [] );
        $versions[$domain_pattern] = $wl_version;
        update_option( 'vapt_locked_build_versions', $versions );

        // Create PHP file content
        $json_payload = json_encode( $payload );
        
        // Generate Integrity Signature to prevent tampering
        // We use a fixed salt for now since this must be verifiable across different installations
        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $signature = hash_hmac( 'sha256', $json_payload, $salt );

        // We double encode or create strict php file
        $file_content = "<?php
/**
 * {$display_name} - Domain Locked Configuration
 * 
 * This file is automatically generated.
 * It is locked to the domain pattern: {$domain_pattern}
 * 
 * DO NOT EDIT THIS FILE MANUALLY.
 * Integrity Check: {$signature}
 */

\$vapt_locked_config_data = '" . addslashes($json_payload) . "';
\$vapt_locked_config_sig = '{$signature}';
";

        // Sanitize domain for filename
        $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain_pattern );
        $safe_domain = trim( $safe_domain, '-' );
        $filename = "vapt-{$safe_domain}-locked-config.php";
        $file_path = plugin_dir_path( __FILE__ ) . 'releases/configurations/' . $filename;

        if ( file_put_contents( $file_path, $file_content ) ) {
            // Log to history
            $payload['filename'] = $filename;
            $this->add_build_to_history( $payload, 'config', $build_id );

            wp_send_json_success([
                'message'  => __( 'Configuration generated and saved to server.', 'vapt-security' ),
                'filename' => $filename
            ]);
        } else {
             wp_send_json_error( [ 'message' => __( 'Failed to write configuration file to server.', 'vapt-security' ) ] );
        }
    }

    /**
     * Generate Client Zip (Domain Specific)
     */
    public function handle_generate_client_zip() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        $user = wp_get_current_user();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        if ( ! class_exists( 'ZipArchive' ) ) {
            wp_send_json_error( [ 'message' => __( 'ZipArchive PHP extension is missing.', 'vapt-security' ) ] );
        }

        // 1. Generate the Config Content (Reusing logic)
        $domain_pattern = sanitize_text_field( $_POST['domain'] ?? '' );
        if ( empty( $domain_pattern ) ) {
            wp_send_json_error( [ 'message' => __( 'Domain pattern is required.', 'vapt-security' ) ] );
        }
        $include_settings = ! empty( $_POST['include_settings'] );
        $settings = $include_settings ? $this->get_config() : [];
        
        $domain_type  = sanitize_text_field( $_POST['domain_type'] ?? 'standard' );
        $lic_type     = sanitize_text_field( $_POST['license_type'] ?? 'standard' );
        $lic_renew    = ! empty( $_POST['auto_renew'] );

        // Calculate Expiry for history and payload
        $start = time();
        $expires = 0;
        if ( $lic_type === 'trial' ) $expires = $start + ( 7 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'demo' ) $expires = $start + ( 15 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'standard' ) $expires = $start + ( 30 * DAY_IN_SECONDS );
        elseif ( $lic_type === 'pro' ) $expires = $start + ( 365 * DAY_IN_SECONDS );

        $wl_name    = sanitize_text_field( $_POST['wl_name'] ?? '' );
        $wl_slug    = sanitize_text_field( $_POST['wl_slug'] ?? '' );
        $wl_desc    = sanitize_text_field( $_POST['wl_description'] ?? '' );
        $wl_author  = sanitize_text_field( $_POST['wl_author'] ?? '' );
        $wl_company = sanitize_text_field( $_POST['wl_company'] ?? '' );
        $wl_version = sanitize_text_field( $_POST['wl_version'] ?? '1.0.0' );
        $wl_wp      = sanitize_text_field( $_POST['wl_wp_version'] ?? '5.6' );
        $wl_php     = sanitize_text_field( $_POST['wl_php_version'] ?? '8.0' );

        $display_name = ! empty( $wl_name ) ? $wl_name : 'VAPT Security';
        $build_id = !empty($_POST['edit_id']) ? sanitize_text_field($_POST['edit_id']) : 'B' . date('ymd') . '-' . substr( md5( microtime() ), 0, 4 );

        // Tracking Mode logic
        $tracking_mode = sanitize_text_field( $_POST['tracking_mode'] ?? 'production' );
        $integrity_url = VAPT_INTEGRITY_URL;
        
        if ( $tracking_mode === 'local' ) {
            $integrity_url = admin_url( 'admin-ajax.php' );
        } elseif ( $tracking_mode === 'custom' ) {
            $custom_url = esc_url_raw( $_POST['custom_url'] ?? '' );
            if ( ! empty( $custom_url ) ) {
                $integrity_url = $custom_url;
            }
        }

        $payload = [
            'build_id'       => $build_id,
            'domain_pattern' => $domain_pattern,
            'domain_type'    => $domain_type,
            'tracking_mode'  => $tracking_mode,
            'integrity_url'  => $integrity_url,
            'callback_test'  => ! empty( $_POST['include_callback_test'] ),
            'license'        => [
                'type'       => $lic_type,
                'auto_renew' => $lic_renew,
                'start'      => $start,
                'expires'    => $expires,
                'renewal_count' => 0
            ],
            'white_label'    => [
                'name'    => $wl_name,
                'slug'    => $wl_slug,
                'description' => $wl_desc,
                'author'  => $wl_author,
                'company' => $wl_company,
                'version' => $wl_version,
                'requires_at_least' => $wl_wp,
                'requires_php'      => $wl_php
            ],
            'settings'       => $settings,
            'generated_at'   => time(),
            'generated_by'   => $user->user_login
        ];

        // Store version for this domain
        $versions = get_option( 'vapt_locked_build_versions', [] );
        $versions[$domain_pattern] = $wl_version;
        update_option( 'vapt_locked_build_versions', $versions );

        $json_payload = json_encode( $payload );
        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $signature = hash_hmac( 'sha256', $json_payload, $salt );
        
        $config_content = "<?php
/**
 * {$display_name} - Domain Locked Configuration
 * 
 * This file is automatically generated.
 * It is locked to the domain pattern: {$domain_pattern}
 * 
 * DO NOT EDIT THIS FILE MANUALLY.
 * Integrity Check: {$signature}
 */

\$vapt_locked_config_data = '" . addslashes($json_payload) . "';
\$vapt_locked_config_sig = '{$signature}';
";

        // 2. Build Zip — use .buildincl allowlist
        $zip_file = tempnam( sys_get_temp_dir(), 'vapt_client_' );
        $zip = new ZipArchive();
        if ( $zip->open( $zip_file, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== TRUE ) {
            wp_send_json_error( [ 'message' => __( 'Could not create temp zip file.', 'vapt-security' ) ] );
        }

        // Folder name inside zip
        $folder = 'vapt-security';
        $zip->addEmptyDir( $folder );

        // Add Config File
        $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain_pattern );
        $safe_domain = trim( $safe_domain, '-' );
        $config_filename = "vapt-{$safe_domain}-locked-config.php";
        $zip->addFromString( $folder . '/' . $config_filename, $config_content );

        // Read .buildincl allowlist
        $plugin_path  = untrailingslashit( plugin_dir_path( __FILE__ ) );
        $buildincl    = $plugin_path . '/.buildincl';
        $include_list = [];

        if ( file_exists( $buildincl ) ) {
            $lines = file( $buildincl, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
            foreach ( $lines as $line ) {
                $line = trim( $line );
                if ( $line === '' || $line[0] === '#' ) continue;
                $include_list[] = rtrim( $line, '/' );
            }
        }

        // Fallback hardcoded allowlist if .buildincl is missing
        if ( empty( $include_list ) ) {
            $include_list = [
                'vapt-security.php',
                'uninstall.php',
                'README.txt',
                'USER_GUIDE.md',
                'assets',
                'includes',
                'templates',
                'vendor/autoload.php',
                'vendor/composer',
            ];
        }

        // Expand allowlist entries into actual files
        foreach ( $include_list as $entry ) {
            $full_entry = $plugin_path . '/' . $entry;

            if ( is_file( $full_entry ) ) {
                // Single file entry
                $relative_path = $entry;

                // Skip any locked-config files
                if ( strpos( $relative_path, '-locked-config.php' ) !== false ) continue;

                // White-label main plugin file header
                if ( $relative_path === 'vapt-security.php' ) {
                    $main_content = file_get_contents( $full_entry );
                    $header_end   = strpos( $main_content, '*/' );
                    if ( $header_end !== false ) {
                        $header_end += 2;
                        $header = substr( $main_content, 0, $header_end );
                        $rest   = substr( $main_content, $header_end );
                        if ( ! empty( $wl_name ) )   $header = preg_replace( '/Plugin Name: .*/', 'Plugin Name: ' . $wl_name, $header );
                        if ( ! empty( $wl_author ) )  $header = preg_replace( '/Author: .*/', 'Author: ' . $wl_author, $header );
                        if ( ! empty( $wl_desc ) )    $header = preg_replace( '/Description: .*/', 'Description: ' . $wl_desc, $header );
                        if ( ! empty( $wl_version ) ) $header = preg_replace( '/Version: .*/', 'Version: ' . $wl_version, $header );
                        if ( ! empty( $wl_wp ) ) {
                            if ( strpos( $header, 'Requires at least:' ) !== false ) {
                                $header = preg_replace( '/Requires at least: .*/', 'Requires at least: ' . $wl_wp, $header );
                            } else {
                                $header = str_replace( 'Version: ' . $wl_version, 'Version: ' . $wl_version . "\n * Requires at least: " . $wl_wp, $header );
                            }
                        }
                        if ( ! empty( $wl_php ) ) {
                            if ( strpos( $header, 'Requires PHP:' ) !== false ) {
                                $header = preg_replace( '/Requires PHP: .*/', 'Requires PHP: ' . $wl_php, $header );
                            } else {
                                $anchor = ( ! empty( $wl_wp ) ) ? 'Requires at least: ' . $wl_wp : 'Version: ' . $wl_version;
                                $header = str_replace( $anchor, $anchor . "\n * Requires PHP: " . $wl_php, $header );
                            }
                        }
                        $main_content = $header . $rest;
                    }
                    $zip->addFromString( $folder . '/' . $relative_path, $main_content );
                    continue;
                }

                // White-label README.txt
                if ( $relative_path === 'README.txt' ) {
                    $content = file_get_contents( $full_entry );
                    if ( ! empty( $wl_name ) ) $content = preg_replace( '/=== .* ===/', '=== ' . $wl_name . ' ===', $content, 1 );
                    $content = str_replace( 'Contributors: tanveeratlogicx', 'Contributors: CosmicTechSol', $content );
                    $content = preg_replace( '/Stable tag: .*/', 'Stable tag: ' . $wl_version, $content );
                    $content = preg_replace( '/6\. \*\*Domain Control Features\*\*.*?License management\n/s', '', $content );
                    $content = preg_replace( '/\* Added Domain Locked Configuration Generator.*?conditional submenu for Superadmin\n/s', '', $content );
                    $content = preg_replace( '/\* Major release with Domain Control features.*?OTP authentication for superadmin\n/s', '', $content );
                    $zip->addFromString( $folder . '/' . $relative_path, $content );
                    continue;
                }

                // White-label USER_GUIDE.md
                if ( $relative_path === 'USER_GUIDE.md' ) {
                    $content = file_get_contents( $full_entry );
                    if ( ! empty( $wl_name ) ) $content = preg_replace( '/^# .*/m', '# ' . $wl_name . ' - User Guide', $content, 1 );
                    $zip->addFromString( $folder . '/' . $relative_path, $content );
                    continue;
                }

                $zip->addFile( $full_entry, $folder . '/' . $relative_path );

            } elseif ( is_dir( $full_entry ) ) {
                // Directory entry — recurse
                $dir_files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $full_entry, RecursiveDirectoryIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $dir_files as $dir_file ) {
                    if ( ! $dir_file->isFile() ) continue;
                    $rel = $entry . '/' . str_replace( '\\', '/', substr( $dir_file->getPathname(), strlen( $full_entry ) + 1 ) );
                    if ( strpos( $rel, '-locked-config.php' ) !== false ) continue;
                    $zip->addFile( $dir_file->getRealPath(), $folder . '/' . $rel );
                }
            }
        }

        $zip->close();

        // 3. Return Base64
        if ( ! file_exists( $zip_file ) ) {
            wp_send_json_error( [ 'message' => __( 'Zip generation failed — temp file not found.', 'vapt-security' ) ] );
        }

        $data = file_get_contents( $zip_file );
        unlink( $zip_file ); // clean up temp file — only once

        if ( $data === false || strlen( $data ) === 0 ) {
            wp_send_json_error( [ 'message' => __( 'Zip generation failed — could not read temp file.', 'vapt-security' ) ] );
        }

        // Sanitize domain for filename (replace dots with hyphens)
        $filename_domain  = str_replace( '.', '-', $safe_domain );
        $filename_slug    = ! empty( $wl_slug ) ? $wl_slug : 'security';

        // Smart Version Handling for Filename (Avoid vv1.0.0)
        $clean_version    = ltrim( $wl_version, 'vV' );
        $filename_version = 'v' . $clean_version;

        $filename = "vapt-{$filename_slug}-{$filename_domain}-{$filename_version}.zip";

        // Save a copy to the server for history
        $server_zip    = plugin_dir_path( __FILE__ ) . 'releases/builds/' . $filename;
        $file_existed  = file_exists( $server_zip );

        // If caller explicitly confirmed overwrite, proceed. Otherwise flag it.
        $confirmed_overwrite = ! empty( $_POST['confirm_overwrite'] );
        if ( $file_existed && ! $confirmed_overwrite ) {
            wp_send_json_success( [
                'needs_confirm' => true,
                'filename'      => $filename,
                'message'       => sprintf(
                    /* translators: %s: filename */
                    __( 'A build named <strong>%s</strong> already exists. Overwrite it or save as a new file?', 'vapt-security' ),
                    esc_html( $filename )
                ),
            ] );
        }

        // If user chose "Save as new", append a timestamp suffix
        if ( ! empty( $_POST['save_as_new'] ) ) {
            $filename = str_replace( '.zip', '-' . date( 'His' ) . '.zip', $filename );
            $server_zip = plugin_dir_path( __FILE__ ) . 'releases/builds/' . $filename;
        }

        $bytes_written = file_put_contents( $server_zip, $data );

        if ( $bytes_written === false ) {
            error_log( 'VAPT Build Generator: failed to write server copy to ' . $server_zip );
        }

        // Log to history
        $payload['filename'] = $filename;
        $this->add_build_to_history( $payload, 'zip', $build_id );

        $server_msg = ( $bytes_written !== false )
            ? __( 'Build saved successfully.', 'vapt-security' )
            : __( 'Build generated but could not be saved to server. Check folder permissions on releases/builds/.', 'vapt-security' );

        wp_send_json_success([
            'message'  => $server_msg,
            'filename' => $filename,
        ]);
    }

    /**
     * Add build record to history
     */
    private function add_build_to_history( $payload, $type, $edit_id = '' ) {
        $history = get_option( 'vapt_build_history', [] );
        
        $build_id = !empty($edit_id) ? $edit_id : 'B' . date('ymd') . '-' . substr( md5( microtime() ), 0, 4 );
        
        $entry = [
            'id'          => $build_id,
            'type'        => $type,
            'status'      => 'active',
            'domain'      => $payload['domain_pattern'],
            'domain_type' => $payload['domain_type'] ?? 'standard',
            'tracking_mode' => $payload['tracking_mode'] ?? 'production',
            'integrity_url' => $payload['integrity_url'] ?? '',
            'name'        => $payload['white_label']['name'] ?: 'VAPT Security',
            'version'     => $payload['white_label']['version'],
            'license'     => $payload['license']['type'],
            'expires'     => $payload['license']['expires'] ?? 0,
            'filename'    => $payload['filename'] ?? '',
            'white_label' => $payload['white_label'], // Store full WL for editing
            'callback_test' => ! empty( $payload['callback_test'] ),
            'auto_renew'  => ! empty( $payload['license']['auto_renew'] ),
            'renewal_count' => ! empty( $payload['license']['renewal_count'] ) ? (int) $payload['license']['renewal_count'] : 0,
            'time'        => time()
        ];

        if ( !empty($edit_id) ) {
            $updated = false;
            foreach ( $history as &$b ) {
                if ( $b['id'] === $edit_id ) {
                    $b = $entry;
                    $updated = true;
                    break;
                }
            }
            if ( !$updated ) {
                $history[] = $entry;
            }
        } else {
            $history[] = $entry;
        }
        
        // Keep only last 50 builds
        if ( count( $history ) > 50 ) {
            $history = array_slice( $history, -50 );
        }
        
        update_option( 'vapt_build_history', $history );
    }

    /**
     * Toggle build status (Suspend/Resume)
     */
    public function handle_toggle_build_status() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        $user = wp_get_current_user();
        if ( ! $user->exists() || $user->user_login !== 'tanmalik786' ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( $_POST['id'] ?? '' );
        if ( empty( $build_id ) ) {
            wp_send_json_error( [ 'message' => 'ID required' ] );
        }

        $history = get_option( 'vapt_build_history', [] );
        $new_status = 'active';
        foreach ( $history as &$b ) {
            if ( $b['id'] === $build_id ) {
                $b['status'] = ( empty($b['status']) || $b['status'] === 'active' ) ? 'suspended' : 'active';
                $new_status = $b['status'];
                break;
            }
        }
        
        update_option( 'vapt_build_history', $history );
        wp_send_json_success( [ 
            'message' => ($new_status === 'suspended') ? 'Build suspended' : 'Build resumed',
            'status'  => $new_status
        ] );
    }

    /**
     * Delete build from history
     */
    public function handle_delete_build() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $build_id = sanitize_text_field( $_POST['id'] ?? '' );
        if ( empty( $build_id ) ) {
            wp_send_json_error( [ 'message' => 'ID required' ] );
        }

        $history = get_option( 'vapt_build_history', [] );
        $deleted_file = false;

        foreach ( $history as $k => $b ) {
            if ( $b['id'] === $build_id ) {
                // Delete physical file
                $filename = !empty($b['filename']) ? $b['filename'] : '';
                if ( empty($filename) ) {
                    $domain_pattern = $b['domain'] ?? '';
                    $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain_pattern );
                    $safe_domain = trim( $safe_domain, '-' );
                    $filename = ($b['type'] === 'zip') ? "vapt-security-{$safe_domain}.zip" : "vapt-{$safe_domain}-locked-config.php";
                }

                $sub_dir = ($b['type'] === 'zip') ? 'releases/builds/' : 'releases/configurations/';
                $file_path = plugin_dir_path( __FILE__ ) . $sub_dir . $filename;

                if ( file_exists( $file_path ) ) {
                    @unlink( $file_path );
                    $deleted_file = true;
                }

                unset( $history[$k] );
                break;
            }
        }
        
        update_option( 'vapt_build_history', array_values($history) );
        $message = $deleted_file ? 'Build record and file deleted.' : 'Build record deleted (file not found).';
        wp_send_json_success( [ 'message' => $message ] );
    }

    /**
     * Repair/Recreate a broken build record
     */
    public function handle_repair_build() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );

        $build_id = sanitize_text_field( $_POST['id'] ?? '' );
        $history = get_option( 'vapt_build_history', [] );
        $record = null;

        foreach ( $history as $b ) {
            if ( $b['id'] === $build_id ) {
                $record = $b;
                break;
            }
        }

        if ( ! $record ) wp_send_json_error( [ 'message' => 'Build record not found.' ] );

        // Simulate POST data for generation handlers
        $_POST['domain'] = $record['domain'];
        $_POST['domain_type'] = $record['domain_type'] ?? 'standard';
        $_POST['license_type'] = $record['license'];
        $_POST['edit_id'] = $record['id'];
        $_POST['include_settings'] = 1;
        $_POST['include_callback_test'] = ! empty( $record['callback_test'] ) ? 1 : 0;
        $_POST['tracking_mode'] = $record['tracking_mode'] ?? 'production';
        $_POST['custom_url'] = $record['integrity_url'] ?? '';
        $_POST['auto_renew'] = ! empty( $record['license']['auto_renew'] ) ? 1 : 0;
        
        $_POST['wl_name'] = $record['white_label']['name'] ?? '';
        $_POST['wl_slug'] = $record['white_label']['slug'] ?? '';
        $_POST['wl_description'] = $record['white_label']['description'] ?? '';
        $_POST['wl_author'] = $record['white_label']['author'] ?? '';
        $_POST['wl_company'] = $record['white_label']['company'] ?? '';
        $_POST['wl_version'] = $record['version'];
        $_POST['wl_wp_version'] = $record['white_label']['requires_at_least'] ?? '5.6';
        $_POST['wl_php_version'] = $record['white_label']['requires_php'] ?? '8.0';

        if ( $record['type'] === 'zip' ) {
            $this->handle_generate_client_zip();
        } else {
            $this->handle_generate_locked_config();
        }
    }

}

VAPT_Security::instance();
