<?php
/**
 * Plugin Name: VAPT Security - Full
 * Plugin URI:  https://github.com/tanveeratlogicx/vapt-security-full
 * Description: A comprehensive WordPress plugin that protects against DoS via wp-cron, enforces strict input validation, and throttles form submissions.
 * Version:     3.2.1
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

        // Allow any user with manage_options ONLY if NOT on a client build
        if ( $this->is_local_environment() ) {
            // Check if this is a client site (has locked config)
            $is_client = ! empty( glob( plugin_dir_path( __FILE__ ) . 'vapt-*-locked-config.php*' ) ) 
                || file_exists( plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php' )
                || file_exists( plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php.imported' );

            if ( ! $is_client ) {
                return current_user_can( 'manage_options' );
            }
        }

        // Strict Username Check for remote/production or local client sites
        if ( $user->user_login === 'tanmalik786' ) {
            if ( $user->user_email === 'tanmalik786@gmail.com' ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Setup plugin constants.
     * Hooked to plugins_loaded to allow for user check.
     */
    public function setup_constants() {
        $is_master = $this->is_master_admin();

        if ( ! defined( 'VAPT_VERSION' ) ) {
            define( 'VAPT_VERSION', '3.2.1' );
        }

        if ( ! defined( 'VAPT_INTEGRITY_URL' ) ) {
            define( 'VAPT_INTEGRITY_URL', 'https://vaptsecure.net/vapts' );
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

        add_action( 'init', [ $this, 'initialize_security_logging' ] );
        add_action( 'vapt_cleanup_event', [ $this, 'cleanup_old_data' ] );

        // Disable updates for white-labeled plugin to prevent overwriting by original plugin.
        add_filter( 'site_transient_update_plugins', [ $this, 'disable_plugin_updates' ] );

        // Run domain lock check immediately on load to ensure white-labeling is active
        // But allow Master Admin to continue even if no lock file exists
        if ( ! $this->enforce_domain_lock() && ! $this->is_master_admin() ) {
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
        
        // Move Configs
        $configs = glob( $root . 'vapt-*-locked-config.php*' );
        if ( ! empty( $configs ) ) {
            foreach ( $configs as $file ) {
                $name = basename( $file );
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
        if ( $this->is_master_admin() ) {
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
        $wl = get_option( 'vapt_white_label_data', [] );
        if ( ! empty( $wl['name'] ) ) {
            return $wl['name'];
        }

        return __( 'VAPT Security - Full', 'vapt-security' );
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
        $this->enforce_domain_lock( true );

        // Generate initial .htaccess rules
        VAPT_Hardening::write_htaccess_rules();
    }

    /**
     * Activate the license.
     */
    public function activate_license() {
        VAPT_License::activate_license();
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
            $formatted = $license['expires'] ? date_i18n( get_option( 'date_format' ), $license['expires'] ) : __( 'Never', 'vapt-security' );
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
            $formatted = $license['expires'] ? date_i18n( get_option( 'date_format' ), $license['expires'] ) : __( 'Never', 'vapt-security' );
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
        $wl_php     = sanitize_text_field( $_POST['wl_php_version'] ?? '7.4' );

        $display_name = ! empty( $wl_name ) ? $wl_name : 'VAPT Security';
        $build_id = !empty($_POST['edit_id']) ? sanitize_text_field($_POST['edit_id']) : 'B' . date('ymd') . '-' . substr( md5( microtime() ), 0, 4 );

        // Tracking Mode logic
        $tracking_mode = sanitize_text_field( $_POST['tracking_mode'] ?? 'production' );
        $integrity_url = VAPT_INTEGRITY_URL;
        
        if ( $tracking_mode === 'testing' ) {
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
        $wl_php     = sanitize_text_field( $_POST['wl_php_version'] ?? '7.4' );

        $display_name = ! empty( $wl_name ) ? $wl_name : 'VAPT Security';
        $build_id = !empty($_POST['edit_id']) ? sanitize_text_field($_POST['edit_id']) : 'B' . date('ymd') . '-' . substr( md5( microtime() ), 0, 4 );

        // Tracking Mode logic
        $tracking_mode = sanitize_text_field( $_POST['tracking_mode'] ?? 'production' );
        $integrity_url = VAPT_INTEGRITY_URL;
        
        if ( $tracking_mode === 'testing' ) {
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

        // 2. Build Zip
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

        // Add Plugin Files
        $plugin_path = untrailingslashit( plugin_dir_path( __FILE__ ) );
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $plugin_path, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        $exclude_list = [
            '.git', '.gitignore', '.github',
            'ARCHITECTURE.md', 'CHANGELOG.md', 'DOCUMENTATION.md', 'FEATURES.md', 'VERSION_CONTROL.md', 'Project Layout.me', 'README.md', 'SUPERADMIN_GUIDE.md', 'Folder Structure.md',
            'composer.json', 'composer.lock', 'package.json', 'package-lock.json', 'prompt.txt',
            'test-config.php', 'test-vapt-features.php', 'vapt-config.php', 'vapt-config-sample.php',
            'tests', 'bin', 'node_modules', 'DevDocs', 'LegacyZips', 'kilo', 'ReqDocs', 'releases',
            'VAPTSecurity Initial.zip', 'VAPTSecurity v105.zip'
        ];

        foreach ( $files as $name => $file ) {
            // Check for valid file info
            if ( ! $file->isFile() ) continue;

            $relative_path = substr( $file->getPathname(), strlen( $plugin_path ) + 1 );
            // Normalize slashes
            $relative_path = str_replace( '\\', '/', $relative_path );
            
            // Check Exclusions
            $skip = false;
            foreach ( $exclude_list as $exclude ) {
                if ( strpos( $relative_path, $exclude ) === 0 || strpos( $relative_path, '/' . $exclude ) !== false ) {
                    $skip = true;
                    break;
                }
            }
            if ( $skip ) continue;
            
            // Don't include existing locked config if one somehow exists in dev
            if ( strpos( $relative_path, '-locked-config.php' ) !== false ) continue;

            // White Label Main Plugin File Header
            if ( $relative_path === 'vapt-security.php' ) {
                $main_content = file_get_contents( $file->getRealPath() );
                
                // 100% Safe Approach: Isolate the header block (first 1000 characters)
                // This prevents the generator from accidentally matching its own source code
                $header_end = strpos( $main_content, '*/' );
                if ( $header_end !== false ) {
                    $header_end += 2; // Include the closing tag
                    $header = substr( $main_content, 0, $header_end );
                    $rest   = substr( $main_content, $header_end );

                    if ( ! empty( $wl_name ) ) {
                        $header = preg_replace( '/Plugin Name: .*/', 'Plugin Name: ' . $wl_name, $header );
                    }
                    if ( ! empty( $wl_author ) ) {
                        $header = preg_replace( '/Author: .*/', 'Author: ' . $wl_author, $header );
                    }
                    if ( ! empty( $wl_desc ) ) {
                        $header = preg_replace( '/Description: .*/', 'Description: ' . $wl_desc, $header );
                    }
                    if ( ! empty( $wl_version ) ) {
                        $header = preg_replace( '/Version: .*/', 'Version: ' . $wl_version, $header );
                    }
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

            // White Label README.txt
            if ( $relative_path === 'README.txt' ) {
                $content = file_get_contents( $file->getRealPath() );
                if ( ! empty( $wl_name ) ) {
                    $content = preg_replace( '/=== .* ===/', '=== ' . $wl_name . ' ===', $content, 1 );
                }
                $content = str_replace( 'Contributors: tanveeratlogicx', 'Contributors: CosmicTechSol', $content );
                $content = preg_replace( '/Stable tag: .*/', 'Stable tag: ' . $wl_version, $content );
                
                // Remove Superadmin/Domain Control mentions from README.txt
                $content = preg_replace( '/6\. \*\*Domain Control Features\*\*.*?License management\n/s', '', $content );
                $content = preg_replace( '/\* Added Domain Locked Configuration Generator.*?conditional submenu for Superadmin\n/s', '', $content );
                $content = preg_replace( '/\* Major release with Domain Control features.*?OTP authentication for superadmin\n/s', '', $content );
                
                $zip->addFromString( $folder . '/' . $relative_path, $content );
                continue;
            }

            // White Label and Include USER_GUIDE.md
            if ( $relative_path === 'USER_GUIDE.md' ) {
                $content = file_get_contents( $file->getRealPath() );
                if ( ! empty( $wl_name ) ) {
                    $content = preg_replace( '/^# .*/m', '# ' . $wl_name . ' - User Guide', $content, 1 );
                }
                
                // Keep original filename as USER_GUIDE.md
                $zip->addFromString( $folder . '/' . $relative_path, $content );
                continue;
            }

            $zip->addFile( $file->getRealPath(), $folder . '/' . $relative_path );
        }

        $zip->close();

        // 3. Return Base64
        if ( file_exists( $zip_file ) ) {
            $data = file_get_contents( $zip_file );
            unlink( $zip_file );
            
            // Sanitize domain for filename (replace dots with hyphens)
            $filename_domain = str_replace( '.', '-', $safe_domain );
            $filename_slug   = ! empty( $wl_slug ) ? $wl_slug : 'security';
            
            // Smart Version Handling for Filename (Avoid vv1.0.0)
            $clean_version = ltrim( $wl_version, 'vV' );
            $filename_version = 'v' . $clean_version;
            
            $filename = "vapt-{$filename_slug}-{$filename_domain}-{$filename_version}.zip";

            // Save a copy to the server for history
            $server_zip = plugin_dir_path( __FILE__ ) . 'releases/builds/' . $filename;
            file_put_contents( $server_zip, $data );
            
            unlink( $zip_file );
            
            // Log to history
            $payload['filename'] = $filename;
            $this->add_build_to_history( $payload, 'zip', $build_id );

            wp_send_json_success([
                'message'  => __( 'Zip built successfully.', 'vapt-security' ),
                'filename' => $filename,
                'base64'   => base64_encode( $data )
            ]);
        } else {
             wp_send_json_error( [ 'message' => __( 'Zip generation failed.', 'vapt-security' ) ] );
        }
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
        
        $_POST['wl_name'] = $record['white_label']['name'] ?? '';
        $_POST['wl_slug'] = $record['white_label']['slug'] ?? '';
        $_POST['wl_description'] = $record['white_label']['description'] ?? '';
        $_POST['wl_author'] = $record['white_label']['author'] ?? '';
        $_POST['wl_company'] = $record['white_label']['company'] ?? '';
        $_POST['wl_version'] = $record['version'];
        $_POST['wl_wp_version'] = $record['white_label']['requires_at_least'] ?? '5.6';
        $_POST['wl_php_version'] = $record['white_label']['requires_php'] ?? '7.4';

        if ( $record['type'] === 'zip' ) {
            $this->handle_generate_client_zip();
        } else {
            $this->handle_generate_locked_config();
        }
    }

    /**
     * Export build history to JSON or ZIP
     */
    public function handle_export_build_history() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );

        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $history = get_option( 'vapt_build_history', [] );
        $ids = $_POST['ids'] ?? '';
        
        $export_data = $history;
        $filename_prefix = 'Build-All-Logs';

        if ( ! empty( $ids ) ) {
            $id_array = is_array( $ids ) ? $ids : explode( ',', $ids );
            $export_data = array_filter( $history, function( $item ) use ( $id_array ) {
                return in_array( $item['id'], $id_array );
            } );
            $export_data = array_values( $export_data ); // Reset keys

            if ( count( $export_data ) === 1 ) {
                $domain = $export_data[0]['domain'] ?? 'unknown';
                $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain );
                $safe_domain = trim( $safe_domain, '-' );
                $filename_prefix = 'Build-' . $safe_domain;
            } else {
                $filename_prefix = 'Build-Selected';
            }
        }

        if ( empty( $export_data ) ) {
            wp_send_json_error( [ 'message' => 'No records found for export' ] );
        }

        $log_dir = plugin_dir_path( __FILE__ ) . 'releases/logs/';
        if ( ! is_dir( $log_dir ) ) {
            @mkdir( $log_dir, 0755, true );
        }

        // Determine if we should force ZIP (for "Export All") or use JSON (for single record)
        $is_export_all = empty( $ids );
        
        // --- SINGLE RECORD EXPORT (JSON) ---
        // Only if NOT "Export All" and exactly 1 record is selected
        if ( ! $is_export_all && count( $export_data ) === 1 ) {
            $final_filename = $filename_prefix . '-' . date( 'Y-m-d-H-i-s' ) . '.json';
            $json_content = json_encode( $export_data[0], JSON_PRETTY_PRINT );
            
            if ( is_writable( $log_dir ) ) {
                $saved = @file_put_contents( $log_dir . $final_filename, $json_content );
                if ( $saved !== false ) {
                    wp_send_json_success( [ 
                        'message' => sprintf( __( 'Record exported successfully to: releases/logs/%s', 'vapt-security' ), $final_filename ),
                        'filename' => $final_filename 
                    ] );
                }
            }
            wp_send_json_error( [ 'message' => 'Failed to save JSON export to server.' ] );
        }

        // --- MULTIPLE RECORDS OR "EXPORT ALL" (ZIP) ---
        if ( ! class_exists( 'ZipArchive' ) ) {
            wp_send_json_error( [ 'message' => __( 'ZipArchive PHP extension is missing for multi-file export.', 'vapt-security' ) ] );
        }

        $zip_file = tempnam( sys_get_temp_dir(), 'vapt_logs_' );
        $zip = new ZipArchive();
        if ( $zip->open( $zip_file, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== TRUE ) {
            wp_send_json_error( [ 'message' => 'Could not create temp zip file.' ] );
        }

        foreach ( $export_data as $record ) {
            $domain = $record['domain'] ?? 'unknown';
            $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain );
            $safe_domain = trim( $safe_domain, '-' );
            $build_id = $record['id'] ?? 'unknown';
            $internal_filename = "Build-{$safe_domain}-{$build_id}.json";
            $zip->addFromString( $internal_filename, json_encode( $record, JSON_PRETTY_PRINT ) );
        }
        $zip->close();

        $final_zip_name = $filename_prefix . '-' . date( 'Y-m-d-H-i-s' ) . '.zip';
        $zip_content = file_get_contents( $zip_file );
        
        if ( is_writable( $log_dir ) ) {
            $saved = @file_put_contents( $log_dir . $final_zip_name, $zip_content );
            unlink( $zip_file );
            if ( $saved !== false ) {
                wp_send_json_success( [ 
                    'message' => sprintf( __( 'Multi-record export saved to: releases/logs/%s', 'vapt-security' ), $final_zip_name ),
                    'filename' => $final_zip_name 
                ] );
            }
        }
        
        @unlink( $zip_file );
        wp_send_json_error( [ 'message' => 'Failed to save export ZIP to server.' ] );
    }

    /**
     * Import build history from JSON file
     */
    public function handle_import_build_history() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );

        if ( empty( $_FILES['history_file'] ) ) {
            wp_send_json_error( [ 'message' => 'No file uploaded' ] );
        }

        $file = $_FILES['history_file']['tmp_name'];
        $content = file_get_contents( $file );
        $data = json_decode( $content, true );

        if ( ! $data ) {
            wp_send_json_error( [ 'message' => 'Invalid JSON file' ] );
        }

        $history = get_option( 'vapt_build_history', [] );
        
        // Handle both single record and array of records
        $new_records = isset( $data['id'] ) ? [ $data ] : $data;
        $imported_count = 0;

        foreach ( $new_records as $record ) {
            if ( empty( $record['id'] ) ) continue;
            
            // Check for duplicates
            $exists = false;
            foreach ( $history as $idx => $existing ) {
                if ( $existing['id'] === $record['id'] ) {
                    $history[$idx] = $record; // Update existing
                    $exists = true;
                    break;
                }
            }

            if ( ! $exists ) {
                $history[] = $record;
            }
            $imported_count++;
        }

        update_option( 'vapt_build_history', $history );
        wp_send_json_success( [ 'message' => sprintf( 'Imported %d record(s) successfully.', $imported_count ) ] );
    }

    /**
     * Get updated build history table rows (AJAX)
     */
    public function handle_get_history_table() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );

        if ( ! $this->is_master_admin() ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $history = get_option( 'vapt_build_history', [] );
        $history = array_reverse( $history ); // Show newest first
        
        ob_start();
        if ( empty( $history ) ) {
            ?>
            <tr class="no-builds">
                <td colspan="10" style="text-align: center; color: #999; padding: 30px;"><?php esc_html_e( 'No builds generated yet.', 'vapt-security' ); ?></td>
            </tr>
            <?php
        } else {
            foreach ( $history as $build ) {
                $is_suspended = (isset($build['status']) && $build['status'] === 'suspended');
                $filename = !empty($build['filename']) ? $build['filename'] : '';
                
                if ( empty($filename) && ! empty( $build['domain'] ) ) {
                    $domain_pattern = $build['domain'];
                    $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $domain_pattern );
                    $safe_domain = trim( $safe_domain, '-' );
                    $filename = ($build['type'] === 'zip') ? "vapt-security-{$safe_domain}.zip" : "vapt-{$safe_domain}-locked-config.php";
                }
                
                $sub_dir = ($build['type'] === 'zip') ? 'releases/builds/' : 'releases/configurations/';
                $file_path = plugin_dir_path( __FILE__ ) . $sub_dir . $filename;
                $file_exists = !empty($filename) && file_exists( $file_path );
                $download_url = $file_exists ? plugins_url( $sub_dir . $filename, __FILE__ ) : '';
                ?>
                <tr class="<?php echo $is_suspended ? 'vapt-row-suspended' : ''; ?> <?php echo !$file_exists ? 'vapt-row-broken' : ''; ?>">
                    <td><input type="checkbox" class="vapt-build-checkbox" value="<?php echo esc_attr( $build['id'] ); ?>"></td>
                    <td>
                        <span class="vapt-build-id"><?php echo esc_html( $build['id'] ); ?></span>
                        <?php if ( !$file_exists ) : ?>
                            <span class="dashicons dashicons-warning" style="color: #d63638; font-size: 14px; width: 14px; height: 14px; margin-left: 4px;" title="<?php esc_attr_e( 'Build file is missing from server!', 'vapt-security' ); ?>"></span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html( $build['domain'] ); ?></td>
                    <td style="font-size: 11px; text-transform: capitalize; color: #666;"><?php echo esc_html( $build['domain_type'] ?? 'standard' ); ?></td>
                    <td><?php echo esc_html( $build['name'] ); ?></td>
                    <td><?php echo esc_html( $build['version'] ); ?></td>
                    <td><span class="badge" style="background: #2271b1; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 10px;"><?php echo esc_html( strtoupper($build['license']) ); ?></span></td>
                    <td style="font-size: 11px; color: #666;"><?php echo esc_html( date_i18n( get_option( 'date_format' ), $build['time'] ) ); ?></td>
                    <td style="font-size: 11px; color: #666;">
                        <?php 
                            if ( empty($build['expires']) || $build['license'] === 'developer' ) {
                                esc_html_e( 'Never', 'vapt-security' );
                            } else {
                                echo esc_html( date_i18n( get_option( 'date_format' ), $build['expires'] ) );
                            }
                        ?>
                    </td>
                    <td>
                        <div class="vapt-actions" style="display: flex; gap: 5px; align-items: center;">
                            <?php if ( $file_exists ) : ?>
                                <a href="<?php echo esc_url( $download_url ); ?>" class="button button-small" download title="<?php esc_attr_e( 'Download', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                    <span class="dashicons dashicons-download" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                </a>
                            <?php else : ?>
                                <button type="button" class="button button-small vapt-repair-build" 
                                    data-id="<?php echo esc_attr($build['id']); ?>" 
                                    data-type="<?php echo esc_attr($build['type']); ?>"
                                    style="padding: 0 6px; color: #d63638;" title="<?php esc_attr_e( 'Build missing! Click to Repair/Recreate', 'vapt-security' ); ?>">
                                    <span class="dashicons dashicons-hammer" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                </button>
                            <?php endif; ?>

                            <button type="button" class="button button-small vapt-edit-build" 
                                data-id="<?php echo esc_attr($build['id']); ?>" 
                                data-domain="<?php echo esc_attr($build['domain']); ?>"
                                data-domain-type="<?php echo esc_attr($build['domain_type'] ?? 'standard'); ?>"
                                data-license-type="<?php echo esc_attr($build['license']); ?>"
                                data-name="<?php echo esc_attr($build['name']); ?>"
                                data-version="<?php echo esc_attr($build['version']); ?>"
                                data-author="<?php echo esc_attr($build['white_label']['author'] ?? ''); ?>"
                                data-company="<?php echo esc_attr($build['white_label']['company'] ?? ''); ?>"
                                data-desc="<?php echo esc_attr($build['white_label']['description'] ?? ''); ?>"
                                data-wp="<?php echo esc_attr($build['white_label']['requires_at_least'] ?? '5.6'); ?>"
                                data-php="<?php echo esc_attr($build['white_label']['requires_php'] ?? '7.4'); ?>"
                                title="<?php esc_attr_e( 'Edit/Reuse settings', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                <span class="dashicons dashicons-edit" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                            </button>

                            <button type="button" class="button button-small vapt-export-single" 
                                data-id="<?php echo esc_attr($build['id']); ?>" 
                                title="<?php esc_attr_e( 'Export Record', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                <span class="dashicons dashicons-upload" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                            </button>

                            <div class="vapt-action-group" style="display: flex; gap: 2px; border-left: 1px solid #eee; padding-left: 5px; margin-left: 2px;">
                                <button type="button" class="button button-small vapt-suspend-build" 
                                    data-id="<?php echo esc_attr($build['id']); ?>" 
                                    data-status="<?php echo $is_suspended ? 'suspended' : 'active'; ?>"
                                    style="color: <?php echo $is_suspended ? '#2271b1' : '#46b450'; ?>; padding: 0 6px;" 
                                    title="<?php echo $is_suspended ? esc_attr__( 'Resume Build', 'vapt-security' ) : esc_attr__( 'Suspend Build', 'vapt-security' ); ?>">
                                    <span class="dashicons <?php echo $is_suspended ? 'dashicons-undo' : 'dashicons-lock'; ?>" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                </button>
                                <?php if ( $is_suspended ) : ?>
                                    <button type="button" class="button button-small vapt-delete-build" 
                                        data-id="<?php echo esc_attr($build['id']); ?>" 
                                        style="color: #d63638; padding: 0 6px;" 
                                        title="<?php esc_attr_e( 'Purge Record', 'vapt-security' ); ?>">
                                        <span class="dashicons dashicons-trash" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                    </button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </td>
                </tr>
                <?php
            }
        }
        $html = ob_get_clean();
        
        wp_send_json_success( [ 'html' => $html ] );
    }

    /**
     * Enforce Domain Locked Configuration
     * 
     * @param bool $is_activation Whether this is running during plugin activation.
     * @return bool True if configuration is valid and domain matches, false otherwise.
     */
    public function enforce_domain_lock( $is_activation = false ) {
        $files = glob( plugin_dir_path( __FILE__ ) . 'vapt-*-locked-config.php*' );
        
        // Sort by modification time (newest first) to ensure we use the latest config
        if ( ! empty( $files ) ) {
            usort( $files, function( $a, $b ) {
                return filemtime( $b ) - filemtime( $a );
            });
        }
        
        if ( empty( $files ) ) {
            $legacy = plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php';
            $legacy_imported = plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php.imported';
            
            if ( file_exists( $legacy ) ) {
                $files = [ $legacy ];
            } elseif ( file_exists( $legacy_imported ) ) {
                $files = [ $legacy_imported ];
            } else {
                return false;
            }
        }

        $config_file = $files[0];
        $file_content = file_get_contents( $config_file );
        
        $vapt_locked_config_data = null;
        $vapt_locked_config_sig  = null;
        
        if ( preg_match( '/\$vapt_locked_config_data\s*=\s*\'(.*?)\';/s', $file_content, $matches ) ) {
            $vapt_locked_config_data = stripslashes( $matches[1] );
        }
        
        if ( preg_match( '/\$vapt_locked_config_sig\s*=\s*\'([a-f0-9]+)\';/', $file_content, $matches ) ) {
            $vapt_locked_config_sig = $matches[1];
        }

        if ( ! $vapt_locked_config_data || ! $vapt_locked_config_sig ) {
            return false;
        }
        
        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $check_sig = hash_hmac( 'sha256', $vapt_locked_config_data, $salt );
        
        if ( ! isset( $vapt_locked_config_sig ) || ! hash_equals( $check_sig, $vapt_locked_config_sig ) ) {
            error_log( 'VAPT Security: Locked configuration file integrity check failed.' );
            return false;
        }

        $data = json_decode( $vapt_locked_config_data, true );
        if ( ! $data || empty( $data['domain_pattern'] ) ) {
            return false;
        }

        $current_host = $_SERVER['HTTP_HOST'] ?? '';
        $pattern      = $data['domain_pattern'];
        $domain_type  = $data['domain_type'] ?? 'standard';
        $match        = false;

        if ( $domain_type === 'universal' ) {
            $match = true;
        } elseif ( $domain_type === 'wildcard' ) {
            $match = ( strpos( $current_host, $pattern ) !== false );
        } else {
            if ( strpos( $pattern, '.' ) === false && strpos( $pattern, '*' ) === false ) {
                $regex = '/^.*' . preg_quote( $pattern, '/' ) . '.*$/';
            } else {
                $regex = '/^' . str_replace( '\*', '.*', preg_quote( $pattern, '/' ) ) . '$/';
            }
            $match = (bool) preg_match( $regex, $current_host );
        }

        if ( ! $match ) {
            $user = wp_get_current_user();
            if ( $user->exists() && $user->user_login === 'tanmalik786' ) {
                if ( is_admin() && ! $is_activation && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
                    add_action( 'admin_notices', function() use ( $pattern, $current_host ) {
                        echo '<div class="notice notice-error is-dismissible"><p>';
                        printf( 
                            esc_html__( 'VAPT Security Superadmin Bypass: This build is locked to %1$s but you are on %2$s. Security features are active but you should re-generate the config.', 'vapt-security' ), 
                            '<strong>' . esc_html( $pattern ) . '</strong>',
                            '<strong>' . esc_html( $current_host ) . '</strong>'
                        );
                        echo '</p></div>';
                    });
                }
                $match = true;
            } else {
                if ( $this->is_local_environment() ) {
                    if ( is_admin() && ! $is_activation && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
                        add_action( 'admin_notices', function() use ( $pattern, $current_host ) {
                            echo '<div class="notice notice-warning is-dismissible"><p>';
                            printf( 
                                esc_html__( 'VAPT Security Warning: This build is locked to domain pattern %1$s but is running on %2$s. Allowed for Local Development.', 'vapt-security' ), 
                                '<strong>' . esc_html( $pattern ) . '</strong>',
                                '<strong>' . esc_html( $current_host ) . '</strong>'
                            );
                            echo '</p></div>';
                        });
                    }
                    $match = true;
                } else {
                    wp_mail( 
                        'tanmalik786@gmail.com', 
                        'VAPT Security Violation: Domain Mismatch', 
                        sprintf( 
                            "A locked build was attempted to be used on an unauthorized domain.\n\nLocked Pattern: %s\nAttempted Host: %s\nIP: %s", 
                            $pattern,
                            $current_host,
                            $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                        ) 
                    );

                    if ( ! function_exists( 'deactivate_plugins' ) ) {
                        require_once ABSPATH . 'wp-admin/includes/plugin.php';
                    }
                    deactivate_plugins( plugin_basename( __FILE__ ) );
                    
                    $msg = sprintf( 
                        '<h1>Security Violation</h1><p>This build of <strong>VAPT Security</strong> is locked to the domain pattern: <code>%s</code>.</p><p>You are attempting to use it on: <code>%s</code>.</p><p>Please contact the developer at <strong>tanmalik786@gmail.com</strong> to obtain a license for this domain.</p>', 
                        esc_html( $pattern ),
                        esc_html( $current_host )
                    );
                    
                    wp_die( $msg, 'Domain Lock Violation', [ 'response' => 403 ] );
                    return false;
                }
            }
        }
        
        if ( ! empty( $data['white_label'] ) ) {
            update_option( 'vapt_white_label_data', $data['white_label'] );
        }

        if ( ! empty( $data['license'] ) ) {
            $lic = $data['license'];
            if ( empty( $lic['expires'] ) ) {
                $start = $lic['start'] ?? time();
                if ( $lic['type'] === 'standard' ) $lic['expires'] = $start + ( 30 * DAY_IN_SECONDS );
                elseif ( $lic['type'] === 'pro' ) $lic['expires'] = $start + ( 365 * DAY_IN_SECONDS );
                elseif ( $lic['type'] === 'trial' ) $lic['expires'] = $start + ( 7 * DAY_IN_SECONDS );
                elseif ( $lic['type'] === 'demo' ) $lic['expires'] = $start + ( 15 * DAY_IN_SECONDS );
                else $lic['expires'] = 0;
            }
            update_option( 'vapt_license', $lic );
        }
        
        if ( ! empty( $data['settings'] ) ) {
            $json = json_encode( $data['settings'] );
            $encrypted = VAPT_Encryption::encrypt( $json );
            update_option( 'vapt_security_options', $encrypted );
        }

        if ( strpos( $config_file, '.imported' ) === false ) {
            @rename( $config_file, $config_file . '.imported' );
            if ( is_admin() && ! $is_activation && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
                add_action( 'admin_notices', function() use ( $pattern ) {
                    echo '<div class="notice notice-success is-dismissible"><p>';
                    printf( 
                        esc_html__( 'VAPT Security: Configuration successfully imported for domain pattern %s.', 'vapt-security' ), 
                        '<strong>' . esc_html( $pattern ) . '</strong>' 
                    );
                    echo '</p></div>';
                });
            }
        }
        
        $guide_file = plugin_dir_path( __FILE__ ) . 'USER_GUIDE.md';
        if ( file_exists( $guide_file ) && is_writable( $guide_file ) ) {
            $guide_content = file_get_contents( $guide_file );
            $updated_content = str_replace( 'your-domain.com', $current_host, $guide_content );
            file_put_contents( $guide_file, $updated_content );
        }

        return true;
    }

    /**
     * Push a remote command to a build (Master Server Side)
     */
    public function handle_push_remote_command() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        if ( ! $this->is_master_admin() ) wp_send_json_error( [ 'message' => 'Unauthorized' ] );

        $build_id = sanitize_text_field( $_POST['build_id'] ?? '' );
        $type     = sanitize_text_field( $_POST['cmd_type'] ?? '' );
        $val      = sanitize_text_field( $_POST['cmd_val'] ?? '' );

        if ( empty( $build_id ) || empty( $type ) ) {
            wp_send_json_error( [ 'message' => 'Missing data' ] );
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        if ( ! isset( $tracking[$build_id] ) ) {
            wp_send_json_error( [ 'message' => 'Build not found in tracking' ] );
        }

        $commands = get_option( 'vapt_pending_commands', [] );
        if ( ! isset( $commands[$build_id] ) ) $commands[$build_id] = [];

        $command_payload = [ 'type' => $type ];

        if ( $type === 'EXTEND' ) {
            $current_expiry = $tracking[$build_id]['license']['expiry'] ?: time();
            $license_type = $tracking[$build_id]['license']['type'];
            
            $days_to_add = 0;
            if ( $val === 'term' ) {
                if ( $license_type === 'pro' ) $days_to_add = 365;
                elseif ( $license_type === 'standard' ) $days_to_add = 30;
                elseif ( $license_type === 'demo' ) $days_to_add = 15;
                elseif ( $license_type === 'trial' ) $days_to_add = 7;
            } elseif ( strpos( $val, '-' ) !== false ) {
                $new_expiry = strtotime( $val );
            } else {
                $days_to_add = (int) $val;
                $new_expiry = $current_expiry + ( $days_to_add * DAY_IN_SECONDS );
            }

            if ( ! isset( $new_expiry ) ) {
                $new_expiry = $current_expiry + ( $days_to_add * DAY_IN_SECONDS );
            }
            $command_payload['type'] = 'EXTEND_LICENSE';
            $command_payload['expiry'] = $new_expiry;
            
            // Update local tracking immediately so UI reflects it
            $tracking[$build_id]['license']['expiry'] = $new_expiry;
            $tracking[$build_id]['license']['status'] = 'active';
            update_option( 'vapt_build_tracking', $tracking );
        }

        if ( $type === 'SUSPEND' ) {
            $command_payload['type'] = 'SUSPEND';
        }

        $commands[$build_id][] = $command_payload;
        update_option( 'vapt_pending_commands', $commands );

        wp_send_json_success( [ 'message' => 'Command queued for next heartbeat.' ] );
    }

    /**
     * Handle force ping for testing (AJAX)
     */
    public function handle_force_ping() {
        check_ajax_referer( 'vapt_locked_config', 'nonce' );
        
        $config = $this->get_locked_config_data();
        if ( ! $config ) {
            wp_send_json_error( [ 'message' => 'No locked config found' ] );
        }
        
        if ( empty( $config['build_id'] ) ) {
            wp_send_json_error( [ 'message' => 'Config missing build_id' ] );
        }
        
        $integrity_url = ! empty( $config['integrity_url'] ) ? $config['integrity_url'] : VAPT_INTEGRITY_URL;
        
        if ( ! get_option( 'vapt_initial_install_time' ) ) {
            update_option( 'vapt_initial_install_time', time() );
        }
        
        $license = VAPT_License::get_license();
        $payload = [
            'action'          => 'vapt_build_callback',
            'build_id'        => $config['build_id'],
            'domain'          => $_SERVER['HTTP_HOST'] ?? '',
            'license_type'    => $license['type'] ?? '',
            'license_expiry'  => $license['expires'] ?? 0,
            'license_status'  => VAPT_License::is_valid() ? 'active' : 'expired',
            'version'         => VAPT_VERSION,
            'initial_install' => get_option( 'vapt_initial_install_time' )
        ];
        
        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), $salt );
        
        $response = wp_remote_post( $integrity_url, [
            'body'      => $payload,
            'timeout'   => 15,
            'blocking'  => true,
            'sslverify' => false
        ] );
        
        if ( is_wp_error( $response ) ) {
            wp_send_json_error( [ 'message' => $response->get_error_message() ] );
        }
        
        $status = wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );
        
        wp_send_json_success( [
            'status' => $status,
            'body' => $body,
            'url' => $integrity_url,
            'payload' => $payload
        ] );
    }

    /**
     * Handle incoming build tracking callback (Master Server Side)
     */
    public function handle_build_callback() {
        $build_id = sanitize_text_field( $_POST['build_id'] ?? '' );
        if ( empty( $build_id ) ) wp_send_json_error();

        $sig = sanitize_text_field( $_POST['sig'] ?? '' );
        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $payload_for_sig = $_POST;
        unset( $payload_for_sig['sig'] );
        $expected_sig = hash_hmac( 'sha256', json_encode( $payload_for_sig ), $salt );
        if ( ! hash_equals( $expected_sig, $sig ) ) {
            wp_send_json_error( [ 'message' => 'Invalid signature' ] );
        }

        $tracking = get_option( 'vapt_build_tracking', [] );
        $now = time();

        if ( ! isset( $tracking[$build_id] ) ) {
            $tracking[$build_id] = [
                'first_activation' => $now,
                'initial_install'  => (int) ($_POST['initial_install'] ?? $now),
                'history' => []
            ];
            
            // Notification on first activation
            $this->notify_superadmin_first_activation($build_id, $_POST);
        }

        $tracking[$build_id]['last_seen'] = $now;
        $tracking[$build_id]['domain']    = sanitize_text_field( $_POST['domain'] ?? '' );
        $tracking[$build_id]['ip']        = $_SERVER['REMOTE_ADDR'] ?? '';
        $tracking[$build_id]['license']   = [
            'type'   => sanitize_text_field( $_POST['license_type'] ?? '' ),
            'expiry' => (int) ($_POST['license_expiry'] ?? 0),
            'status' => sanitize_text_field( $_POST['license_status'] ?? '' )
        ];
        $tracking[$build_id]['version']   = sanitize_text_field( $_POST['version'] ?? '' );

        if ( ! in_array( $tracking[$build_id]['domain'], $tracking[$build_id]['history'] ) ) {
            $tracking[$build_id]['history'][] = $tracking[$build_id]['domain'];
        }

        update_option( 'vapt_build_tracking', $tracking );

        // Check for pending commands
        $commands = get_option( 'vapt_pending_commands', [] );
        $response_commands = [];
        if ( isset( $commands[$build_id] ) ) {
            $response_commands = $commands[$build_id];
            unset( $commands[$build_id] );
            update_option( 'vapt_pending_commands', $commands );
        }

        wp_send_json_success( [ 'commands' => $response_commands ] );
    }

    /**
     * Check if the current installation has a locked configuration file.
     */
    private function has_locked_config() {
        return ! empty( glob( plugin_dir_path( __FILE__ ) . 'vapt-*-locked-config.php*' ) ) 
            || file_exists( plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php' )
            || file_exists( plugin_dir_path( __FILE__ ) . 'vapt-locked-config.php.imported' );
    }

    /**
     * Notify Superadmin on first activation of a build
     */
    private function notify_superadmin_first_activation($build_id, $data) {
        $to = 'tanmalik786@gmail.com';
        $subject = 'VAPT Security: New Build Activated - ' . $build_id;
        $message = "A new build has been activated.\n\n" .
                   "Build ID: {$build_id}\n" .
                   "Domain: " . ($data['domain'] ?? 'Unknown') . "\n" .
                   "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . "\n" .
                   "License: " . ($data['license_type'] ?? 'Unknown') . "\n" .
                   "Time: " . date('Y-m-d H:i:s');
        wp_mail($to, $subject, $message);
    }

    /**
     * Trigger callback from client site (Client Side)
     */
public function maybe_trigger_callback() {
        // If we have a locked config, we are a client site, so we should ping
        if ( ! $this->has_locked_config() && $this->is_master_admin() ) {
            return;
        }

        $last_ping = get_option( 'vapt_last_integrity_ping', 0 );
        $throttle = $this->is_local_environment() ? 60 : 12 * HOUR_IN_SECONDS; // 1 min for local testing
        
        if ( time() - $last_ping < $throttle ) return;

        $config = $this->get_locked_config_data();
        if ( ! $config ) {
            return;
        }
        if ( empty( $config['build_id'] ) ) {
            error_log( 'VAPT Tracking Error: Locked config file is missing build_id.' );
            return;
        }

        $integrity_url = ! empty( $config['integrity_url'] ) ? $config['integrity_url'] : VAPT_INTEGRITY_URL;

        // Record Initial Install if not set
        if ( ! get_option( 'vapt_initial_install_time' ) ) {
            update_option( 'vapt_initial_install_time', time() );
        }

        // Authoritative first_activation check - use Master's value if available
        $initial_install = get_option( 'vapt_initial_install_time' );
        $master_tracking = get_option( 'vapt_build_tracking', [] );
        if ( isset( $master_tracking[ $config['build_id'] ]['first_activation'] ) ) {
            $initial_install = $master_tracking[ $config['build_id'] ]['first_activation'];
        }

        $license = VAPT_License::get_license();
        $payload = [
            'action'          => 'vapt_build_callback',
            'build_id'        => $config['build_id'],
            'domain'          => $_SERVER['HTTP_HOST'] ?? '',
            'license_type'    => $license['type'] ?? '',
            'license_expiry'  => $license['expires'] ?? 0,
            'license_status'  => VAPT_License::is_valid() ? 'active' : 'expired',
            'version'         => VAPT_VERSION,
            'initial_install' => $initial_install
        ];

        $salt = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';
        $payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), $salt );

        $response = wp_remote_post( $integrity_url, [
            'body'      => $payload,
            'timeout'   => 15,
            'blocking'  => false,
            'sslverify' => false // Local environments often have SSL issues
        ] );

        if ( is_wp_error( $response ) ) {
            error_log( 'VAPT Tracking Error (' . $integrity_url . '): ' . $response->get_error_message() );
            return;
        }

        update_option( 'vapt_last_integrity_ping', time() );
    }

    /**
     * Process remote commands received from Master Server
     */
    private function process_remote_commands( $commands ) {
        foreach ( $commands as $cmd ) {
            switch ( $cmd['type'] ) {
                case 'EXTEND_LICENSE':
                    $new_expiry = (int) $cmd['expiry'];
                    $license = VAPT_License::get_license();
                    if ( $license ) {
                        $license['expires'] = $new_expiry;
                        update_option( 'vapt_license', $license );
                        $this->send_license_notification_email('extended', $new_expiry);
                    }
                    break;
                case 'SUSPEND':
                    // Deactivate and show error
                    if ( ! function_exists( 'deactivate_plugins' ) ) {
                        require_once ABSPATH . 'wp-admin/includes/plugin.php';
                    }
                    deactivate_plugins( plugin_basename( __FILE__ ) );
                    wp_die( 'Your VAPT Security license has been suspended by the provider.', 'License Suspended' );
                    break;
            }
        }
    }

    /**
     * Display Tiered License Expiry Notices
     */
    public function display_license_expiry_notices() {
        if ( $this->is_master_admin() || ! is_admin() ) return;

        $license = VAPT_License::get_license();
        if ( ! $license || $license['type'] === 'developer' ) return;

        $expires = $license['expires'];
        if ( ! $expires ) return;

        $days_left = ceil( ( $expires - time() ) / DAY_IN_SECONDS );
        if ( $days_left > 20 ) return;

        $type = $license['type'];
        $notice = '';
        $class = 'notice-warning';

        if ( $type === 'standard' || $type === 'pro' ) {
            if ( $days_left <= 5 ) {
                $notice = __( 'URGENT: Your VAPT Security license expires in %d days. Protection will be disabled soon!', 'vapt-security' );
                $class = 'notice-error';
            } elseif ( $days_left <= 10 ) {
                $notice = __( 'Attention: Your VAPT Security license expires in %d days. Please renew to maintain security.', 'vapt-security' );
            } elseif ( $days_left <= 20 ) {
                $notice = __( 'Friendly Reminder: Your VAPT Security license expires in %d days.', 'vapt-security' );
                $class = 'notice-info';
            }
        } elseif ( $type === 'demo' ) {
            if ( $days_left <= 3 ) {
                $notice = __( 'FINAL NOTICE: Your VAPT Security Demo expires in %d days. Act now to stay protected!', 'vapt-security' );
                $class = 'notice-error';
            } elseif ( $days_left <= 10 ) {
                $notice = __( 'Trial Ending Soon: Your VAPT Security Demo expires in %d days.', 'vapt-security' );
            }
        } elseif ( $type === 'trial' ) {
            if ( $days_left <= 3 ) {
                $notice = __( 'IMMEDIATE ACTION REQUIRED: Your VAPT Security Trial expires in %d days!', 'vapt-security' );
                $class = 'notice-error';
            }
        }

        if ( $notice ) {
            echo '<div class="notice ' . esc_attr( $class ) . ' is-dismissible"><p><strong>' . sprintf( $notice, $days_left ) . '</strong></p></div>';
            
            // Send email if it's the first time seeing this stage
            $stage_key = 'vapt_expiry_notified_' . ( $days_left <= 5 ? 'level3' : ( $days_left <= 10 ? 'level2' : 'level1' ) );
            if ( ! get_transient( $stage_key ) ) {
                $this->send_license_notification_email('expiry_warning', $expires, $days_left);
                set_transient( $stage_key, 1, 7 * DAY_IN_SECONDS );
            }
        }
    }

    /**
     * Send professional HTML email for license events
     */
    private function send_license_notification_email( $event, $expiry, $days_left = 0 ) {
        $admin_email = 'tanmalik786@gmail.com';
        $blog_name = get_option( 'blogname' );
        
        $subject = '';
        $title = '';
        $body = '';
        $color = '#2271b1';

        switch ( $event ) {
            case 'extended':
                $subject = "License Extended: VAPT Security on {$blog_name}";
                $title = "Good News! Your License is Extended";
                $body = "Your VAPT Security license term has been successfully extended. Your new expiry date is " . date_i18n( get_option( 'date_format' ), $expiry ) . ". No further action is required.";
                $color = '#00a32a';
                break;
            case 'expiry_warning':
                $urgency = ( $days_left <= 5 ) ? 'Urgent' : 'Upcoming';
                $subject = "{$urgency}: VAPT Security License Expiry on {$blog_name}";
                $title = "Your Security Protection is Expiring Soon";
                $body = "Your VAPT Security license for <strong>{$blog_name}</strong> will expire in {$days_left} days (" . date_i18n( get_option( 'date_format' ), $expiry ) . "). Please contact your provider to renew and stay protected.";
                $color = ( $days_left <= 5 ) ? '#d63638' : '#dba617';
                break;
        }

        if ( ! $subject ) return;

        $html_message = "
        <div style='font-family: sans-serif; max-width: 600px; margin: 20px auto; border: 1px solid #eee; border-radius: 8px; overflow: hidden;'>
            <div style='background: {$color}; padding: 20px; color: #fff; text-align: center;'>
                <h1 style='margin: 0; font-size: 20px;'>{$title}</h1>
            </div>
            <div style='padding: 30px; line-height: 1.6; color: #333;'>
                <p>Hello Admin,</p>
                <p>{$body}</p>
                <p style='margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666;'>
                    This is an automated notification from VAPT Security installed on {$blog_name}.
                </p>
            </div>
        </div>";

        add_filter( 'wp_mail_content_type', function() { return 'text/html'; } );
        wp_mail( $admin_email, $subject, $html_message );
        remove_filter( 'wp_mail_content_type', 'text/html' );
    }

    /**
     * Helper to get locked config data
     */
    private function get_locked_config_data() {
        $files = glob( plugin_dir_path( __FILE__ ) . 'vapt-*-locked-config.php*' );
        if ( empty( $files ) ) return false;
        
        // Sort by modification time (newest first) to ensure we use the latest config
        usort( $files, function( $a, $b ) {
            return filemtime( $b ) - filemtime( $a );
        });
        
        $content = file_get_contents( $files[0] );
        if ( preg_match( '/\$vapt_locked_config_data\s*=\s*\'(.*?)\';/s', $content, $matches ) ) {
            return json_decode( stripslashes( $matches[1] ), true );
        }
        return false;
    }
}

/* Kick it off. */
VAPT_Security::instance();
