<?php
/**
 * VAPT Hardening Module
 *
 * Implements additional security hardening measures based on VAPT report.
 *
 * @package VAPT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class VAPT_Hardening {

    /**
     * Initialize hardening measures.
     */
    public function init() {
        // V#11 Security Headers / Clickjacking
        if ( VAPT_Features::is_enabled( 'security_headers' ) ) {
            add_action( 'send_headers', [ $this, 'send_security_headers' ] );
        }

        // V#3 XML-RPC Protection
        if ( VAPT_Features::is_enabled( 'xmlrpc_protection' ) ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_action( 'init', [ $this, 'block_xmlrpc_access' ] );
            add_action( 'wp_head', [ $this, 'remove_pingback_header' ] );
            remove_action( 'wp_head', 'rsd_link' );
        }

        // V#1 Login Rate Limiting
        if ( VAPT_Features::is_enabled( 'login_protection' ) ) {
            add_filter( 'authenticate', [ $this, 'check_login_rate_limit' ], 30, 3 );
            add_action( 'wp_login_failed', [ $this, 'track_login_failed' ] );
        }

        // V#8 Username Enumeration
        if ( VAPT_Features::is_enabled( 'login_enum_protection' ) ) {
            add_filter( 'login_errors', [ $this, 'generic_login_errors' ] );
        }

        // V#7 & V#10 REST API Protection (Whitelist approach)
        if ( VAPT_Features::is_enabled( 'rest_api_protection' ) ) {
            add_filter( 'rest_authentication_errors', [ $this, 'restrict_rest_api' ] );
        }

        // V#6 Banner Grabbing
        if ( VAPT_Features::is_enabled( 'banner_grabbing' ) ) {
            add_action( 'init', [ $this, 'hide_version_info' ] );
            add_filter( 'script_loader_src', [ $this, 'remove_version_query' ], 15 );
            add_filter( 'style_loader_src', [ $this, 'remove_version_query' ], 15 );
        }

        // V#12 Debug Log Protection
        if ( VAPT_Features::is_enabled( 'debug_log_protection' ) ) {
            add_action( 'template_redirect', [ $this, 'block_debug_log' ] );
        }

        // V#13 readme.html Protection
        if ( VAPT_Features::is_enabled( 'readme_protection' ) ) {
            add_action( 'template_redirect', [ $this, 'block_readme_file' ] );
        }

        // V#4 Directory Listing
        if ( VAPT_Features::is_enabled( 'directory_listing' ) ) {
            $this->create_silencer_files();
        }
    }

    /**
     * V#4 Create index.php files to prevent directory listing
     */
    public function create_silencer_files() {
        $dirs = [
            WP_CONTENT_DIR . '/uploads',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
        ];

        $content = "<?php\n// Silence is golden.\n";

        foreach ( $dirs as $dir ) {
            if ( is_dir( $dir ) ) {
                $file = untrailingslashit( $dir ) . '/index.php';
                if ( ! file_exists( $file ) ) {
                    @file_put_contents( $file, $content );
                }
            }
        }
    }

    /**
     * V#11 Send Security Headers
     */
    public function send_security_headers() {
        if ( ! headers_sent() ) {
            header( 'X-Frame-Options: SAMEORIGIN' );
            header( 'X-Content-Type-Options: nosniff' );
            header( 'X-XSS-Protection: 1; mode=block' );
            header( 'Referrer-Policy: strict-origin-when-cross-origin' );
            header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        }
    }

    /**
     * V#3 Block direct XML-RPC requests
     */
    public function block_xmlrpc_access() {
        if ( defined( 'XMLRPC_REQUEST' ) || strpos( $_SERVER['REQUEST_URI'], 'xmlrpc.php' ) !== false ) {
            wp_die( __( 'XML-RPC is disabled for security reasons.', 'vapt-security' ), 'XML-RPC Disabled', [ 'response' => 403 ] );
        }
    }

    /**
     * V#3 Remove Pingback header
     */
    public function remove_pingback_header() {
        header_remove( 'X-Pingback' );
    }

    /**
     * V#1 Check login rate limit
     */
    public function check_login_rate_limit( $user, $username, $password ) {
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        $rate_limiter = new VAPT_Rate_Limiter();
        if ( ! $rate_limiter->allow_login_request() ) {
            return new WP_Error( 'too_many_retries', __( 'Too many failed login attempts. Please try again later.', 'vapt-security' ) );
        }

        return $user;
    }

    /**
     * V#1 Track failed logins
     */
    public function track_login_failed( $username ) {
        $rate_limiter = new VAPT_Rate_Limiter();
        $rate_limiter->track_login_failure();

        if ( VAPT_Features::is_enabled( 'security_logging' ) ) {
            $logger = new VAPT_Security_Logger();
            $logger->log_event( 'login_failed', [ 'username' => $username ] );
        }
    }

    /**
     * V#8 Generic login errors
     */
    public function generic_login_errors( $error ) {
        return __( 'Invalid username or password.', 'vapt-security' );
    }

    /**
     * V#7 & V#10 Restrict REST API to whitelisted namespaces for unauthenticated users
     */
    public function restrict_rest_api( $result ) {
        if ( true === $result || is_wp_error( $result ) ) {
            return $result;
        }

        // Allow authenticated users
        if ( is_user_logged_in() ) {
            return $result;
        }

        // Allow Local and Loopback requests to prevent breaking core features
        if ( $this->is_internal_request() ) {
            return $result;
        }

        $options = get_option( 'vapt_security_options', [] );
        $custom_whitelist = isset( $options['rest_api_whitelist'] ) ? explode( ',', $options['rest_api_whitelist'] ) : [];
        
        $whitelist = array_merge( [
            'oembed/1.0',
            'wp-site-health/v1',
            'contact-form-7/v1',
            'wp/v2',           // Allow core wp/v2 namespace
            'wp-block-editor/v1',
            'batch/v1',
        ], array_map( 'trim', $custom_whitelist ) );

        $current_route = untrailingslashit( $GLOBALS['wp']->query_vars['rest_route'] ?? '' );
        
        // STRICTURE: Always block user enumeration regardless of whitelist
        if ( strpos( $current_route, 'wp/v2/users' ) !== false ) {
            return new WP_Error( 'rest_forbidden', __( 'User enumeration is disabled.', 'vapt-security' ), [ 'status' => 401 ] );
        }

        foreach ( $whitelist as $allowed ) {
            if ( ! empty( $allowed ) && strpos( $current_route, untrailingslashit( $allowed ) ) !== false ) {
                return $result;
            }
        }

        // If we are here, it's an unauthenticated request to a non-whitelisted route
        // We return 401 only if it's not a core discovery route
        if ( empty( $current_route ) || $current_route === '/' ) {
            return $result;
        }

        return new WP_Error( 'rest_forbidden', __( 'Authentication required.', 'vapt-security' ), [ 'status' => 401 ] );
    }

    /**
     * Check if the request is internal (local or loopback)
     * 
     * @return bool
     */
    private function is_internal_request() {
        // Always allow installation and import processes
        if ( ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) || ( defined( 'WP_IMPORTING' ) && WP_IMPORTING ) ) {
            return true;
        }

        $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '';
        $server_addr = $_SERVER['SERVER_ADDR'] ?? '';
        $host        = $_SERVER['HTTP_HOST'] ?? '';
        $user_agent  = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Allow WordPress loopback requests specifically
        if ( strpos( $user_agent, 'WordPress/' ) !== false ) {
            return true;
        }

        // Local environment check
        if ( strpos( $host, '.local' ) !== false || 
             strpos( $host, '.test' ) !== false || 
             strpos( $host, 'localhost' ) !== false ||
             $remote_addr === '127.0.0.1' || 
             $remote_addr === '::1'
        ) {
            return true;
        }

        // Loopback check
        if ( ! empty( $server_addr ) && $remote_addr === $server_addr ) {
            return true;
        }

        // Additional Loopback check (WordPress often uses this for Site Health/Cron)
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
     * V#6 Hide version information
     */
    public function hide_version_info() {
        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string' );
        header_remove( 'X-Powered-By' );
    }

    /**
     * V#6 Remove version query string from scripts and styles
     */
    public function remove_version_query( $src ) {
        if ( strpos( $src, 'ver=' ) ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /**
     * V#12 Block access to debug.log
     */
    public function block_debug_log() {
        if ( strpos( $_SERVER['REQUEST_URI'] ?? '', 'debug.log' ) !== false ) {
            status_header( 403 );
            wp_die( __( 'Access to debug.log is forbidden.', 'vapt-security' ), 'Forbidden', [ 'response' => 403 ] );
        }
    }

    /**
     * V#13 Block access to readme.html
     */
    public function block_readme_file() {
        if ( strpos( $_SERVER['REQUEST_URI'] ?? '', 'readme.html' ) !== false ) {
            status_header( 403 );
            wp_die( __( 'Access to readme.html is forbidden.', 'vapt-security' ), 'Forbidden', [ 'response' => 403 ] );
        }
    }

    /**
     * Generate .htaccess rules
     */
    public static function write_htaccess_rules() {
        $abspath = untrailingslashit( ABSPATH );
        $htaccess_path = $abspath . '/.htaccess';

        if ( ! is_writable( $htaccess_path ) && ! is_writable( dirname( $htaccess_path ) ) ) {
            return false;
        }

        $rules = [];
        $rules[] = '# BEGIN VAPT Security Hardening';

        // V#4 Directory Listing
        if ( VAPT_Features::is_enabled( 'directory_listing' ) ) {
            $rules[] = 'Options -Indexes';
        }

        // V#3 XML-RPC
        if ( VAPT_Features::is_enabled( 'xmlrpc_protection' ) ) {
            $rules[] = '<Files xmlrpc.php>';
            $rules[] = '  <IfModule mod_authz_core.c>';
            $rules[] = '    Require all denied';
            $rules[] = '  </IfModule>';
            $rules[] = '  <IfModule !mod_authz_core.c>';
            $rules[] = '    Order deny,allow';
            $rules[] = '    Deny from all';
            $rules[] = '  </IfModule>';
            $rules[] = '</Files>';
        }

        // V#12 Debug Log
        if ( VAPT_Features::is_enabled( 'debug_log_protection' ) ) {
            $rules[] = '<Files "debug.log">';
            $rules[] = '  <IfModule mod_authz_core.c>';
            $rules[] = '    Require all denied';
            $rules[] = '  </IfModule>';
            $rules[] = '  <IfModule !mod_authz_core.c>';
            $rules[] = '    Order deny,allow';
            $rules[] = '    Deny from all';
            $rules[] = '  </IfModule>';
            $rules[] = '</Files>';
        }

        // V#13 readme.html
        if ( VAPT_Features::is_enabled( 'readme_protection' ) ) {
            $rules[] = '<Files "readme.html">';
            $rules[] = '  <IfModule mod_authz_core.c>';
            $rules[] = '    Require all denied';
            $rules[] = '  </IfModule>';
            $rules[] = '  <IfModule !mod_authz_core.c>';
            $rules[] = '    Order deny,allow';
            $rules[] = '    Deny from all';
            $rules[] = '  </IfModule>';
            $rules[] = '</Files>';
        }

        $rules[] = '# END VAPT Security Hardening';

        $rules_str = implode( "\n", $rules );

        $current_content = file_exists( $htaccess_path ) ? file_get_contents( $htaccess_path ) : '';
        
        // Remove old rules if they exist
        $new_content = preg_replace( '/# BEGIN VAPT Security Hardening.*?# END VAPT Security Hardening/s', '', $current_content );
        
        // Append new rules
        $new_content = trim( $new_content ) . "\n\n" . $rules_str;

        return file_put_contents( $htaccess_path, $new_content );
    }
}
