<?php
/**
 * WordPress function stubs for unit testing without a full WP environment.
 *
 * These stubs allow the VAPT_Security class methods to be exercised in isolation.
 * They are intentionally minimal — only what the tested code paths require.
 */

// ── Constants ────────────────────────────────────────────────────────────────
if ( ! defined( 'WPINC' ) )              define( 'WPINC', 'wp-includes' );
if ( ! defined( 'ABSPATH' ) )            define( 'ABSPATH', dirname( __DIR__ ) . '/' );
if ( ! defined( 'VAPT_VERSION' ) )       define( 'VAPT_VERSION', '3.2.1' );
if ( ! defined( 'VAPT_INTEGRITY_URL' ) ) define( 'VAPT_INTEGRITY_URL', 'https://vaptsecure.net/vapts' );
if ( ! defined( 'HOUR_IN_SECONDS' ) )    define( 'HOUR_IN_SECONDS', 3600 );
if ( ! defined( 'DAY_IN_SECONDS' ) )     define( 'DAY_IN_SECONDS', 86400 );
if ( ! defined( 'DOING_CRON' ) )         define( 'DOING_CRON', false );

// ── Global state store (simulates WP options) ────────────────────────────────
$GLOBALS['_vapt_test_options']       = [];
$GLOBALS['_vapt_wp_remote_post_log'] = [];   // captures every wp_remote_post() call
$GLOBALS['_vapt_error_log']          = [];   // captures every error_log() call

// ── WordPress option functions ───────────────────────────────────────────────
if ( ! function_exists( 'get_option' ) ) {
    function get_option( string $key, $default = false ) {
        return $GLOBALS['_vapt_test_options'][ $key ] ?? $default;
    }
}

if ( ! function_exists( 'update_option' ) ) {
    function update_option( string $key, $value ): bool {
        $GLOBALS['_vapt_test_options'][ $key ] = $value;
        return true;
    }
}

if ( ! function_exists( 'delete_option' ) ) {
    function delete_option( string $key ): bool {
        unset( $GLOBALS['_vapt_test_options'][ $key ] );
        return true;
    }
}

// ── WordPress HTTP functions ─────────────────────────────────────────────────
if ( ! function_exists( 'wp_remote_post' ) ) {
    /**
     * Stub: records the call and returns a fake non-error response.
     * Tests inspect $GLOBALS['_vapt_wp_remote_post_log'] to assert call args.
     */
    function wp_remote_post( string $url, array $args = [] ) {
        $GLOBALS['_vapt_wp_remote_post_log'][] = [ 'url' => $url, 'args' => $args ];
        return [ 'response' => [ 'code' => 200 ], 'body' => '{"success":true}' ];
    }
}

if ( ! function_exists( 'is_wp_error' ) ) {
    function is_wp_error( $thing ): bool {
        return $thing instanceof WP_Error;
    }
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
    function wp_remote_retrieve_response_code( $response ) {
        return $response['response']['code'] ?? 0;
    }
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
    function wp_remote_retrieve_body( $response ): string {
        return $response['body'] ?? '';
    }
}

// ── WordPress user / auth stubs ──────────────────────────────────────────────
if ( ! function_exists( 'wp_get_current_user' ) ) {
    function wp_get_current_user() {
        return new class {
            public string $user_login = '';
            public function exists(): bool { return false; }
        };
    }
}

if ( ! function_exists( 'check_ajax_referer' ) ) {
    function check_ajax_referer( string $action, string|bool $query_arg = false ): bool {
        return true; // always pass in tests
    }
}

if ( ! function_exists( 'wp_send_json_success' ) ) {
    function wp_send_json_success( $data = null ): void {
        $GLOBALS['_vapt_json_response'] = [ 'success' => true, 'data' => $data ];
    }
}

if ( ! function_exists( 'wp_send_json_error' ) ) {
    function wp_send_json_error( $data = null, int $status_code = 0 ): void {
        $GLOBALS['_vapt_json_response'] = [ 'success' => false, 'data' => $data ];
    }
}

if ( ! function_exists( 'wp_mail' ) ) {
    function wp_mail( $to, $subject, $message, $headers = '', $attachments = [] ): bool {
        return true;
    }
}

// ── WordPress URL / path stubs ───────────────────────────────────────────────
if ( ! function_exists( 'plugin_dir_path' ) ) {
    function plugin_dir_path( string $file ): string {
        return rtrim( dirname( $file ), DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
    }
}

if ( ! function_exists( 'admin_url' ) ) {
    function admin_url( string $path = '' ): string {
        return 'http://vaptsecure.local/wp-admin/' . ltrim( $path, '/' );
    }
}

if ( ! function_exists( 'esc_url_raw' ) ) {
    function esc_url_raw( string $url ): string {
        return filter_var( $url, FILTER_SANITIZE_URL ) ?: '';
    }
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
    function sanitize_text_field( string $str ): string {
        return trim( strip_tags( $str ) );
    }
}

// ── WordPress misc stubs ─────────────────────────────────────────────────────
if ( ! function_exists( 'add_action' ) ) {
    function add_action( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
        return true;
    }
}

if ( ! function_exists( 'add_filter' ) ) {
    function add_filter( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
        return true;
    }
}

if ( ! function_exists( 'apply_filters' ) ) {
    function apply_filters( string $hook, $value, ...$args ) {
        return $value;
    }
}

if ( ! function_exists( 'do_action' ) ) {
    function do_action( string $hook, ...$args ): void {}
}

if ( ! function_exists( 'register_activation_hook' ) ) {
    function register_activation_hook( string $file, callable $callback ): void {}
}

if ( ! function_exists( 'register_deactivation_hook' ) ) {
    function register_deactivation_hook( string $file, callable $callback ): void {}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
    function wp_schedule_event( int $timestamp, string $recurrence, string $hook, array $args = [] ): bool {
        return true;
    }
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
    function wp_next_scheduled( string $hook, array $args = [] ) {
        return false;
    }
}

if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
    function wp_clear_scheduled_hook( string $hook, array $args = [] ): int {
        return 0;
    }
}

if ( ! function_exists( 'is_admin' ) ) {
    function is_admin(): bool { return false; }
}

if ( ! function_exists( 'current_user_can' ) ) {
    function current_user_can( string $cap ): bool { return false; }
}

if ( ! function_exists( 'wp_die' ) ) {
    function wp_die( $message = '', $title = '', $args = [] ): void {
        throw new \RuntimeException( 'wp_die called: ' . (string) $message );
    }
}

if ( ! function_exists( 'absint' ) ) {
    function absint( $maybeint ): int {
        return abs( (int) $maybeint );
    }
}

if ( ! function_exists( 'trailingslashit' ) ) {
    function trailingslashit( string $string ): string {
        return rtrim( $string, '/\\' ) . '/';
    }
}

if ( ! function_exists( 'wp_json_encode' ) ) {
    function wp_json_encode( $data, int $options = 0, int $depth = 512 ): string|false {
        return json_encode( $data, $options, $depth );
    }
}

if ( ! function_exists( 'wp_unslash' ) ) {
    function wp_unslash( $value ) {
        return is_array( $value ) ? array_map( 'wp_unslash', $value ) : stripslashes( (string) $value );
    }
}

if ( ! function_exists( 'set_transient' ) ) {
    function set_transient( string $transient, $value, int $expiration = 0 ): bool {
        $GLOBALS['_vapt_test_options'][ '_transient_' . $transient ] = $value;
        return true;
    }
}

if ( ! function_exists( 'get_transient' ) ) {
    function get_transient( string $transient ) {
        return $GLOBALS['_vapt_test_options'][ '_transient_' . $transient ] ?? false;
    }
}

if ( ! function_exists( 'delete_transient' ) ) {
    function delete_transient( string $transient ): bool {
        unset( $GLOBALS['_vapt_test_options'][ '_transient_' . $transient ] );
        return true;
    }
}

// ── WP_Error stub ────────────────────────────────────────────────────────────
if ( ! class_exists( 'WP_Error' ) ) {
    class WP_Error {
        private string $code;
        private string $message;
        public function __construct( string $code = '', string $message = '' ) {
            $this->code    = $code;
            $this->message = $message;
        }
        public function get_error_message(): string { return $this->message; }
        public function get_error_code(): string    { return $this->code; }
    }
}

// ── VAPT_License stub ────────────────────────────────────────────────────────
if ( ! class_exists( 'VAPT_License' ) ) {
    class VAPT_License {
        public static function get_license(): array {
            return [ 'type' => 'standard', 'expires' => time() + 86400 ];
        }
        public static function is_valid(): bool {
            return true;
        }
    }
}

// ── Override error_log to capture messages ───────────────────────────────────
// We use a global array instead of the real error_log so tests can assert on it.
// NOTE: We use a namespace trick — declare in a test namespace to shadow the built-in.
// Since we can't redeclare error_log in global namespace, we use a wrapper approach.
// The test file will call vapt_test_error_log() instead, and we patch via runkit or
// simply capture via output buffering. For simplicity, we use a global flag approach:
// the bootstrap registers a custom stream wrapper for error_log capture.

// Actually, the simplest approach: use PHP's error_log with a custom log file,
// then read it. But even simpler: the tests directly call the guard logic inline
// and capture via the global array — the bootstrap just needs to define the array.
// The error_log() calls in the test file go through the real error_log() which we
// cannot override in global namespace in PHP 8. Instead, the test directly asserts
// on the guard condition logic (empty check) rather than intercepting error_log.

