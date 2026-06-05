<?php
/**
 * VAPT Security - Client Diagnostics
 * 
 * Upload this file to your client site's WordPress root (same folder as wp-load.php)
 * and access it via: http://wptest.local/wp-content/plugins/vapt-security/vapt-diagnostics.php
 * (Or wherever you placed it)
 */

require_once __DIR__ . '/../../../wp-load.php';

// Security: Only allow logged-in admins
if ( ! current_user_can( 'manage_options' ) ) {
    wp_die( 'Admin access required.' );
}

header( 'Content-Type: text/html' );

echo '<h1>VAPT Security - Client Diagnostics</h1>';
echo '<hr>';

// 1. Check for locked config file
$plugin_path = plugin_dir_path( __FILE__ );
$files = glob( $plugin_path . 'vapt-*-locked-config.php*' );
$ip_files = glob( $plugin_path . 'VAPTIPv4-*-Config.php*' );
if ( is_array( $ip_files ) ) {
    $files = is_array( $files ) ? array_merge( $files, $ip_files ) : $ip_files;
}
$legacy = $plugin_path . 'vapt-locked-config.php';
$legacy_imported = $plugin_path . 'vapt-locked-config.php.imported';

$config_found = false;
$config_file = '';

if ( ! empty( $files ) ) {
    $config_found = true;
    $config_file = $files[0];
} elseif ( file_exists( $legacy ) ) {
    $config_found = true;
    $config_file = $legacy;
} elseif ( file_exists( $legacy_imported ) ) {
    $config_found = true;
    $config_file = $legacy_imported;
}

echo '<h2>1. Config File Check</h2>';
if ( $config_found ) {
    echo '<p style="color:green;">Found: ' . esc_html( $config_file ) . '</p>';
    
    $content = file_get_contents( $config_file );
    $data = null;
    
    if ( preg_match( '/\$vapt_locked_config_data\s*=\s*\'(.*?)\';/s', $content, $matches ) ) {
        $json = stripslashes( $matches[1] );
        $data = json_decode( $json, true );
    }
    
    if ( $data ) {
        echo '<pre>';
        echo 'Build ID: ' . esc_html( $data['build_id'] ?? 'MISSING' ) . "\n";
        echo 'Domain Pattern: ' . esc_html( $data['domain_pattern'] ?? 'MISSING' ) . "\n";
        echo 'Tracking Mode: ' . esc_html( $data['tracking_mode'] ?? 'MISSING' ) . "\n";
        echo 'Integrity URL: ' . esc_html( $data['integrity_url'] ?? 'MISSING' ) . "\n";
        echo '</pre>';
    } else {
        echo '<p style="color:red;">Could not parse config file data.</p>';
    }
} else {
    echo '<p style="color:red;">No locked config file found in: ' . esc_html( $plugin_path ) . '</p>';
}

echo '<hr>';

// 2. Domain Lock Check
$current_host = $_SERVER['HTTP_HOST'] ?? 'unknown';
echo '<h2>2. Domain Lock Check</h2>';
echo '<p>Current Host: <strong>' . esc_html( $current_host ) . '</strong></p>';

if ( ! empty( $data['domain_pattern'] ) ) {
    $pattern = $data['domain_pattern'];
    $domain_type = $data['domain_type'] ?? 'standard';
    $match = false;
    
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
    
    if ( $match ) {
        echo '<p style="color:green;">Domain pattern <code>' . esc_html( $pattern ) . '</code> matches current host.</p>';
    } else {
        echo '<p style="color:red;">Domain pattern <code>' . esc_html( $pattern ) . '</code> does NOT match current host. This would normally block the plugin.</p>';
    }
    
    // Check local bypass
    $is_local = (
        strpos( $current_host, '.local' ) !== false ||
        strpos( $current_host, 'localhost' ) !== false ||
        in_array( $_SERVER['REMOTE_ADDR'] ?? '', [ '127.0.0.1', '::1' ], true )
    );
    if ( $is_local ) {
        echo '<p style="color:orange;">Local environment detected. Domain lock bypass is active.</p>';
    }
}

echo '<hr>';

// 3. Network Connectivity Test
if ( ! empty( $data['integrity_url'] ) ) {
    $integrity_url = $data['integrity_url'];
    $host = parse_url( $integrity_url, PHP_URL_HOST );
    
    echo '<h2>3. Network Connectivity Test</h2>';
    echo '<p>Target URL: <code>' . esc_html( $integrity_url ) . '</code></p>';
    echo '<p>Target Host: <code>' . esc_html( $host ) . '</code></p>';
    
    // DNS Test
    $ip = gethostbyname( $host );
    if ( $ip === $host ) {
        echo '<p style="color:red;">DNS Resolution: FAILED. Could not resolve <code>' . esc_html( $host ) . '</code>.</p>';
        echo '<p style="color:red;"><strong>This is the most likely cause of the tracking failure.</strong> Your local site cannot resolve the master domain name.</p>';
    } else {
        echo '<p style="color:green;">DNS Resolution: SUCCESS. IP: <code>' . esc_html( $ip ) . '</code></p>';
    }
    
    // HTTP Test (Simple GET to check if server responds)
    echo '<h3>HTTP GET Test (to master root)</h3>';
    $test_url = parse_url( $integrity_url, PHP_URL_SCHEME ) . '://' . $host . '/';
    $get_response = wp_remote_get( $test_url, [ 'timeout' => 15, 'sslverify' => false ] );
    
    if ( is_wp_error( $get_response ) ) {
        echo '<p style="color:red;">HTTP GET Failed: ' . esc_html( $get_response->get_error_message() ) . '</p>';
    } else {
        $status = wp_remote_retrieve_response_code( $get_response );
        echo '<p style="color:green;">HTTP GET Status: ' . esc_html( $status ) . '</p>';
    }
    
    // Actual Tracking Ping Test
    echo '<h3>Actual Tracking Ping Test</h3>';
    $payload = [
        'action'          => 'vapt_build_callback',
        'build_id'        => $data['build_id'] ?? 'test',
        'domain'          => $current_host,
        'license_type'    => 'trial',
        'license_expiry'  => time() + 86400,
        'license_status'  => 'active',
        'version'         => '1.0.0',
        'initial_install' => time()
    ];
    
    $post_response = wp_remote_post( $integrity_url, [
        'body'      => $payload,
        'timeout'   => 15,
        'blocking'  => true,
        'sslverify' => false
    ]);
    
    if ( is_wp_error( $post_response ) ) {
        echo '<p style="color:red;">Tracking Ping Failed: ' . esc_html( $post_response->get_error_message() ) . '</p>';
    } else {
        $status = wp_remote_retrieve_response_code( $post_response );
        $body = wp_remote_retrieve_body( $post_response );
        echo '<p style="color:green;">Tracking Ping Status: ' . esc_html( $status ) . '</p>';
        echo '<p>Response Body:</p>';
        echo '<pre>' . esc_html( $body ) . '</pre>';
        
        if ( $status === 200 ) {
            $json = json_decode( $body, true );
            if ( ! empty( $json['success'] ) ) {
                echo '<p style="color:green;"><strong>Master server received the ping successfully!</strong></p>';
            } else {
                echo '<p style="color:orange;">Master server responded but did not return success. Check the response body above.</p>';
            }
        } else {
            echo '<p style="color:red;">Master server returned HTTP ' . esc_html( $status ) . '. This usually means the URL is wrong or the master plugin is not active.</p>';
        }
    }
} else {
    echo '<h2>3. Network Connectivity Test</h2>';
    echo '<p style="color:red;">Cannot test: Integrity URL is missing from config file.</p>';
}

echo '<hr>';
echo '<h2>4. Recommendations</h2>';
echo '<ul>';
echo '<li>If <strong>DNS Resolution failed</strong>: Your local development environment cannot resolve the master domain. You may need to add the master IP to your client site\'s hosts file, or use the Custom Tracking URL feature (see below).</li>';
echo '<li>If <strong>HTTP GET failed</strong> (e.g., Connection Refused): The master site is not reachable. Verify the master site is running and accessible.</li>';
echo '<li>If <strong>HTTP status is 404</strong>: The URL path is wrong. The master plugin must be active on the target site.</li>';
echo '<li>If <strong>HTTP status is 200 but no success</strong>: Check the master site\'s debug log for PHP errors in <code>handle_build_callback</code>.</li>';
echo '</ul>';

echo '<hr>';
echo '<h2>5. Custom Tracking URL Test</h2>';
echo '<p>If the default URLs are not working, you can test a custom URL here:</p>';

echo '<form method="get" action="">';
echo '<input type="hidden" name="run_custom_test" value="1">';
echo '<p><input type="text" name="custom_url" value="" placeholder="http://192.168.1.100:10004/wp-admin/admin-ajax.php" style="width:80%;"></p>';
echo '<p><button type="submit">Test Custom URL</button></p>';
echo '</form>';

if ( ! empty( $_GET['run_custom_test'] ) && ! empty( $_GET['custom_url'] ) ) {
    $custom_url = esc_url_raw( $_GET['custom_url'] );
    echo '<h3>Testing: ' . esc_html( $custom_url ) . '</h3>';
    
    $payload = [
        'action'          => 'vapt_build_callback',
        'build_id'        => $data['build_id'] ?? 'test',
        'domain'          => $current_host,
        'license_type'    => 'trial',
        'license_expiry'  => time() + 86400,
        'license_status'  => 'active',
        'version'         => '1.0.0',
        'initial_install' => time()
    ];
    
    $post_response = wp_remote_post( $custom_url, [
        'body'      => $payload,
        'timeout'   => 15,
        'blocking'  => true,
        'sslverify' => false
    ]);
    
    if ( is_wp_error( $post_response ) ) {
        echo '<p style="color:red;">Custom URL Failed: ' . esc_html( $post_response->get_error_message() ) . '</p>';
    } else {
        $status = wp_remote_retrieve_response_code( $post_response );
        $body = wp_remote_retrieve_body( $post_response );
        echo '<p style="color:green;">Status: ' . esc_html( $status ) . '</p>';
        echo '<pre>' . esc_html( $body ) . '</pre>';
    }
}
