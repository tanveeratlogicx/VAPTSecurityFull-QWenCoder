<?php
/**
 * Uninstall VAPT Security
 *
 * @package VAPT_Security
 */

// If uninstall is not called from WordPress, exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit();
}

// Delete all plugin options
delete_option( 'vapt_rate_limit' );
delete_option( 'vapt_cron_rate_limit' );
delete_option( 'vapt_blocked_ips' );
delete_option( 'vapt_security_logs' );
delete_option( 'vapt_ip_violations' );
delete_option( 'vapt_security_options' );

// For site options in Multisite
delete_site_option( 'vapt_rate_limit' );
delete_site_option( 'vapt_cron_rate_limit' );
delete_site_option( 'vapt_blocked_ips' );
delete_site_option( 'vapt_security_logs' );
delete_site_option( 'vapt_ip_violations' );
delete_site_option( 'vapt_security_options' );

// Clear any scheduled events
wp_clear_scheduled_hook( 'vapt_cleanup_event' );

// Cleanup generated files
$plugin_dir = plugin_dir_path( __FILE__ );
$files_to_delete = [
    $plugin_dir . 'vapt-locked-config.php',
    $plugin_dir . 'vapt-locked-config.php.imported'
];

// Clean up any stray locked configs in root
$root_configs = glob( $plugin_dir . 'vapt-*-locked-config.php*' );
$ip_root_configs = glob( $plugin_dir . 'VAPTIPv4-*-Config.php*' );
if ( $root_configs || $ip_root_configs ) {
    $files_to_delete = array_merge( $files_to_delete, $root_configs ?: [], $ip_root_configs ?: [] );
}

foreach ( $files_to_delete as $file ) {
    if ( file_exists( $file ) ) {
        @unlink( $file );
    }
}

// Clean up Releases folder
$releases_dir = $plugin_dir . 'releases/';
if ( file_exists( $releases_dir ) ) {
    $it = new RecursiveDirectoryIterator( $releases_dir, RecursiveDirectoryIterator::SKIP_DOTS );
    $files = new RecursiveIteratorIterator( $it, RecursiveIteratorIterator::CHILD_FIRST );
    foreach( $files as $file ) {
        if ( $file->isDir() ) {
            @rmdir( $file->getRealPath() );
        } else {
            @unlink( $file->getRealPath() );
        }
    }
    @rmdir( $releases_dir );
}

// Clean up any stray zip files if they exist
$zips = glob( $plugin_dir . 'vapt-security-*.zip' );
if ( $zips ) {
    foreach ( $zips as $zip ) {
        @unlink( $zip );
    }
}