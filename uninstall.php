<?php
/**
 * Uninstall script for Security Hardener
 *
 * Fired when the plugin is uninstalled.
 *
 * @package Security_Hardener
 * @since 0.5
 */

// If uninstall not called from WordPress, exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Delete plugin options
delete_option( 'wpsh_options' );

// Delete security logs
delete_option( 'wpsh_security_logs' );

// Clean up transients for login rate limiting
global $wpdb;

// Delete login attempts transients using efficient SQL query
$wpdb->query(
	"DELETE FROM {$wpdb->options} 
	WHERE option_name LIKE '_transient_wpsh_login_attempts_%' 
	OR option_name LIKE '_transient_timeout_wpsh_login_attempts_%'
	OR option_name LIKE '_transient_wpsh_login_blocked_%'
	OR option_name LIKE '_transient_timeout_wpsh_login_blocked_%'"
);

// If using object cache, flush it to remove any cached transients
if ( function_exists( 'wp_cache_flush' ) ) {
	wp_cache_flush();
}

// Optional: Clear any scheduled cron jobs if we add them in the future
// Example: wp_clear_scheduled_hook( 'wpsh_cleanup_logs' );

// Log uninstallation (optional - only if you want to keep a record)
// Note: This creates a log entry before deleting options
if ( function_exists( 'error_log' ) ) {
	error_log( 'Security Hardener plugin uninstalled at ' . current_time( 'mysql' ) );
}