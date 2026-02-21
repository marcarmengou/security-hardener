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

// Delete login attempts transients using a direct SQL query.
// There is no WordPress API to delete transients by pattern, so a direct query
// is the only reliable approach here. Caching is intentionally skipped in an
// uninstall context; the object cache is flushed immediately afterwards.
$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	"DELETE FROM {$wpdb->options}
	WHERE option_name LIKE '_transient_wpsh_login_attempts_%'
	OR option_name LIKE '_transient_timeout_wpsh_login_attempts_%'
	OR option_name LIKE '_transient_wpsh_login_blocked_%'
	OR option_name LIKE '_transient_timeout_wpsh_login_blocked_%'"
);

// Flush the object cache to remove any in-memory copies of the deleted transients.
wp_cache_flush();