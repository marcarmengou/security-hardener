<?php
/**
 * Uninstall script for Security Hardener
 *
 * Fired when the plugin is uninstalled.
 *
 * @package Security_Hardener
 * @since 0.5
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Only delete data if the user has explicitly opted in.
// Retrieve the option before deleting it so we can honour the preference.
$wpsh_options     = get_option( 'wpsh_options', [] );
$wpsh_delete_data = ! empty( $wpsh_options['delete_data_on_uninstall'] );

if ( ! $wpsh_delete_data ) {
	// Data-preservation is the default — leave everything intact.
	return;
}

// --- Opt-in path: remove all plugin data ---

// Delete plugin options.
delete_option( 'wpsh_options' );

// Delete security logs.
delete_option( 'wpsh_security_logs' );

// Delete login rate-limiting transients.
// We cannot enumerate every hashed IP key ahead of time, so we retrieve
// their option_names via a single parameterised SELECT (no raw DELETE),
// then remove each entry through the standard WordPress Options API.
// wp_cache_flush() clears any remaining in-memory copies afterwards.
$wpsh_transient_prefixes = [
	'_transient_wpsh_login_attempts_',
	'_transient_timeout_wpsh_login_attempts_',
	'_transient_wpsh_login_blocked_',
	'_transient_timeout_wpsh_login_blocked_',
];

global $wpdb;

foreach ( $wpsh_transient_prefixes as $wpsh_prefix ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpsh_option_names = $wpdb->get_col(
		$wpdb->prepare(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
			$wpdb->esc_like( $wpsh_prefix ) . '%'
		)
	);

	if ( ! empty( $wpsh_option_names ) ) {
		foreach ( $wpsh_option_names as $wpsh_option_name ) {
			delete_option( $wpsh_option_name );
		}
	}
}

// Flush the object cache to remove any in-memory copies of the deleted data.
wp_cache_flush();
