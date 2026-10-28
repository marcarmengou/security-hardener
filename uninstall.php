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
// Retrieve the option before deleting it so we can honor the preference.
$wpsh_options     = get_option( 'wpsh_options', array() );
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

// Delete hardening checklist state.
delete_option( 'wpsh_checklist' );

// The login rate-limiting transients (wpsh_login_attempts_* and wpsh_login_blocked_*)
// are keyed by a hash of the visitor's IP address, so they cannot be listed without
// querying the database directly. They are intentionally left alone: each one expires
// on its own (24 hours at most, the maximum block duration) and WordPress core removes
// expired transients automatically.
