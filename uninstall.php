<?php
/**
 * Cleaning when uninstalling Security Hardener.
 */
if ( ! defined('WP_UNINSTALL_PLUGIN') ) {
    exit;
}

// 1) Main option
delete_option('wphn_hardener_options');

// 2) Clear rate-limit transients (without SQL):
// We delete any transients starting with 'wphn_login_' (adjust the prefix if you use another one).
$all_options = array_keys( wp_load_alloptions() );
foreach ( $all_options as $opt_name ) {
    if ( str_starts_with( $opt_name, '_transient_wph_failed_' )
        || str_starts_with( $opt_name, '_transient_timeout_wph_failed_' ) ) {
        // Rebuild the transient key (remove the '_transient_' prefix).
        $transient_key = substr( $opt_name, strlen('_transient_') );
        // This removes both the transient and its timeout in any backend (including object cache).
        delete_transient( $transient_key );
    }
}
